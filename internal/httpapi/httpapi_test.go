package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ngm-gateway/ngm/api"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/sse"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

type fixture struct {
	srv  *Server
	jobs *jobs.Journal
	auth *auth.Service
	db   *store.DB
}

func newFixture(t *testing.T) *fixture {
	db := storetest.New(t)
	j := jobs.NewJournal(db)
	cfg := config.Default()
	cfg.API.PublicOrigin = "https://ngm.example.com"
	ui := fstest.MapFS{
		"index.html":      {Data: []byte(`<!doctype html><meta name="ngm-csp-nonce" content="__NGM_CSP_NONCE__"><title>NGM</title>`)},
		"assets/app-1.js": {Data: []byte("console.log(1)")},
	}
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	v := vault.New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	al := audit.New(db)
	pol := auth.DefaultPolicy()
	pol.Argon2 = auth.Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}
	as := auth.NewService(db, v, al, pol)
	if err := as.EnsureBuiltins(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &fixture{srv: New(Deps{DB: db, Jobs: j, Broker: sse.NewBroker(db), Config: cfg, UI: ui, Auth: as, Vault: v, Audit: al, GW: gwstore.New(db, v, al)}), jobs: j, auth: as, db: db}
}

func (f *fixture) do(t *testing.T, method, target string, hdr map[string]string, local bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if local {
		req.RemoteAddr = "127.0.0.1:50000"
	} else {
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set("X-Forwarded-For", "203.0.113.9") // relayed by nginx from the internet
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

type errEnvelope struct {
	Error struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		Details   map[string]any `json:"details"`
		RequestID string         `json:"request_id"`
		Retryable *bool          `json:"retryable"`
	} `json:"error"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) errEnvelope {
	t.Helper()
	var e errEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("not an error envelope: %s", rec.Body.String())
	}
	if e.Error.Code == "" || e.Error.RequestID == "" || e.Error.Retryable == nil {
		t.Fatalf("incomplete envelope: %s", rec.Body.String())
	}
	if e.Error.RequestID != rec.Header().Get("X-Request-ID") {
		t.Fatalf("request_id mismatch")
	}
	return e
}

// ── Contract ────────────────────────────────────────────────────────────────

func TestRoutesMatchOpenAPI(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Perm *string `json:"x-ngm-permission"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(api.OpenAPI, &doc); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	spec := map[string]string{}
	for p, ops := range doc.Paths {
		for m, op := range ops {
			if op.Perm == nil {
				t.Errorf("%s %s: missing x-ngm-permission", m, p)
				continue
			}
			spec[strings.ToUpper(m)+" "+p] = *op.Perm
		}
	}
	got := map[string]string{}
	for _, r := range newFixture(t).srv.Routes() {
		got[r.Method+" "+strings.Replace(r.Path, "{path...}", "{path}", 1)] = r.Permission
	}
	var problems []string
	for k, perm := range got {
		sp, ok := spec[k]
		if !ok {
			problems = append(problems, "registered but undocumented: "+k)
		} else if sp != perm {
			problems = append(problems, "permission mismatch "+k+": code="+perm+" spec="+sp)
		}
	}
	for k := range spec {
		if _, ok := got[k]; !ok {
			problems = append(problems, "documented but not registered: "+k)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestErrorEnvelopeOnUnknownEndpoint(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/v1/nope", nil, true)
	if rec.Code != 404 {
		t.Fatalf("code %d", rec.Code)
	}
	if e := decodeErr(t, rec); e.Error.Code != "not_found" {
		t.Fatalf("%+v", e)
	}
}

// ── Authentication / authorization baseline ────────────────────────────────

func TestProxiedRequestsAreUnauthenticated(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/api/v1/jobs", "/api/v1/system/version", "/api/v1/events"} {
		rec := f.do(t, "GET", p, nil, false)
		if rec.Code != 401 {
			t.Errorf("%s via proxy: %d, want 401", p, rec.Code)
			continue
		}
		decodeErr(t, rec)
	}
	// Spoofing a loopback client while relayed must not help.
	rec := f.do(t, "GET", "/api/v1/jobs", map[string]string{"X-Real-IP": "127.0.0.1"}, true)
	if rec.Code != 401 {
		t.Fatalf("X-Real-IP relayed request authenticated: %d", rec.Code)
	}
}

func TestNonLoopbackPeerUnauthenticated(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", "/api/v1/jobs", nil)
	req.RemoteAddr = "198.51.100.7:4444"
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHealthHidesDetailFromAnonymous(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/v1/system/health", nil, false)
	var h healthResponse
	json.Unmarshal(rec.Body.Bytes(), &h)
	if len(h.Components) != 0 {
		t.Fatalf("anonymous saw components: %s", rec.Body.String())
	}
	rec = f.do(t, "GET", "/api/v1/system/health", nil, true)
	json.Unmarshal(rec.Body.Bytes(), &h)
	if len(h.Components) < 3 {
		t.Fatalf("local caller should see components: %s", rec.Body.String())
	}
	// Unobserved components must be Unknown, so overall must not be healthy.
	if h.Status == Healthy {
		t.Fatalf("overall healthy despite unknown components: %s", rec.Body.String())
	}
	for _, c := range h.Components {
		if c.Name == "nginx" && c.Status != Unknown {
			t.Fatalf("nginx reported %s without observation", c.Status)
		}
	}
}

// ── Browser security baseline ───────────────────────────────────────────────

func TestSecurityHeaders(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/api/v1/system/health", "/", "/gateway/routes"} {
		rec := f.do(t, "GET", p, nil, true)
		h := rec.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") ||
			!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			strings.Contains(h.Get("Content-Security-Policy"), "unsafe-inline") {
			t.Errorf("%s CSP: %q", p, h.Get("Content-Security-Policy"))
		}
		for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
			if h.Get(k) != v {
				t.Errorf("%s %s=%q", p, k, h.Get(k))
			}
		}
	}
}

func TestCrossSiteUnsafeRequestsRejected(t *testing.T) {
	f := newFixture(t)
	cases := []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
	}
	for _, h := range cases {
		rec := f.do(t, "POST", "/api/v1/jobs", h, true)
		if rec.Code != 403 {
			t.Errorf("%v: %d", h, rec.Code)
			continue
		}
		if e := decodeErr(t, rec); e.Error.Code != "csrf_failed" {
			t.Errorf("%v: code %s", h, e.Error.Code)
		}
	}
	// The configured public origin is allowed past the origin guard (it then
	// hits method routing, not CSRF rejection).
	rec := f.do(t, "POST", "/api/v1/jobs", map[string]string{"Origin": "https://ngm.example.com", "Sec-Fetch-Site": "same-origin"}, false)
	if rec.Code == 403 {
		t.Fatalf("public origin rejected as CSRF")
	}
}

func TestRequestIDHandling(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/v1/system/health", map[string]string{"X-Request-ID": "abcDEF12-3456"}, true)
	if rec.Header().Get("X-Request-ID") != "abcDEF12-3456" {
		t.Fatal("valid request id not echoed")
	}
	rec = f.do(t, "GET", "/api/v1/system/health", map[string]string{"X-Request-ID": "bad\r\nid<script>"}, true)
	if got := rec.Header().Get("X-Request-ID"); strings.ContainsAny(got, "<>\r\n") || got == "" {
		t.Fatalf("unsafe request id reflected: %q", got)
	}
}

func TestPanicDoesNotLeakInternals(t *testing.T) {
	f := newFixture(t)
	f.srv.handle("GET", "/api/v1/test-panic", "", func(http.ResponseWriter, *http.Request) error {
		panic("secret path /etc/ngm/keys/kek-1.key")
	})
	rec := f.do(t, "GET", "/api/v1/test-panic", nil, true)
	if rec.Code != 500 {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "/etc/ngm") || strings.Contains(body, "goroutine") || strings.Contains(body, "secret") {
		t.Fatalf("leak: %s", body)
	}
	decodeErr(t, rec)
}

// ── Jobs endpoints ──────────────────────────────────────────────────────────

func TestJobsListPaginationAndGet(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var last *jobs.Job
	for i := 0; i < 5; i++ {
		last, _, _ = f.jobs.Submit(ctx, jobs.SubmitRequest{Kind: "test"})
	}
	rec := f.do(t, "GET", "/api/v1/jobs?limit=2", nil, true)
	var pg struct {
		Items      []jobs.Job `json:"items"`
		NextCursor *string    `json:"next_cursor"`
	}
	json.Unmarshal(rec.Body.Bytes(), &pg)
	if rec.Code != 200 || len(pg.Items) != 2 || pg.NextCursor == nil || pg.Items[0].ID != last.ID {
		t.Fatalf("page1: %d %s", rec.Code, rec.Body.String())
	}
	seen := 2
	for pg.NextCursor != nil {
		rec = f.do(t, "GET", "/api/v1/jobs?limit=2&cursor="+*pg.NextCursor, nil, true)
		pg.NextCursor = nil
		pg.Items = nil
		json.Unmarshal(rec.Body.Bytes(), &pg)
		seen += len(pg.Items)
	}
	if seen != 5 {
		t.Fatalf("paginated %d jobs, want 5", seen)
	}
	for _, bad := range []string{"limit=0", "limit=201", "limit=x", "state=Bogus", "cursor=../../x"} {
		if rec := f.do(t, "GET", "/api/v1/jobs?"+bad, nil, true); rec.Code != 400 {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	rec = f.do(t, "GET", "/api/v1/jobs/"+last.ID, nil, true)
	if rec.Code != 200 || rec.Header().Get("ETag") != `"r1"` {
		t.Fatalf("get: %d etag=%q", rec.Code, rec.Header().Get("ETag"))
	}
	if rec := f.do(t, "GET", "/api/v1/jobs/"+last.ID+"/steps", nil, true); rec.Code != 200 {
		t.Fatalf("steps %d", rec.Code)
	}
	if rec := f.do(t, "GET", "/api/v1/jobs/01J0000000000000000000000Z", nil, true); rec.Code != 404 {
		t.Fatalf("missing job %d", rec.Code)
	}
}

func TestIfMatch(t *testing.T) {
	r := httptest.NewRequest("PUT", "/", nil)
	if err := RequireIfMatch(r, 3); err == nil || !strings.Contains(err.Error(), "precondition_required") {
		t.Fatalf("missing If-Match: %v", err)
	}
	r.Header.Set("If-Match", `"r2"`)
	if err := RequireIfMatch(r, 3); err == nil || !strings.Contains(err.Error(), "precondition_failed") {
		t.Fatalf("stale If-Match: %v", err)
	}
	r.Header.Set("If-Match", `"r3"`)
	if err := RequireIfMatch(r, 3); err != nil {
		t.Fatal(err)
	}
}

// ── UI serving ──────────────────────────────────────────────────────────────

func TestUIServingAndFallback(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/gateway/routes", nil, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>NGM") {
		t.Fatalf("spa fallback: %d", rec.Code)
	}
	rec = f.do(t, "GET", "/assets/app-1.js", nil, true)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec := f.do(t, "GET", "/assets/missing.js", nil, true); rec.Code != 404 {
		t.Fatalf("missing asset: %d", rec.Code)
	}
	rec = f.do(t, "GET", "/../../etc/passwd", nil, true)
	body, _ := io.ReadAll(rec.Body)
	if strings.Contains(string(body), "root:") {
		t.Fatal("traversal")
	}
}
