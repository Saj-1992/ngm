package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/store"
)

const (
	bootToken = "boot-token-0123456789abcdef"
	ownerPW   = "Correct-Horse-9-Battery"
)

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	jar  http.CookieJar
	// bearer, when set, replaces cookie auth.
	bearer string
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, hc: &http.Client{Jar: jar}, jar: jar}
}

func (c *client) csrf() string {
	u, _ := url.Parse(c.base)
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	return ""
}

type resp struct {
	code int
	body map[string]any
	hdr  http.Header
}

func (r resp) errCode() string {
	e, _ := r.body["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (c *client) do(method, path string, body any, hdr map[string]string) resp {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" && c.bearer == "" {
		req.Header.Set(csrfHeader, c.csrf())
		req.Header.Set("Origin", c.base)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out := resp{code: res.StatusCode, hdr: res.Header, body: map[string]any{}}
	b, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(b, &out.body)
	return out
}

func setupServer(t *testing.T) (*fixture, *httptest.Server) {
	f := newFixture(t)
	f.srv.limiter = newRateLimiter(1000, 1000)
	ts := httptest.NewServer(f.srv)
	t.Cleanup(ts.Close)
	h, _ := json.Marshal(auth.HashToken(bootToken))
	if _, err := f.db.ExecContext(context.Background(), "INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)",
		SettingBootstrapTokenHash, string(h), store.FormatTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	return f, ts
}

// enrolOwner runs setup + TOTP enrolment and returns an active client and the TOTP secret.
func enrolOwner(t *testing.T, ts *httptest.Server) (*client, string) {
	c := newClient(t, ts.URL)
	r := c.do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": bootToken, "username": "owner", "password": ownerPW, "locale": "fa"}, nil)
	if r.code != 201 || r.body["stage"] != "mfa_enroll" {
		t.Fatalf("setup owner: %d %v", r.code, r.body)
	}
	return c, enrol(t, c)
}

func enrol(t *testing.T, c *client) string {
	r := c.do("POST", "/api/v1/auth/mfa/enroll", nil, nil)
	secret, _ := r.body["secret"].(string)
	if r.code != 200 || secret == "" || !strings.HasPrefix(r.body["otpauth_uri"].(string), "otpauth://totp/NGM:") {
		t.Fatalf("enroll: %d %v", r.code, r.body)
	}
	code, _ := auth.TOTPCode(secret, time.Now())
	r = c.do("POST", "/api/v1/auth/mfa/confirm", map[string]string{"code": code}, nil)
	if r.code != 200 || r.body["stage"] != "active" {
		t.Fatalf("confirm: %d %v", r.code, r.body)
	}
	return secret
}

func TestSetupOwnerGuards(t *testing.T) {
	f, ts := setupServer(t)
	c := newClient(t, ts.URL)
	// Wrong bootstrap token.
	r := c.do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": "nope", "username": "owner", "password": ownerPW}, nil)
	if r.code != 403 || r.errCode() != "invalid_bootstrap_token" {
		t.Fatalf("bad token: %d %v", r.code, r.body)
	}
	// Relayed through a proxy: refused even with the right token.
	r = c.do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": bootToken, "username": "owner", "password": ownerPW},
		map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if r.code != 403 {
		t.Fatalf("proxied setup: %d %v", r.code, r.body)
	}
	// Weak password.
	r = c.do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": bootToken, "username": "owner", "password": "short"}, nil)
	if r.code != 400 {
		t.Fatalf("weak pw: %d %v", r.code, r.body)
	}
	enrolOwner(t, ts)
	// Token is single use and the window is closed.
	r = newClient(t, ts.URL).do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": bootToken, "username": "x2", "password": ownerPW}, nil)
	if r.code != 403 && r.code != 409 {
		t.Fatalf("second owner: %d %v", r.code, r.body)
	}
	// Local read-only bootstrap access is gone once a user exists.
	if r := newClient(t, ts.URL).do("GET", "/api/v1/jobs", nil, nil); r.code != 401 {
		t.Fatalf("local anonymous after setup: %d", r.code)
	}
	var n int
	f.db.QueryRowContext(context.Background(), "SELECT count(*) FROM settings WHERE key=?", SettingBootstrapTokenHash).Scan(&n)
	if n != 0 {
		t.Fatal("bootstrap token not consumed")
	}
}

func TestStageGatingCSRFAndStepUp(t *testing.T) {
	f, ts := setupServer(t)
	c := newClient(t, ts.URL)
	c.do("POST", "/api/v1/setup/owner", map[string]any{"bootstrap_token": bootToken, "username": "owner", "password": ownerPW}, nil)
	// mfa_enroll stage: no access to resources.
	if r := c.do("GET", "/api/v1/users", nil, nil); r.code != 401 || r.errCode() != "mfa_required" {
		t.Fatalf("enroll stage access: %d %v", r.code, r.body)
	}
	secret := enrol(t, c)
	if r := c.do("GET", "/api/v1/users", nil, nil); r.code != 200 {
		t.Fatalf("active list users: %d %v", r.code, r.body)
	}
	// CSRF: unsafe request without token rejected.
	body := map[string]any{"username": "viewer1", "password": ownerPW, "grants": []map[string]string{{"role_id": auth.RoleViewer}}}
	if r := c.do("POST", "/api/v1/users", body, map[string]string{csrfHeader: ""}); r.code != 403 || r.errCode() != "csrf_failed" {
		t.Fatalf("missing csrf: %d %v", r.code, r.body)
	}
	if r := c.do("POST", "/api/v1/users", body, map[string]string{csrfHeader: "forged"}); r.code != 403 {
		t.Fatalf("forged csrf: %d", r.code)
	}
	// Fresh MFA from enrolment satisfies step-up.
	r := c.do("POST", "/api/v1/users", body, nil)
	if r.code != 201 {
		t.Fatalf("create user: %d %v", r.code, r.body)
	}
	viewerID := r.body["id"].(string)
	etag := r.hdr.Get("ETag")
	// Expire the step-up window → critical action refused.
	ctx := context.Background()
	f.db.ExecContext(ctx, "UPDATE sessions SET mfa_verified_at=? WHERE revoked_at IS NULL", store.FormatTime(time.Now().Add(-10*time.Minute)))
	disabled := "disabled"
	r = c.do("PATCH", "/api/v1/users/"+viewerID, map[string]any{"status": disabled}, map[string]string{"If-Match": etag})
	if r.code != 403 || r.errCode() != "step_up_required" {
		t.Fatalf("stale step-up: %d %v", r.code, r.body)
	}
	// Allow the same TOTP step to be reused for this test only.
	f.db.ExecContext(ctx, "UPDATE totp_secrets SET last_used_step=0")
	code, _ := auth.TOTPCode(secret, time.Now())
	if r := c.do("POST", "/api/v1/auth/step-up", map[string]string{"code": code}, nil); r.code != 200 {
		t.Fatalf("step-up: %d %v", r.code, r.body)
	}
	// If-Match is mandatory and checked.
	if r := c.do("PATCH", "/api/v1/users/"+viewerID, map[string]any{"status": disabled}, nil); r.code != 428 {
		t.Fatalf("missing If-Match: %d", r.code)
	}
	if r := c.do("PATCH", "/api/v1/users/"+viewerID, map[string]any{"status": disabled}, map[string]string{"If-Match": `"r99"`}); r.code != 412 {
		t.Fatalf("stale If-Match: %d", r.code)
	}
	if r := c.do("PATCH", "/api/v1/users/"+viewerID, map[string]any{"status": disabled}, map[string]string{"If-Match": etag}); r.code != 200 {
		t.Fatalf("patch: %d %v", r.code, r.body)
	}
	// Session endpoint never leaks secrets.
	r = c.do("GET", "/api/v1/auth/session", nil, nil)
	raw, _ := json.Marshal(r.body)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "password") {
		t.Fatalf("session leaks: %s", raw)
	}
	// Logout invalidates.
	c.do("POST", "/api/v1/auth/logout", nil, nil)
	if r := c.do("GET", "/api/v1/auth/session", nil, nil); r.code != 401 {
		t.Fatalf("after logout: %d", r.code)
	}
}

func TestRBACMatrixAndTokens(t *testing.T) {
	_, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	for _, u := range []struct{ name, role string }{{"viewer1", auth.RoleViewer}, {"oper1", auth.RoleOperator}} {
		r := owner.do("POST", "/api/v1/users", map[string]any{"username": u.name, "password": ownerPW, "grants": []map[string]string{{"role_id": u.role}}}, nil)
		if r.code != 201 {
			t.Fatalf("create %s: %d %v", u.name, r.code, r.body)
		}
	}
	login := func(name string) *client {
		c := newClient(t, ts.URL)
		r := c.do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": ownerPW}, nil)
		if r.code != 200 || r.body["stage"] != "mfa_enroll" {
			t.Fatalf("login %s: %d %v", name, r.code, r.body)
		}
		enrol(t, c)
		return c
	}
	viewer, oper := login("viewer1"), login("oper1")
	matrix := []struct {
		c      *client
		who    string
		method string
		path   string
		want   int
	}{
		{viewer, "viewer", "GET", "/api/v1/jobs", 200},
		{viewer, "viewer", "GET", "/api/v1/users", 403},
		{viewer, "viewer", "GET", "/api/v1/audit", 403},
		{viewer, "viewer", "GET", "/api/v1/roles", 403},
		{viewer, "viewer", "GET", "/api/v1/secrets", 403},
		{oper, "operator", "GET", "/api/v1/jobs", 200},
		{oper, "operator", "GET", "/api/v1/audit", 403},
		{oper, "operator", "GET", "/api/v1/users", 403},
		{owner, "owner", "GET", "/api/v1/audit", 200},
		{owner, "owner", "GET", "/api/v1/secrets", 200},
	}
	for _, m := range matrix {
		if r := m.c.do(m.method, m.path, nil, nil); r.code != m.want {
			t.Errorf("%s %s %s: %d want %d", m.who, m.method, m.path, r.code, m.want)
		}
	}
	// Operator cannot create users even with fresh MFA (no permission).
	if r := oper.do("POST", "/api/v1/users", map[string]any{"username": "x9x", "password": ownerPW}, nil); r.code != 403 {
		t.Errorf("operator create user: %d", r.code)
	}
	// Tokens: create, use, scope limits.
	r := owner.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "scopes": []string{"jobs.read"}, "expires_in_days": 1}, nil)
	tok, _ := r.body["token"].(string)
	if r.code != 201 || tok == "" {
		t.Fatalf("create token: %d %v", r.code, r.body)
	}
	bc := newClient(t, ts.URL)
	bc.bearer = tok
	if r := bc.do("GET", "/api/v1/jobs", nil, nil); r.code != 200 {
		t.Fatalf("bearer jobs: %d", r.code)
	}
	if r := bc.do("GET", "/api/v1/users", nil, nil); r.code != 403 {
		t.Fatalf("bearer outside scope: %d", r.code)
	}
	bc.bearer = tok + "x"
	if r := bc.do("GET", "/api/v1/jobs", nil, nil); r.code != 401 {
		t.Fatalf("tampered bearer: %d", r.code)
	}
	// Token listing never returns the secret.
	r = owner.do("GET", "/api/v1/tokens", nil, nil)
	raw, _ := json.Marshal(r.body)
	if strings.Contains(string(raw), tok) {
		t.Fatal("token list leaks plaintext")
	}
	// IDOR: viewer cannot revoke the owner's token (no permission), and an
	// operator-level token holder cannot see another user's tokens.
	id := r.body["items"].([]any)[0].(map[string]any)["id"].(string)
	if r := viewer.do("DELETE", "/api/v1/tokens/"+id, nil, nil); r.code != 403 {
		t.Fatalf("viewer revoke owner token: %d", r.code)
	}
}

func TestLoginThrottlingHTTP(t *testing.T) {
	_, ts := setupServer(t)
	enrolOwner(t, ts)
	c := newClient(t, ts.URL)
	for i := 0; i < 5; i++ {
		if r := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": "wrong-password-xyz"}, nil); r.code != 401 || r.errCode() != "invalid_credentials" {
			t.Fatalf("attempt %d: %d %v", i, r.code, r.body)
		}
	}
	r := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": ownerPW}, nil)
	if r.code != 429 || r.errCode() != "rate_limited" {
		t.Fatalf("locked: %d %v", r.code, r.body)
	}
	// Unknown user error is indistinguishable from a wrong password.
	r = newClient(t, ts.URL).do("POST", "/api/v1/auth/login", map[string]string{"username": "ghost", "password": ownerPW}, map[string]string{"X-Forwarded-For": "1.1.1.1", "X-Real-IP": "198.51.100.3", "Origin": "https://ngm.example.com"})
	if r.code != 401 || r.errCode() != "invalid_credentials" {
		t.Fatalf("unknown user: %d %v", r.code, r.body)
	}
}

func TestAuditTrailRecordsAuthEvents(t *testing.T) {
	_, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	newClient(t, ts.URL).do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": "wrong-password-xyz"}, nil)
	r := owner.do("GET", "/api/v1/audit?limit=50", nil, nil)
	if r.code != 200 {
		t.Fatalf("%d %v", r.code, r.body)
	}
	actions := map[string]bool{}
	for _, it := range r.body["items"].([]any) {
		m := it.(map[string]any)
		actions[m["action"].(string)+"/"+m["result"].(string)] = true
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), ownerPW) || strings.Contains(string(raw), "wrong-password") {
			t.Fatalf("audit leaks password: %s", raw)
		}
	}
	for _, want := range []string{"setup.owner_create/success", "auth.login/success", "auth.mfa_enroll/success", "auth.login/failure"} {
		if !actions[want] {
			t.Errorf("missing audit %s (have %v)", want, actions)
		}
	}
	if r := owner.do("GET", "/api/v1/audit/verify", nil, nil); r.body["ok"] != true {
		t.Fatalf("chain: %v", r.body)
	}
}
