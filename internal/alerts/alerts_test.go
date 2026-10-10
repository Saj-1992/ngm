package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func TestLifecycleDedupEscalateResolve(t *testing.T) {
	ctx := context.Background()
	s := &Store{DB: storetest.New(t)}
	now := time.Now()
	c := Condition{Rule: "backend_down", Subject: "app", Severity: "warning", Message: "down"}
	tr, _ := s.Sync(ctx, []Condition{c, c}, now)
	if len(tr) != 1 || tr[0].Event != "firing" {
		t.Fatalf("fire: %+v", tr)
	}
	if tr, _ := s.Sync(ctx, []Condition{c}, now); len(tr) != 0 {
		t.Fatal("repeat must not re-notify")
	}
	open, _ := s.List(ctx, true, 0)
	if err := s.Acknowledge(ctx, open[0].ID, "U1"); err != nil {
		t.Fatal(err)
	}
	c.Severity = "critical"
	if tr, _ := s.Sync(ctx, []Condition{c}, now); len(tr) != 1 {
		t.Fatal("escalation must notify")
	}
	tr, _ = s.Sync(ctx, nil, now)
	if len(tr) != 1 || tr[0].Event != "resolved" {
		t.Fatalf("resolve: %+v", tr)
	}
	if o, _ := s.List(ctx, true, 0); len(o) != 0 {
		t.Fatal("still open")
	}
}

func TestEvaluateFromEvidence(t *testing.T) {
	ctx := context.Background()
	db := storetest.New(t)
	now := time.Now()
	db.ExecContext(ctx, "INSERT INTO service_heartbeats(service,pid,version,status,detail,observed_at) VALUES('ngm-ops',1,'x','healthy','',?),('ngm-monitor',1,'x','healthy','',?)",
		store.FormatTime(now), store.FormatTime(now.Add(-10*time.Minute)))
	db.ExecContext(ctx, "INSERT INTO certificates(id,name,source,not_after,created_at,updated_at) VALUES('C1','soon','uploaded',?,'x','x'),('C2','dead','uploaded',?,'x','x')",
		store.FormatTime(now.Add(5*24*time.Hour)), store.FormatTime(now.Add(-time.Hour)))
	conds, _ := Evaluate(ctx, db, now)
	got := map[string]string{}
	for _, c := range conds {
		got[c.Rule+":"+c.Subject] = c.Severity
	}
	for k, v := range map[string]string{"service_unresponsive:ngm-monitor": "critical", "cert_expiring:soon": "warning", "cert_expired:dead": "critical", "nginx_unknown:nginx": "warning"} {
		if got[k] != v {
			t.Fatalf("%s = %q (all %v)", k, got[k], got)
		}
	}
	if _, ok := got["service_unresponsive:ngm-ops"]; ok {
		t.Fatal("healthy service alerted")
	}
}

func notifier(t *testing.T) *Notifier {
	db := storetest.New(t)
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	v := vault.New(db, kr)
	v.Init(context.Background())
	return &Notifier{DB: db, Vault: v, AllowPrivate: true, Host: "gw1"}
}

func TestWebhookAndTelegramDelivery(t *testing.T) {
	ctx := context.Background()
	n := notifier(t)
	var mu sync.Mutex
	var gotSig, gotBody, tgPath, tgBody string
	fail := 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.URL.Path, "/bot") {
			tgPath, tgBody = r.URL.Path, string(b)
			return
		}
		if fail > 0 {
			fail--
			w.WriteHeader(503)
			return
		}
		gotSig, gotBody = r.Header.Get("X-NGM-Signature"), string(b)
	}))
	defer srv.Close()
	n.HTTP = srv.Client()
	n.TelegramBase = srv.URL
	if _, err := n.Create(ctx, TargetInput{Name: "w", Kind: "webhook", URL: "http://example.com/x", Enabled: true}); err == nil {
		t.Fatal("plain http webhook accepted")
	}
	wh, err := n.Create(ctx, TargetInput{Name: "w", Kind: "webhook", URL: "https://example.com/hook", Secret: "0123456789abcdef-secret", Enabled: true, MinSev: "warning"})
	if err != nil {
		t.Fatal(err)
	}
	// Point the stored URL at the test server (Create requires https).
	n.DB.ExecContext(ctx, "UPDATE notification_targets SET config_json=? WHERE id=?", `{"url":"`+srv.URL+`/hook","min_severity":"warning"}`, wh.ID)
	tg, err := n.Create(ctx, TargetInput{Name: "tg", Kind: "telegram", ChatID: "-100123", Secret: "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Enabled: true, MinSev: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := n.List(ctx); strings.Contains(toJSON(l), "AAAAAAAA") {
		t.Fatal("secret in target list")
	}
	n.DB.ExecContext(ctx, "INSERT INTO alerts(id,rule,subject,severity,state,first_at,last_at) VALUES('A1','backend_down','app','warning','firing','x','x'),('A2','cert_expired','c','critical','firing','x','x')")
	k, _ := n.Enqueue(ctx, []Transition{{Event: "firing", Alert: Alert{ID: "A1", Rule: "backend_down", Subject: "app", Severity: "warning", Message: "down"}}})
	if k != 1 {
		t.Fatalf("min severity filter: %d deliveries", k)
	}
	now := time.Now()
	for i := 0; i < 3; i++ { // 503, 503, 200 with backoff
		n.Run(ctx, now)
		now = now.Add(time.Hour)
	}
	ds, _ := n.Deliveries(ctx, 10)
	if ds[0].Status != "sent" || ds[0].Attempts != 3 {
		t.Fatalf("retry: %+v", ds[0])
	}
	m := hmac.New(sha256.New, []byte("0123456789abcdef-secret"))
	m.Write([]byte(gotBody))
	if gotSig != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		t.Fatal("bad HMAC signature")
	}
	n.Enqueue(ctx, []Transition{{Event: "firing", Alert: Alert{ID: "A2", Rule: "cert_expired", Subject: "c", Severity: "critical", Message: "expired"}}})
	n.Run(ctx, now)
	if !strings.Contains(tgPath, "/bot123456789:") || !strings.Contains(tgBody, "-100123") || !strings.Contains(tgBody, "cert_expired") {
		t.Fatalf("telegram: %s %s", tgPath, tgBody)
	}
	_ = tg
}

func TestSSRFGuardAndRateLimit(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1", "fd00::1", "100.64.0.1"} {
		if publicOnly(netip.MustParseAddr(s)) {
			t.Fatalf("%s considered public", s)
		}
	}
	if !publicOnly(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address refused")
	}
	ctx := context.Background()
	n := notifier(t)
	n.HTTP = nil
	// Creation rejects literal internal addresses; create with AllowPrivate to
	// exercise the dial-time guard (DNS rebinding case).
	wh, _ := n.Create(ctx, TargetInput{Name: "w", Kind: "webhook", URL: "https://127.0.0.1/x", Enabled: true})
	n.AllowPrivate = false
	n.Test(ctx, wh.ID)
	n.Run(ctx, time.Now())
	ds, _ := n.Deliveries(ctx, 1)
	if !strings.Contains(ds[0].LastError, "non-public") {
		t.Fatalf("SSRF guard: %+v", ds[0])
	}
	// Rate limit: RatePerHour sent in the last hour → further ones are marked rate_limited.
	for i := 0; i < RatePerHour; i++ {
		n.DB.ExecContext(ctx, "INSERT INTO notification_deliveries(id,target_id,event,status,next_at,created_at,sent_at) VALUES(?,?,'test','sent',?,?,?)",
			"D"+strings.Repeat("0", 3)+string(rune('A'+i%26))+strings.Repeat("x", i), wh.ID, store.FormatTime(time.Now()), store.FormatTime(time.Now()), store.FormatTime(time.Now()))
	}
	id, _ := n.Test(ctx, wh.ID)
	n.Run(ctx, time.Now())
	var st string
	n.DB.QueryRowContext(ctx, "SELECT status FROM notification_deliveries WHERE id=?", id).Scan(&st)
	if st != "rate_limited" {
		t.Fatalf("rate limit: %s", st)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
