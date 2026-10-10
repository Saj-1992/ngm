package deploy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ngm-gateway/ngm/internal/cloudflare"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/vault"
)

type miniCF struct {
	mu   sync.Mutex
	recs []cloudflare.Record
	puts int
}

func (m *miniCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ok := func(v any) { json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v}) }
	switch {
	case r.URL.Path == "/user/tokens/verify":
		ok(map[string]string{"status": "active"})
	case r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			ok([]cloudflare.Zone{{ID: "Z1", Name: "example.com"}})
		} else {
			ok([]any{})
		}
	case r.URL.Path == "/zones/Z1/dns_records" && r.Method == "GET":
		ok(m.recs)
	case r.URL.Path == "/zones/Z1/dns_records" && r.Method == "POST":
		var rec cloudflare.Record
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = "N" + string(rune('a'+len(m.recs)))
		m.recs = append(m.recs, rec)
		m.puts++
		ok(rec)
	default:
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "nope"}}})
	}
}

func TestCloudflareJobsBindApplyToPreview(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	cf := &miniCF{recs: []cloudflare.Record{{ID: "X1", Type: "MX", Name: "example.com", Content: "mx.example.net"}}}
	srv := httptest.NewServer(cf)
	defer srv.Close()
	CloudflareBase = srv.URL
	t.Cleanup(func() { CloudflareBase = "" })
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	e.c.Vault = vault.New(e.db, kr)
	reg := &domains.Service{DB: e.db, Audit: e.c.Audit}
	d, _ := reg.Create(ctx, nil, "example.com", "general", "")
	reg.AddExpectation(ctx, nil, d.ID, domains.Expect{Name: "example.com", Type: "A", Value: "203.0.113.7"})

	// No token → Blocked, nothing called.
	if j := e.submit(t, KindDNSPreview, DNSPayload{DomainID: d.ID}); j.State != jobs.Blocked || !strings.Contains(string(j.Error), "token") {
		t.Fatalf("no token: %s %s", j.State, j.Error)
	}
	e.c.Vault.Put(ctx, CloudflareTokenRef, []byte("tok"))
	j := e.submit(t, KindDNSPreview, DNSPayload{DomainID: d.ID})
	var res struct {
		Plan cloudflare.Plan `json:"plan"`
	}
	json.Unmarshal(j.Result, &res)
	if j.State != jobs.Succeeded || res.Plan.Hash == "" || len(res.Plan.Changes) != 1 || res.Plan.Changes[0].Action != "create" || res.Plan.External != 1 {
		t.Fatalf("preview: %s %s %+v", j.State, j.Result, res.Plan)
	}
	// A stale or missing hash is refused (explicit confirmation of this plan).
	if j := e.submit(t, KindDNSApply, DNSPayload{DomainID: d.ID, PlanHash: "deadbeef"}); j.State != jobs.Blocked || cf.puts != 0 {
		t.Fatalf("stale hash: %s", j.State)
	}
	// The expectations change after the preview → the old hash no longer applies.
	reg.AddExpectation(ctx, nil, d.ID, domains.Expect{Name: "www.example.com", Type: "CNAME", Value: "example.com"})
	if j := e.submit(t, KindDNSApply, DNSPayload{DomainID: d.ID, PlanHash: res.Plan.Hash}); j.State != jobs.Blocked || !strings.Contains(string(j.Error), "plan_changed") {
		t.Fatalf("changed plan: %s %s", j.State, j.Error)
	}
	j = e.submit(t, KindDNSPreview, DNSPayload{DomainID: d.ID})
	json.Unmarshal(j.Result, &res)
	j = e.submit(t, KindDNSApply, DNSPayload{DomainID: d.ID, PlanHash: res.Plan.Hash})
	if j.State != jobs.Succeeded || cf.puts != 2 || cf.recs[0].Content != "mx.example.net" {
		t.Fatalf("apply: %s %s puts=%d", j.State, j.Error, cf.puts)
	}
	var n int
	e.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE action='dns.cloudflare_apply'").Scan(&n)
	var prov string
	e.db.QueryRowContext(ctx, "SELECT dns_provider FROM domains WHERE id=?", d.ID).Scan(&prov)
	if n != 1 || prov != "cloudflare" {
		t.Fatalf("audit=%d provider=%s", n, prov)
	}
}
