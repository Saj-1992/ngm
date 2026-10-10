package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCF is an in-memory Cloudflare API (zones + dns_records).
type fakeCF struct {
	mu      sync.Mutex
	token   string
	records map[string]Record
	seq     int
	writes  []string
	authHdr []string
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authHdr = append(f.authHdr, r.Header.Get("Authorization"))
	ok := func(v any) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": v})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "Invalid API Token"}}})
		return
	}
	p := r.URL.Path
	switch {
	case p == "/user/tokens/verify":
		ok(map[string]string{"status": "active"})
	case p == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			ok([]Zone{{ID: "Z1", Name: "example.com"}})
		} else {
			ok([]Zone{})
		}
	case p == "/zones/Z1/dns_records" && r.Method == "GET":
		var rs []Record
		for _, x := range f.records {
			rs = append(rs, x)
		}
		ok(rs)
	case p == "/zones/Z1/dns_records" && r.Method == "POST":
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		f.seq++
		rec.ID = "R" + string(rune('0'+f.seq))
		f.records[rec.ID] = rec
		f.writes = append(f.writes, "create "+rec.Name+" "+rec.Type)
		ok(rec)
	case strings.HasPrefix(p, "/zones/Z1/dns_records/") && r.Method == "PUT":
		id := strings.TrimPrefix(p, "/zones/Z1/dns_records/")
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = id
		f.records[id] = rec
		f.writes = append(f.writes, "update "+id)
		ok(rec)
	default:
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "not found"}}})
	}
}

func setup(t *testing.T) (*Client, *fakeCF) {
	f := &fakeCF{token: "tok-secret-123", records: map[string]Record{
		"E1": {ID: "E1", Type: "A", Name: "example.com", Content: "198.51.100.1", TTL: 300},                       // external, conflicting
		"E2": {ID: "E2", Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300},                  // external, unrelated
		"M1": {ID: "M1", Type: "A", Name: "www.example.com", Content: "203.0.113.9", TTL: 1, Comment: Marker},     // NGM-managed, outdated
		"M2": {ID: "M2", Type: "TXT", Name: "example.com", Content: "v=ngm-ok", TTL: 1, Comment: Marker + " e2e"}, // NGM-managed, current
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Client{Token: f.token, Base: srv.URL}, f
}

func TestPlanPreservesExternalRecords(t *testing.T) {
	ctx := context.Background()
	c, f := setup(t)
	if err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	z, err := c.FindZone(ctx, "app.example.com")
	if err != nil || z.ID != "Z1" {
		t.Fatalf("zone: %v %+v", err, z)
	}
	cur, _ := c.Records(ctx, z.ID)
	desired := []Desired{
		{Name: "example.com", Type: "A", Value: "203.0.113.7"},
		{Name: "www.example.com", Type: "A", Value: "203.0.113.7"},
		{Name: "example.com", Type: "TXT", Value: "v=ngm-ok"},
		{Name: "api.example.com", Type: "CNAME", Value: "example.com"},
		{Name: "example.com", Type: "CAA", Value: `0 issue "letsencrypt.org"`},
	}
	p, err := MakePlan(z, cur, desired)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, ch := range p.Changes {
		got[ch.Desired.Name+" "+ch.Desired.Type] = ch.Action
	}
	want := map[string]string{"example.com A": "conflict", "www.example.com A": "update", "example.com TXT": "unchanged", "api.example.com CNAME": "create", "example.com CAA": "create"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %s want %s (all %v)", k, got[k], v, got)
		}
	}
	if p.External != 1 || p.Hash == "" {
		t.Fatalf("external=%d hash=%q", p.External, p.Hash)
	}
	// Same inputs → same hash (the apply is bound to the preview).
	p2, _ := MakePlan(z, cur, desired)
	if p2.Hash != p.Hash {
		t.Fatal("plan hash not deterministic")
	}
	res, err := c.Apply(ctx, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.records["E1"].Content != "198.51.100.1" || f.records["E2"].Content != "mail.example.com" {
		t.Fatal("an external record was modified")
	}
	if f.records["M1"].Content != "203.0.113.7" || !strings.Contains(f.records["M1"].Comment, Marker) {
		t.Fatalf("managed record not updated: %+v", f.records["M1"])
	}
	skipped := 0
	for _, a := range res {
		if a.Action == "skipped_conflict" {
			skipped++
		}
	}
	if skipped != 1 || len(f.writes) != 3 {
		t.Fatalf("writes %v results %+v", f.writes, res)
	}
	// Created A/CNAME records are not proxied (traffic must reach the gateway).
	for _, r := range f.records {
		if r.Name == "api.example.com" && (r.Proxied == nil || *r.Proxied) {
			t.Fatal("created record is proxied")
		}
		if r.Type == "CAA" && (r.Data == nil || r.Data.Value != "letsencrypt.org") {
			t.Fatalf("CAA data %+v", r.Data)
		}
	}
	// Explicit adoption of the conflict.
	cur, _ = c.Records(ctx, z.ID)
	p, _ = MakePlan(z, cur, desired)
	if _, err := c.Apply(ctx, p, map[string]bool{"E1": true}); err != nil {
		t.Fatal(err)
	}
	if f.records["E1"].Content != "203.0.113.7" || !f.records["E1"].Managed() {
		t.Fatalf("adopted record %+v", f.records["E1"])
	}
	// Drift: a managed record changed outside NGM.
	f.records["M1"] = Record{ID: "M1", Type: "A", Name: "www.example.com", Content: "192.0.2.66", Comment: Marker}
	cur, _ = c.Records(ctx, z.ID)
	if d := Drift(cur, desired); len(d) != 1 || !strings.Contains(d[0], "www.example.com A") {
		t.Fatalf("drift %v", d)
	}
}

func TestTokenNeverInErrors(t *testing.T) {
	ctx := context.Background()
	c, _ := setup(t)
	c.Token = "wrong-secret-token-xyz"
	err := c.Verify(ctx)
	if err == nil || strings.Contains(err.Error(), "wrong-secret-token-xyz") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("%v", err)
	}
	c.Base = "http://127.0.0.1:1"
	err = c.Verify(ctx)
	if err == nil || strings.Contains(err.Error(), "wrong-secret-token-xyz") {
		t.Fatalf("unreachable: %v", err)
	}
}
