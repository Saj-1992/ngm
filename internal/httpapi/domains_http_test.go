package httpapi

import (
	"context"
	"strings"
	"testing"
)

func TestDomainHTTPFlow(t *testing.T) {
	f, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	r := owner.do("POST", "/api/v1/domains", map[string]any{"fqdn": "Example.com", "purpose": "website"}, nil)
	if r.code != 201 || r.body["fqdn"] != "example.com" || r.body["dns_status"] != "unknown" {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	id, etag := r.body["id"].(string), r.hdr.Get("ETag")
	if r := owner.do("POST", "/api/v1/domains", map[string]any{"fqdn": "example.com"}, nil); r.code != 409 {
		t.Fatalf("duplicate: %d", r.code)
	}
	if r := owner.do("POST", "/api/v1/domains", map[string]any{"fqdn": "not a domain"}, nil); r.code != 400 {
		t.Fatalf("invalid: %d", r.code)
	}
	r = owner.do("POST", "/api/v1/domains/"+id+"/expectations", map[string]any{"name": "www.example.com", "type": "A", "value": "203.0.113.7", "ttl": 300}, nil)
	if r.code != 201 || len(r.body["expectations"].([]any)) != 1 || r.body["comparison"].([]any)[0].(map[string]any)["status"] != "unknown" {
		t.Fatalf("expectation: %d %v", r.code, r.body)
	}
	if r := owner.do("POST", "/api/v1/domains/"+id+"/check", nil, nil); r.code != 202 {
		t.Fatalf("check: %d", r.code)
	}
	var n int
	f.db.QueryRowContext(context.Background(), "SELECT count(*) FROM settings WHERE key=?", "dns.check_request."+id).Scan(&n)
	if n != 1 {
		t.Fatal("check request not recorded")
	}
	r = owner.do("GET", "/api/v1/domains/"+id, nil, nil)
	if r.body["domain"] == nil || r.body["usage"] == nil {
		t.Fatalf("get: %v", r.body)
	}
	// Unregistered route host → validation warning.
	l := owner.do("POST", "/api/v1/listeners", map[string]any{"name": "web", "kind": "http", "address": "0.0.0.0", "port": 8080}, nil).body["id"]
	e := owner.do("POST", "/api/v1/backends", map[string]any{"name": "app", "host": "127.0.0.1", "port": 9000, "transport": "http"}, nil).body["id"]
	owner.do("POST", "/api/v1/routes", map[string]any{"name": "other", "listener_id": l, "protocol": "http", "destination_kind": "endpoint", "destination_id": e,
		"matches": []map[string]string{{"field": "host", "operator": "exact", "value": "app.other.org"}}}, nil)
	owner.do("POST", "/api/v1/routes", map[string]any{"name": "mine", "listener_id": l, "protocol": "http", "destination_kind": "endpoint", "destination_id": e,
		"matches": []map[string]string{{"field": "host", "operator": "exact", "value": "www.example.com"}}}, nil)
	r = owner.do("GET", "/api/v1/gateway/validation", nil, nil)
	warn := 0
	for _, is := range r.body["issues"].([]any) {
		m := is.(map[string]any)
		if m["code"] == "domain_not_registered" {
			warn++
			if m["severity"] != "warning" {
				t.Fatal("must be a warning")
			}
		}
	}
	if warn != 1 || r.body["valid"] != true {
		t.Fatalf("registry warnings: %d %v", warn, r.body)
	}
	// In use by a route → delete refused.
	if r := owner.do("DELETE", "/api/v1/domains/"+id, nil, map[string]string{"If-Match": etag}); r.code != 409 {
		t.Fatalf("delete in use: %d %v", r.code, r.body)
	}
}

func TestCloudflareTokenHandling(t *testing.T) {
	f, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	d := owner.do("POST", "/api/v1/domains", map[string]any{"fqdn": "example.org"}, nil).body["id"].(string)
	if r := owner.do("POST", "/api/v1/domains/"+d+"/cloudflare/preview", nil, nil); r.code != 409 {
		t.Fatalf("preview without token: %d", r.code)
	}
	if r := owner.do("PUT", "/api/v1/integrations/cloudflare", map[string]string{"token": "bad token!"}, nil); r.code != 400 {
		t.Fatalf("bad token: %d", r.code)
	}
	const tok = "cfTokenABCDEFGHIJ0123456789_-xyz"
	if r := owner.do("PUT", "/api/v1/integrations/cloudflare", map[string]string{"token": tok}, nil); r.code != 200 {
		t.Fatalf("set: %d %v", r.code, r.body)
	}
	r := owner.do("GET", "/api/v1/integrations/cloudflare", nil, nil)
	if r.body["configured"] != true || strings.Contains(toJSON(r.body), tok) {
		t.Fatalf("get: %v", r.body)
	}
	var n int
	f.db.QueryRowContext(context.Background(), "SELECT count(*) FROM audit_events WHERE context_json LIKE ?", "%"+tok+"%").Scan(&n)
	var plain, rows int
	if err := f.db.QueryRowContext(context.Background(), "SELECT count(*), COALESCE(SUM(instr(ciphertext, CAST(? AS BLOB)) > 0), 0) FROM vault_secrets WHERE type='cloudflare_token'", tok).Scan(&rows, &plain); err != nil || rows != 1 {
		t.Fatalf("vault query: %v rows=%d", err, rows)
	}
	if n != 0 || plain != 0 {
		t.Fatal("token leaked into audit or stored in plaintext")
	}
	if r := owner.do("POST", "/api/v1/domains/"+d+"/cloudflare/preview", nil, nil); r.code != 202 {
		t.Fatalf("preview: %d", r.code)
	}
	if r := owner.do("POST", "/api/v1/domains/"+d+"/cloudflare/apply", map[string]any{"plan_hash": "short"}, nil); r.code != 400 {
		t.Fatalf("apply without a preview hash: %d", r.code)
	}
}
