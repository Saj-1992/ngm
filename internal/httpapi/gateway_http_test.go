package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/observe"
)

func TestGatewayHTTPFlow(t *testing.T) {
	f, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	observe.Record(context.Background(), f.db, observe.KindNginx, observe.Nginx{Installed: true, Version: "1.24.0", ServiceState: "active", StreamModule: true, SSLPreread: true, HTTPV2: true}, 0)

	r := owner.do("POST", "/api/v1/listeners", map[string]any{"name": "web", "kind": "http", "address": "0.0.0.0", "port": 8080}, nil)
	if r.code != 201 || r.hdr.Get("ETag") != `"r1"` {
		t.Fatalf("listener: %d %v", r.code, r.body)
	}
	lid := r.body["id"].(string)
	r = owner.do("POST", "/api/v1/backends", map[string]any{"name": "app", "host": "127.0.0.1", "port": 9000, "transport": "http"}, nil)
	eid := r.body["id"].(string)
	r = owner.do("POST", "/api/v1/routes", map[string]any{"name": "site", "listener_id": lid, "protocol": "http", "destination_kind": "endpoint", "destination_id": eid,
		"matches": []map[string]string{{"field": "host", "operator": "exact", "value": "a.example.com"}}}, nil)
	if r.code != 201 {
		t.Fatalf("route: %d %v", r.code, r.body)
	}
	rid, rev := r.body["id"].(string), r.hdr.Get("ETag")

	// Validation + preview.
	r = owner.do("GET", "/api/v1/gateway/validation?preview=1", nil, nil)
	if r.body["valid"] != true {
		t.Fatalf("validation: %v", r.body)
	}
	files := r.body["preview"].(map[string]any)["files"].(map[string]any)
	if !strings.Contains(files["http/ngm.conf"].(string), "server_name a.example.com;") || strings.Contains(files["http/ngm.conf"].(string), "PRIVATE") {
		t.Fatal("preview content")
	}

	// Simulation.
	r = owner.do("POST", "/api/v1/gateway/simulate", map[string]any{"address": "203.0.113.5", "port": 8080, "host": "a.example.com", "path": "/x"}, nil)
	res := r.body["result"].(map[string]any)
	if res["route_name"] != "site" || res["outcome"] != "proxy_http" {
		t.Fatalf("simulate: %v", r.body)
	}

	// Deployment submission (idempotent) → 202 + job.
	r = owner.do("POST", "/api/v1/deployments", map[string]any{}, map[string]string{"Idempotency-Key": "deploy-key-001"})
	if r.code != 202 || r.body["job_id"] == nil || r.hdr.Get("Location") == "" {
		t.Fatalf("deploy: %d %v", r.code, r.body)
	}
	jid := r.body["job_id"]
	r = owner.do("POST", "/api/v1/deployments", map[string]any{}, map[string]string{"Idempotency-Key": "deploy-key-001"})
	if r.body["job_id"] != jid || r.body["replayed"] != true {
		t.Fatalf("idempotent replay: %v", r.body)
	}

	// Invalid model → 422 with issues; desired change never touches Nginx directly.
	r = owner.do("PUT", "/api/v1/routes/"+rid, map[string]any{"name": "site", "listener_id": lid, "protocol": "http", "destination_kind": "endpoint", "destination_id": eid,
		"matches": []map[string]string{{"field": "sni", "operator": "exact", "value": "a.example.com"}}}, map[string]string{"If-Match": rev})
	if r.code != 200 {
		t.Fatalf("update: %d %v", r.code, r.body)
	}
	r = owner.do("POST", "/api/v1/deployments", map[string]any{}, nil)
	if r.code != 422 || r.errCode() != "validation_failed" {
		t.Fatalf("invalid deploy: %d %v", r.code, r.body)
	}

	// In-use protection and stale ETag.
	if r := owner.do("DELETE", "/api/v1/backends/"+eid, nil, map[string]string{"If-Match": `"r1"`}); r.code != 409 {
		t.Fatalf("delete in-use: %d %v", r.code, r.body)
	}
	if r := owner.do("PUT", "/api/v1/routes/"+rid, map[string]any{"name": "x", "listener_id": lid, "protocol": "http", "destination_kind": "reject"}, map[string]string{"If-Match": rev}); r.code != 412 {
		t.Fatalf("stale etag: %d", r.code)
	}

	// Input validation.
	if r := owner.do("POST", "/api/v1/listeners", map[string]any{"name": "bad", "kind": "udp", "address": "0.0.0.0", "port": 53}, nil); r.code != 400 {
		t.Fatalf("udp listener: %d", r.code)
	}

	// Certificates: self-signed; key never in responses.
	r = owner.do("POST", "/api/v1/certificates/self-signed", map[string]any{"name": "test", "hosts": []string{"a.example.com"}, "days": 30}, nil)
	if r.code != 201 || r.body["has_key"] != true {
		t.Fatalf("cert: %d %v", r.code, r.body)
	}
	if r := owner.do("GET", "/api/v1/certificates", nil, nil); strings.Contains(strings.ToUpper(toJSON(r.body)), "PRIVATE KEY") {
		t.Fatal("key leaked")
	}

	// RBAC: viewer reads, cannot write or deploy.
	owner.do("POST", "/api/v1/users", map[string]any{"username": "viewer2", "password": ownerPW, "grants": []map[string]string{{"role_id": auth.RoleViewer}}}, nil)
	v := newClient(t, ts.URL)
	v.do("POST", "/api/v1/auth/login", map[string]string{"username": "viewer2", "password": ownerPW}, nil)
	enrol(t, v)
	if r := v.do("GET", "/api/v1/routes", nil, nil); r.code != 200 {
		t.Fatalf("viewer read: %d", r.code)
	}
	if r := v.do("POST", "/api/v1/listeners", map[string]any{"name": "x", "kind": "http", "address": "0.0.0.0", "port": 81}, nil); r.code != 403 {
		t.Fatalf("viewer write: %d", r.code)
	}
	if r := v.do("POST", "/api/v1/deployments", map[string]any{}, nil); r.code != 403 {
		t.Fatalf("viewer deploy: %d", r.code)
	}
}

func toJSON(v any) string {
	b, _ := jsonMarshal(v)
	return string(b)
}

var jsonMarshal = func(v any) ([]byte, error) { return json.Marshal(v) }
