package perf

import (
	"strings"
	"testing"
)

func TestResolveRenderValidate(t *testing.T) {
	if p, _ := Recommend(1<<30, 1); p != "low" {
		t.Fatal(p)
	}
	if p, _ := Recommend(8<<30, 4); p != "high" {
		t.Fatal(p)
	}
	v := Resolve(Settings{Profile: "balanced", Overrides: map[string]int{"client_max_body_size": 500, "limit_req_rate": 20}}, 8<<30, 4)
	if v.Profile != "balanced" || v.Recommended != "high" {
		t.Fatalf("%+v", v)
	}
	r := v.Render()
	j := strings.Join(r.HTTPServer, "\n")
	if !strings.Contains(j, "client_max_body_size 500m;") || !strings.Contains(j, "limit_req zone=ngm_req burst=50 nodelay;") ||
		!strings.Contains(strings.Join(r.HTTP, ""), "rate=20r/s") || !strings.Contains(j, "proxy_buffers 8 8k;") {
		t.Fatalf("render:\n%s\n%v", j, r.HTTP)
	}
	// Overrides persist across profile changes.
	v2 := Resolve(Settings{Profile: "low", Overrides: map[string]int{"client_max_body_size": 500}}, 0, 0)
	for _, x := range v2.Values {
		if x.Name == "client_max_body_size" && (x.Effective != 500 || x.Default != 16) {
			t.Fatalf("%+v", x)
		}
	}
	if Resolve(Settings{}, 0, 0).Render().Hash == r.Hash {
		t.Fatal("hash must change with settings")
	}
	for _, bad := range []Settings{{Profile: "turbo"}, {Overrides: map[string]int{"worker_connections": 1}}, {Overrides: map[string]int{"keepalive_timeout": 0}}, {Overrides: map[string]int{"proxy_buffers": 1000}}} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// Busy buffers stay below (buffers-1)*size, as Nginx requires.
	low := Resolve(Settings{Overrides: map[string]int{"proxy_buffers": 2, "proxy_buffer_size": 4}}, 0, 0).Render()
	if !strings.Contains(strings.Join(low.HTTPServer, " "), "proxy_busy_buffers_size 4k;") {
		t.Fatal(low.HTTPServer)
	}
}
