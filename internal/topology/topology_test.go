package topology

import (
	"testing"

	"github.com/ngm-gateway/ngm/internal/gateway"
)

func TestBuildAndImpact(t *testing.T) {
	m := &gateway.Model{
		Listeners:    []gateway.Listener{{ID: "L1", Name: "web", Kind: "http", Address: "0.0.0.0", Port: 80, Enabled: true}},
		Endpoints:    []gateway.Endpoint{{ID: "E1", Name: "a"}, {ID: "E2", Name: "b"}},
		Pools:        []gateway.Pool{{ID: "P1", Name: "pool", Members: []gateway.PoolMember{{EndpointID: "E1"}}}},
		Certificates: []gateway.Certificate{{ID: "C1", Name: "cert"}},
		Routes: []gateway.Route{
			{ID: "R1", Name: "site", ListenerID: "L1", DestKind: "pool", DestID: "P1", CertificateID: "C1", Enabled: true, Matches: []gateway.Match{{Field: "host", Value: "www.example.com"}}},
			{ID: "R2", Name: "api", ListenerID: "L1", DestKind: "endpoint", DestID: "E2", Enabled: true},
		},
	}
	g := Build(m, Observed{Endpoint: map[string]string{"E1": "down"}, Domains: []string{"example.com"}, FWRules: []FWRule{{ID: "F1", Key: "web", Port: 80, Proto: "tcp", State: "present"}}})
	types := map[string]int{}
	for _, e := range g.Edges {
		types[e.Type]++
	}
	if types["matches"] != 2 || types["forwards_to"] != 3 || types["uses_certificate"] != 1 || types["receives"] != 1 || types["requires_firewall_rule"] != 1 {
		t.Fatalf("%v", types)
	}
	for _, n := range g.Nodes {
		if n.ID == "endpoint:E1" && n.Status != "down" || n.ID == "endpoint:E2" && n.Status != "unknown" {
			t.Fatalf("observed overlay %+v", n)
		}
	}
	imp := Analyze(g, "endpoint:E1")
	if len(imp.Affected) < 3 || len(imp.Critical) != 2 {
		t.Fatalf("impact %+v", imp)
	}
	if imp := Analyze(g, "certificate:C1"); len(imp.Critical) != 1 {
		t.Fatalf("cert impact %+v", imp)
	}
}
