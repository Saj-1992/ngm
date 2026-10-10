package gateway

import "testing"

func TestManagementOnly(t *testing.T) {
	ep := Endpoint{ID: "E", Name: "panel", Host: "127.0.0.1", Port: 9999}
	base := func() *Model {
		return &Model{
			Listeners: []Listener{{ID: "L443", Kind: "stream_tls_front"}, {ID: "L80", Kind: "http"}},
			Endpoints: []Endpoint{ep},
			Routes: []Route{{ID: "R", ListenerID: "L443", Protocol: "tls_terminate_http", DestKind: "endpoint", DestID: "E",
				Matches: []Match{{Field: "sni", Operator: "exact", Value: "ngm.example.com"}}}},
		}
	}
	if !managementOnly(base(), &ep, "ngm.example.com", "") {
		t.Fatal("TLS route on the management host must be allowed")
	}
	if managementOnly(base(), &ep, "", "") {
		t.Fatal("no management origin configured → never allowed")
	}
	m := base()
	m.Routes[0].ListenerID, m.Routes[0].Protocol = "L80", "http"
	if managementOnly(m, &ep, "ngm.example.com", "") {
		t.Fatal("plain HTTP must be refused")
	}
	m = base()
	m.Routes[0].Matches = append(m.Routes[0].Matches, Match{Field: "sni", Operator: "exact", Value: "other.example.com"})
	if managementOnly(m, &ep, "ngm.example.com", "") {
		t.Fatal("extra hosts must be refused")
	}
	m = base()
	m.Routes[0].Matches[0].Operator = "wildcard"
	if managementOnly(m, &ep, "ngm.example.com", "") {
		t.Fatal("non-exact match must be refused")
	}
	m = base()
	m.Pools = []Pool{{ID: "P", Members: []PoolMember{{EndpointID: "E"}}}}
	if managementOnly(m, &ep, "ngm.example.com", "") {
		t.Fatal("pool membership must be refused")
	}
	if OriginHost("https://NGM.example.com:8443") != "ngm.example.com" || OriginHost("https://a.b") != "a.b" {
		t.Fatal("OriginHost")
	}
}

func TestManagementOnlyPathMount(t *testing.T) {
	ep := Endpoint{ID: "E", Name: "panel", Host: "127.0.0.1", Port: 9999}
	m := &Model{
		Listeners: []Listener{{ID: "L", Kind: "stream_tls_front"}},
		Endpoints: []Endpoint{ep},
		Routes: []Route{{ID: "R", ListenerID: "L", Protocol: "tls_terminate_http", DestKind: "endpoint", DestID: "E",
			Matches: []Match{{Field: "sni", Operator: "exact", Value: "ngm.example.com"}, {Field: "path_prefix", Operator: "prefix", Value: "/a1b2c3d4/"}}}},
	}
	if !managementOnly(m, &ep, "ngm.example.com", "/a1b2c3d4") {
		t.Fatal("host + the configured panel path must be allowed")
	}
	if managementOnly(m, &ep, "ngm.example.com", "/other") {
		t.Fatal("a different path must be refused")
	}
	if managementOnly(m, &ep, "ngm.example.com", "") {
		t.Fatal("no configured path → a path-matched route is refused")
	}
}
