package gateway

import (
	"strings"
	"testing"
	"time"
)

var caps = CapsFromVersion("1.24.0", true, true, true)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func opts() BuildOptions {
	return BuildOptions{ReservedPorts: []int{22}, APIListen: "127.0.0.1:9999", Now: now}
}

func ep(id, host string, port int, transport string) Endpoint {
	return Endpoint{ID: id, Name: id, Host: host, Port: port, Transport: transport, TLSVerify: true, Weight: 1, ConnectTimeoutMS: 5000, ReadTimeoutMS: 60000, WriteTimeoutMS: 60000}
}

func m(field, op, v string) Match { return Match{Field: field, Operator: op, Value: v} }

// fixture: http :80, tcp :2222, shared 443 front (terminate + passthrough + ALPN + fallback), https :8443.
func fixture() *Model {
	return &Model{
		Listeners: []Listener{
			{ID: "L80", Name: "web", Kind: KindHTTP, Address: "0.0.0.0", Port: 80, Family: "ipv4", Enabled: true},
			{ID: "LTCP", Name: "tcp", Kind: KindStream, Address: "0.0.0.0", Port: 2222, Family: "ipv4", Enabled: true},
			{ID: "L443", Name: "front", Kind: KindStreamTLSFront, Address: "0.0.0.0", Port: 443, Family: "ipv4", Enabled: true},
			{ID: "L8443", Name: "tls", Kind: KindHTTPS, Address: "0.0.0.0", Port: 8443, Family: "ipv4", Enabled: true, Options: ListenerOptions{HTTP2: true}},
		},
		Endpoints: []Endpoint{
			ep("EAPP", "127.0.0.1", 8081, "http"),
			ep("EAPI", "10.0.0.5", 8082, "http"),
			ep("ETCP", "127.0.0.1", 9001, "tcp"),
			ep("EXRAY", "127.0.0.1", 9443, "tcp"),
			ep("EXRAY2", "127.0.0.1", 9444, "tcp"),
			ep("ESEC", "backend.example.net", 443, "https"),
		},
		Pools: []Pool{{ID: "PAPP", Name: "app", Strategy: "least_conn", Members: []PoolMember{{"EAPP", 1, false}, {"EAPI", 2, false}}}},
		Certificates: []Certificate{
			{ID: "CA", Name: "a-cert", SANs: []string{"a.example.com", "*.example.com"}, NotAfter: now.Add(90 * 24 * time.Hour), Status: "valid", HasKey: true},
		},
		Routes: []Route{
			{ID: "R1", Name: "site", ListenerID: "L80", Protocol: ProtoHTTP, DestKind: DestPool, DestID: "PAPP", Enabled: true, Matches: []Match{m(FieldHost, OpExact, "a.example.com")}},
			{ID: "R2", Name: "api", ListenerID: "L80", Protocol: ProtoHTTP, DestKind: DestEndpoint, DestID: "EAPI", Enabled: true, Options: RouteOptions{WebSocket: true},
				Matches: []Match{m(FieldHost, OpExact, "a.example.com"), m(FieldPathPrefix, OpPrefix, "/api/")}},
			{ID: "R3", Name: "wild", ListenerID: "L80", Protocol: ProtoHTTP, DestKind: DestRedirect, Enabled: true, Options: RouteOptions{RedirectURL: "https://a.example.com/"},
				Matches: []Match{m(FieldHost, OpWildcard, "*.example.org")}},
			{ID: "R4", Name: "raw", ListenerID: "LTCP", Protocol: ProtoTCP, DestKind: DestEndpoint, DestID: "ETCP", Enabled: true},
			{ID: "R5", Name: "panel", ListenerID: "L443", Protocol: ProtoTLSTerminate, DestKind: DestPool, DestID: "PAPP", CertificateID: "CA", Enabled: true,
				Matches: []Match{m(FieldSNI, OpExact, "a.example.com")}},
			{ID: "R6", Name: "xray", ListenerID: "L443", Protocol: ProtoTLSPassthrough, DestKind: DestEndpoint, DestID: "EXRAY", Enabled: true,
				Matches: []Match{m(FieldSNI, OpExact, "x.example.com")}},
			{ID: "R7", Name: "xray-h2", ListenerID: "L443", Protocol: ProtoTLSPassthrough, DestKind: DestEndpoint, DestID: "EXRAY2", Enabled: true, Options: RouteOptions{BackendProxyProto: true},
				Matches: []Match{m(FieldSNI, OpExact, "x.example.com"), m(FieldALPN, OpExact, "h2")}},
			{ID: "R8", Name: "fallback", ListenerID: "L443", Protocol: ProtoTLSPassthrough, DestKind: DestEndpoint, DestID: "EXRAY", Fallback: true, Enabled: true},
			{ID: "R9", Name: "secure", ListenerID: "L8443", Protocol: ProtoHTTP, DestKind: DestEndpoint, DestID: "ESEC", CertificateID: "CA", Enabled: true,
				Matches: []Match{m(FieldHost, OpExact, "a.example.com")}},
		},
	}
}

func build(t *testing.T, mdl *Model) (*Plan, []Issue) {
	t.Helper()
	return Build(mdl, caps, opts())
}

func mustValid(t *testing.T, mdl *Model) *Plan {
	t.Helper()
	p, is := build(t, mdl)
	if HasErrors(is) {
		t.Fatalf("unexpected errors: %+v", is)
	}
	return p
}

func compile(t *testing.T, p *Plan) *Output {
	t.Helper()
	out, err := Compile(p, nil, caps, CompileInput{GenID: "G1", ProbeToken: "tok123", CertPEM: map[string]string{"CA": "PEM"}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCompileFixture(t *testing.T) {
	p := mustValid(t, fixture())
	out := compile(t, p)
	h := string(out.Files[FileHTTP])
	s := string(out.Files[FileStream])
	for _, want := range []string{
		"listen 0.0.0.0:80;", "server_name a.example.com;", "location /api/ {", "location / {",
		"proxy_set_header Upgrade $http_upgrade;", "least_conn;", "server 10.0.0.5:8082 weight=2",
		"server_name *.example.org;", "return 308 https://a.example.com/;",
		"listen 0.0.0.0:80 default_server;", "return 444;",
		"listen 0.0.0.0:8443 ssl http2;", "if ($ssl_server_name != $host) { return 421; }",
		"proxy_pass https://ngm_up_esec;", "proxy_ssl_verify on;", "proxy_ssl_name backend.example.net;",
		"listen 127.0.42.1:", "ssl proxy_protocol;", "real_ip_header proxy_protocol;", "ssl_reject_handshake on;",
		"proxy_set_header X-NGM-Probe \"\";", "\"tok123\" \"G1\"", "if ($http_x_ngm_probe = \"tok123\") { return 204; }", "return 421;", "set_real_ip_from 127.0.0.0/8;",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("http config missing %q", want)
		}
	}
	for _, want := range []string{
		"listen 0.0.0.0:2222;", "proxy_pass ngm_sup_etcp;",
		"ssl_preread on;", "proxy_protocol on;", `"~*^x\.example\.com\|(?:.*,)?h2(?:,.*)?$" ngm_sup_exray2;`,
		`"~*^x\.example\.com\|" ngm_strip_r6;`, `"~*^a\.example\.com\|" ngm_term_l443;`, "default ngm_strip_r8;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stream config missing %q\n%s", want, s)
		}
	}
	// ALPN-qualified rule precedes the unqualified one for the same SNI.
	if strings.Index(s, "h2(?:") > strings.Index(s, `"~*^x\.example\.com\|" ngm_strip_r6`) {
		t.Error("ALPN-qualified rule must come first")
	}
	if len(out.Probes) < 3 || len(out.Listens) < 5 {
		t.Errorf("probes=%v listens=%v", out.Probes, out.Listens)
	}
	if out.Files["certs/CA.crt"] == nil {
		t.Error("certificate not deployed")
	}
	// Determinism.
	if compile(t, mustValid(t, fixture())).Hash != out.Hash {
		t.Error("compilation is not deterministic")
	}
}

func TestRejectsWhenInvalid(t *testing.T) {
	mdl := fixture()
	mdl.Routes[0].Matches[0].Value = "a.example.com; include /etc/shadow"
	p, is := build(t, mdl)
	if !HasErrors(is) {
		t.Fatal("injection value accepted")
	}
	if _, err := Compile(p, is, caps, CompileInput{GenID: "G1", ProbeToken: "t"}); err != ErrInvalid {
		t.Fatalf("compiled despite errors: %v", err)
	}
}

func expectCode(t *testing.T, mdl *Model, code string) {
	t.Helper()
	_, is := build(t, mdl)
	for _, i := range is {
		if i.Code == code && i.Severity == "error" {
			return
		}
	}
	t.Errorf("expected error %s, got %+v", code, is)
}

func TestConflictsAndSafety(t *testing.T) {
	cases := map[string]struct {
		mut  func(*Model)
		code string
	}{
		"duplicate host+path": {func(m *Model) {
			r := m.Routes[0]
			r.ID, r.Name = "RX", "dup"
			m.Routes = append(m.Routes, r)
		}, "route_conflict"},
		"overlapping wildcards": {func(m *Model) {
			m.Routes = append(m.Routes, Route{ID: "RX", Name: "w2", ListenerID: "L80", Protocol: ProtoHTTP, DestKind: DestReject, Enabled: true,
				Matches: []Match{m2(FieldHost, OpWildcard, "*.sub.example.org")}})
		}, "route_wildcard_overlap"},
		"http and stream on same port": {func(m *Model) {
			m.Listeners = append(m.Listeners, Listener{ID: "LX", Name: "web443", Kind: KindHTTPS, Address: "10.0.0.9", Port: 443, Family: "ipv4", Enabled: true})
		}, "listener_module_conflict"},
		"two tcp routes": {func(m *Model) {
			r := m.Routes[3]
			r.ID, r.Name = "RX", "raw2"
			m.Routes = append(m.Routes, r)
		}, "stream_multiple_routes"},
		"host match on passthrough": {func(m *Model) {
			m.Routes[5].Matches = append(m.Routes[5].Matches, m2(FieldHost, OpExact, "x.example.com"))
		}, "route_match_field"},
		"path on raw tcp": {func(m *Model) {
			m.Routes[3].Matches = []Match{m2(FieldPathPrefix, OpPrefix, "/x")}
		}, "route_match_field"},
		"cert does not cover host": {func(m *Model) {
			m.Routes[8].Matches[0].Value = "other.test.com"
		}, "route_cert_san"},
		"expired cert":      {func(m *Model) { m.Certificates[0].NotAfter = now.Add(-time.Hour) }, "route_cert_expired"},
		"metadata endpoint": {func(m *Model) { m.Endpoints[1].Host = "169.254.169.254" }, "endpoint_link_local"},
		"api endpoint":      {func(m *Model) { m.Endpoints[0].Port = 9999 }, "endpoint_api"},
		"ssh port listener": {func(m *Model) { m.Listeners[1].Port = 22 }, "listener_reserved_port"},
		"internal address":  {func(m *Model) { m.Listeners[0].Address = "127.0.42.1" }, "listener_internal"},
		"mixed pool transport": {func(m *Model) {
			m.Pools[0].Members = append(m.Pools[0].Members, PoolMember{"ETCP", 1, false})
		}, "pool_mixed_transport"},
		"fallback with sni": {func(m *Model) {
			m.Routes[7].Matches = []Match{m2(FieldSNI, OpExact, "z.example.com")}
		}, "route_fallback_match"},
		"terminate as fallback": {func(m *Model) {
			m.Routes[7].Protocol, m.Routes[7].DestKind, m.Routes[7].DestID, m.Routes[7].CertificateID = ProtoTLSTerminate, DestPool, "PAPP", "CA"
		}, "route_fallback_terminate"},
		"passthrough and terminate same sni": {func(m *Model) {
			m.Routes[5].Matches[0].Value = "a.example.com"
		}, "route_conflict"},
		"tcp backend for http route":   {func(m *Model) { m.Routes[1].DestID = "ETCP" }, "route_dest_transport"},
		"http backend for passthrough": {func(m *Model) { m.Routes[5].DestID = "EAPP" }, "route_dest_transport"},
		"redirect injection":           {func(m *Model) { m.Routes[2].Options.RedirectURL = "https://x.com/;return 200" }, "route_redirect_url"},
		"website missing":              {func(m *Model) { m.Routes[0].DestKind = DestWebsite }, "route_dest_missing"},
		"website unpublished": {func(m *Model) {
			m.Websites = []Website{{ID: "W1", Name: "site"}}
			m.Routes[0].DestKind, m.Routes[0].DestID = DestWebsite, "W1"
		}, "route_website_unpublished"},
		"no stream module": {func(m *Model) {}, ""},
	}
	for name, c := range cases {
		if c.code == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			mdl := fixture()
			c.mut(mdl)
			expectCode(t, mdl, c.code)
		})
	}
	// Capability gating.
	_, is := Build(fixture(), CapsFromVersion("1.24.0", false, false, true), opts())
	found := false
	for _, i := range is {
		if i.Code == "cap_stream" {
			found = true
		}
	}
	if !found {
		t.Error("stream listeners accepted without stream module")
	}
}

func m2(f, op, v string) Match { return m(f, op, v) }

func TestALPNSplitWithTerminateIsAllowed(t *testing.T) {
	mdl := fixture()
	// Same SNI: h2 clients passthrough, others terminated at NGM.
	mdl.Routes[6].Matches[0].Value = "a.example.com"
	p := mustValid(t, mdl)
	r := Simulate(p, SimInput{Address: "203.0.113.1", Port: 443, SNI: "a.example.com", ALPN: []string{"h2", "http/1.1"}})
	if r.Outcome != "passthrough" || r.RouteName != "xray-h2" {
		t.Fatalf("%+v", r)
	}
	r = Simulate(p, SimInput{Address: "203.0.113.1", Port: 443, SNI: "a.example.com", ALPN: []string{"http/1.1"}, Path: "/"})
	if r.Outcome != "proxy_http" || r.RouteName != "panel" {
		t.Fatalf("%+v", r)
	}
}

func TestSimulation(t *testing.T) {
	p := mustValid(t, fixture())
	cases := []struct {
		name    string
		in      SimInput
		outcome string
		route   string
	}{
		{"http exact host root", SimInput{Address: "198.51.100.1", Port: 80, Host: "a.example.com", Path: "/"}, "proxy_http", "site"},
		{"http longest prefix", SimInput{Address: "198.51.100.1", Port: 80, Host: "A.Example.com:80", Path: "/api/v1/x?q=1"}, "proxy_http", "api"},
		{"http prefix boundary", SimInput{Address: "198.51.100.1", Port: 80, Host: "a.example.com", Path: "/apix"}, "proxy_http", "site"},
		{"http wildcard", SimInput{Address: "198.51.100.1", Port: 80, Host: "deep.www.example.org", Path: "/"}, "redirect", "wild"},
		{"http wildcard needs label", SimInput{Address: "198.51.100.1", Port: 80, Host: "example.org", Path: "/"}, "closed", ""},
		{"http unknown host", SimInput{Address: "198.51.100.1", Port: 80, Host: "evil.test", Path: "/"}, "closed", ""},
		{"tcp", SimInput{Address: "198.51.100.1", Port: 2222}, "proxy_tcp", "raw"},
		{"front terminate", SimInput{Address: "198.51.100.1", Port: 443, SNI: "a.example.com", Path: "/api/x"}, "proxy_http", "panel"},
		{"front host != sni", SimInput{Address: "198.51.100.1", Port: 443, SNI: "a.example.com", Host: "b.example.com"}, "misdirected", ""},
		{"front passthrough", SimInput{Address: "198.51.100.1", Port: 443, SNI: "x.example.com", ALPN: []string{"http/1.1"}}, "passthrough", "xray"},
		{"front passthrough alpn", SimInput{Address: "198.51.100.1", Port: 443, SNI: "X.example.com", ALPN: []string{"h2"}}, "passthrough", "xray-h2"},
		{"front no sni", SimInput{Address: "198.51.100.1", Port: 443}, "passthrough", "fallback"},
		{"front ech", SimInput{Address: "198.51.100.1", Port: 443, SNI: "public.cdn.test", ECH: true}, "passthrough", "fallback"},
		{"no listener", SimInput{Address: "198.51.100.1", Port: 81}, "no_listener", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Simulate(p, c.in)
			if r.Outcome != c.outcome || r.RouteName != c.route {
				t.Fatalf("got outcome=%s route=%q trace=%+v", r.Outcome, r.RouteName, r.Trace)
			}
			if len(r.Uncertainty) == 0 {
				t.Error("simulation must state its limits")
			}
		})
	}
	// Without a fallback, unmatched SNI is closed.
	mdl := fixture()
	mdl.Routes = mdl.Routes[:7]
	p2 := mustValid(t, mdl)
	if r := Simulate(p2, SimInput{Address: "198.51.100.1", Port: 443}); r.Outcome != "closed" || !r.Fallback {
		t.Fatalf("%+v", r)
	}
	s := string(compile(t, p2).Files[FileStream])
	if !strings.Contains(s, "default ngm_reject_l443;") || !strings.Contains(s, `return "";`) {
		t.Fatalf("reject path missing:\n%s", s)
	}
}

// The simulator and compiler must agree on rule order.
func TestSimulatorMatchesCompiledOrder(t *testing.T) {
	p := mustValid(t, fixture())
	s := string(compile(t, p).Files[FileStream])
	var lp *ListenerPlan
	for _, x := range p.Listeners {
		if x.L.ID == "L443" {
			lp = x
		}
	}
	last := -1
	for _, r := range lp.Rules {
		i := strings.Index(s, `"~*`+r.Regex()+`"`)
		if i < 0 || i < last {
			t.Fatalf("rule %s missing or out of order", r.Regex())
		}
		last = i
	}
}

func TestHostPatterns(t *testing.T) {
	w, _ := ParseHostPattern(OpWildcard, "*.Example.com")
	if !w.Matches("a.example.com") || !w.Matches("a.b.example.com") || w.Matches("example.com") || w.Matches("aexample.com") {
		t.Fatal("wildcard semantics")
	}
	for _, bad := range []string{"", "a", "exa mple.com", "-a.com", "a..com", "a.com.", "*.com", "a.com;x", "exämple.com"} {
		if _, err := ParseHostPattern(OpExact, bad); err == nil {
			if bad == "*.com" {
				continue
			}
			t.Errorf("accepted %q", bad)
		}
	}
	if !CertCovers([]string{"*.example.com"}, HostPattern{Name: "a.example.com"}) || CertCovers([]string{"*.example.com"}, HostPattern{Name: "a.b.example.com"}) {
		t.Fatal("TLS wildcard covers exactly one label")
	}
}

func TestHTTP2SyntaxByVersion(t *testing.T) {
	p := mustValid(t, fixture())
	newCaps := CapsFromVersion("1.26.1", true, true, true)
	out, err := Compile(p, nil, newCaps, CompileInput{GenID: "G1", ProbeToken: "t", CertPEM: map[string]string{"CA": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	h := string(out.Files[FileHTTP])
	if !strings.Contains(h, "listen 0.0.0.0:8443 ssl;") || !strings.Contains(h, "http2 on;") {
		t.Fatal("nginx >= 1.25.1 must use the http2 directive")
	}
	old := CapsFromVersion("1.18.0", true, true, true)
	if old.RejectHandshake {
		t.Fatal("1.18 has no ssl_reject_handshake")
	}
	if _, err := Compile(p, nil, old, CompileInput{GenID: "G1", ProbeToken: "t", CertPEM: map[string]string{"CA": "x"}}); err == nil {
		t.Fatal("TLS default server without reject_handshake needs a default certificate")
	}
}

func TestAcmeChallengeLocationOnPort80(t *testing.T) {
	m := &Model{
		Listeners: []Listener{{ID: "L80", Name: "web", Kind: KindHTTP, Address: "0.0.0.0", Family: "ipv4", Port: 80, Enabled: true}, {ID: "L81", Name: "alt", Kind: KindHTTP, Address: "0.0.0.0", Family: "ipv4", Port: 8081, Enabled: true}},
		Endpoints: []Endpoint{{ID: "E1", Name: "app", Host: "127.0.0.1", Port: 9000, Transport: "http", Weight: 1, ConnectTimeoutMS: 1000, ReadTimeoutMS: 1000, WriteTimeoutMS: 1000}},
		Routes: []Route{
			{ID: "R1", Name: "site", ListenerID: "L80", Protocol: ProtoHTTP, DestKind: DestEndpoint, DestID: "E1", Enabled: true, Matches: []Match{{Field: FieldHost, Operator: OpExact, Value: "a.example.com"}}},
			{ID: "R2", Name: "alt", ListenerID: "L81", Protocol: ProtoHTTP, DestKind: DestEndpoint, DestID: "E1", Enabled: true, Matches: []Match{{Field: FieldHost, Operator: OpExact, Value: "a.example.com"}}},
		},
	}
	caps := Caps{StreamModule: true, RejectHandshake: true, SSLPreread: true}
	p, issues := Build(m, caps, BuildOptions{})
	out, err := Compile(p, issues, caps, CompileInput{GenID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", ProbeToken: "tok"})
	if err != nil {
		t.Fatal(err, issues)
	}
	h := string(out.Files[FileHTTP])
	// Port 80: the vhost and the default server answer challenges; 8081 does not.
	if strings.Count(h, "location ^~ "+AcmePrefix) != 2 || !strings.Contains(h, "location / { return 444; }") {
		t.Fatalf("acme locations:\n%s", h)
	}
	// Reserved path on port 80 is rejected; allowed on other ports.
	m.Routes[0].Matches = append(m.Routes[0].Matches, Match{Field: FieldPathPrefix, Operator: OpPrefix, Value: "/.well-known/acme-challenge"})
	m.Routes[1].Matches = append(m.Routes[1].Matches, Match{Field: FieldPathPrefix, Operator: OpPrefix, Value: "/.well-known/acme-challenge"})
	_, issues = Build(m, caps, BuildOptions{})
	n := 0
	for _, i := range issues {
		if i.Code == "route_reserved_path" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("reserved path issues: %+v", issues)
	}
}

func TestWebsiteRoute(t *testing.T) {
	m := &Model{
		Listeners: []Listener{{ID: "L1", Name: "web", Kind: KindHTTP, Address: "0.0.0.0", Family: "ipv4", Port: 8080, Enabled: true}},
		Websites:  []Website{{ID: "01J9WWWWWWWWWWWWWWWWWWWWWW", Name: "docs", Published: true}},
		Routes: []Route{
			{ID: "R1", Name: "root", ListenerID: "L1", Protocol: ProtoHTTP, DestKind: DestWebsite, DestID: "01J9WWWWWWWWWWWWWWWWWWWWWW", Enabled: true,
				Matches: []Match{{Field: FieldHost, Operator: OpExact, Value: "a.example.com"}}},
			{ID: "R2", Name: "docs", ListenerID: "L1", Protocol: ProtoHTTP, DestKind: DestWebsite, DestID: "01J9WWWWWWWWWWWWWWWWWWWWWW", Enabled: true,
				Matches: []Match{{Field: FieldHost, Operator: OpExact, Value: "b.example.com"}, {Field: FieldPathPrefix, Operator: OpPrefix, Value: "/docs/"}}},
		},
	}
	caps := Caps{StreamModule: true, RejectHandshake: true}
	p, issues := Build(m, caps, BuildOptions{})
	out, err := Compile(p, issues, caps, CompileInput{GenID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", ProbeToken: "tok"})
	if err != nil {
		t.Fatal(err, issues)
	}
	h := string(out.Files[FileHTTP])
	for _, want := range []string{"root /var/www/ngm/sites/01J9WWWWWWWWWWWWWWWWWWWWWW/current;", "alias /var/www/ngm/sites/01J9WWWWWWWWWWWWWWWWWWWWWW/current/;",
		"add_header X-Content-Type-Options nosniff always;", "autoindex off;"} {
		if !strings.Contains(h, want) {
			t.Fatalf("missing %q in:\n%s", want, h)
		}
	}
	if strings.Contains(h, "proxy_pass") {
		t.Fatal("websites must not proxy")
	}
	r := Simulate(p, SimInput{Address: "203.0.113.5", Port: 8080, Host: "b.example.com", Path: "/docs/x/"})
	if r.Outcome != "website" || !strings.Contains(r.Destination, "docs") {
		t.Fatalf("simulate: %+v", r)
	}
	// Path must end in / ; exact paths refused; passthrough refused.
	m.Routes[1].Matches[1].Value = "/docs"
	_, issues = Build(m, caps, BuildOptions{})
	if !hasIssue(issues, "route_website_path") {
		t.Fatalf("path issue: %+v", issues)
	}
}

func hasIssue(is []Issue, code string) bool {
	for _, i := range is {
		if i.Code == code {
			return true
		}
	}
	return false
}
