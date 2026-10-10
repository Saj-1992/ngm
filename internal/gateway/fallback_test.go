package gateway

import (
	"strings"
	"testing"
)

// ADR-036: with a fallback website, nothing unmatched is closed or rejected.
func TestFallbackWebsiteReplacesRejects(t *testing.T) {
	p := mustValid(t, fixture())
	out, err := Compile(p, nil, caps, CompileInput{GenID: "G1", ProbeToken: "tok123", CertPEM: map[string]string{"CA": "PEM", "FB": "PEM"},
		FallbackSite: "W1", FallbackCertID: "FB"})
	if err != nil {
		t.Fatal(err)
	}
	h, s := string(out.Files[FileHTTP]), string(out.Files[FileStream])
	if _, ok := out.Files["certs/FB.crt"]; !ok {
		t.Fatal("fallback certificate file must be part of the generation even when no route uses it")
	}
	for _, want := range []string{"root " + SiteRoot("W1") + ";", "server_tokens off;", "ssl_certificate_key " + KeyPath("FB") + ";"} {
		if !strings.Contains(h, want) {
			t.Errorf("http config lacks %q", want)
		}
	}
	if strings.Contains(h, "ssl_reject_handshake on;") {
		t.Error("TLS default servers must present the fallback certificate, not reject the handshake")
	}
	if strings.Contains(s, `return "";`) {
		t.Error("unknown SNI on the shared front must reach the fallback site, not a closed connection")
	}
	// Default servers no longer close connections (explicit reject routes may still return 444).
	for _, blk := range strings.Split(h, "server {") {
		if strings.Contains(blk, "server_name _;") && strings.Contains(blk, "return 444;") {
			t.Errorf("default server still closes connections:\n%s", blk)
		}
	}
	// Without the setting, behaviour is unchanged.
	plain := compile(t, p)
	if !strings.Contains(string(plain.Files[FileHTTP]), "ssl_reject_handshake on;") {
		t.Error("baseline changed")
	}
}

func TestSimulationReportsFallbackSite(t *testing.T) {
	p := mustValid(t, fixture())
	r := Simulate(p, SimInput{Address: "198.51.100.1", Port: 80, Host: "unknown.invalid", FallbackSite: true})
	if r.Outcome != "fallback_site" {
		t.Fatalf("outcome %q, trace %+v", r.Outcome, r.Trace)
	}
	if r = Simulate(p, SimInput{Address: "198.51.100.1", Port: 80, Host: "unknown.invalid"}); r.Outcome == "fallback_site" {
		t.Fatal("no fallback configured")
	}
}
