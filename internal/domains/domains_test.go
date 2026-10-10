package domains

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/dnsq"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

// fakeDNS models one zone with an authoritative server and a caching resolver.
type fakeDNS struct {
	auth    map[string][]dnsq.RR // "name TYPE" → records at the authoritative server
	cache   map[string][]dnsq.RR // resolver answers (may be stale)
	authErr bool
}

func (f *fakeDNS) Query(_ context.Context, server, name string, qtype uint16, rec bool) (*dnsq.Response, error) {
	k := name + " " + dnsq.TypeName(qtype)
	if server == "198.51.100.53" { // authoritative
		if rec {
			return nil, errors.New("authoritative server asked for recursion")
		}
		if f.authErr {
			return nil, errors.New("i/o timeout")
		}
		return &dnsq.Response{Rcode: "NOERROR", Authoritative: true, Answers: f.auth[k]}, nil
	}
	if !rec {
		return nil, errors.New("resolver asked without recursion")
	}
	if v, ok := f.cache[k]; ok {
		return &dnsq.Response{Rcode: "NOERROR", Answers: v}, nil
	}
	switch {
	case k == "example.com SOA":
		return &dnsq.Response{Rcode: "NOERROR", Answers: []dnsq.RR{{Name: "example.com", Type: "SOA", Value: "ns1.example.net"}}}, nil
	case k == "www.example.com SOA":
		return &dnsq.Response{Rcode: "NOERROR", Authority: []dnsq.RR{{Name: "example.com", Type: "SOA"}}}, nil
	case k == "example.com NS":
		return &dnsq.Response{Rcode: "NOERROR", Answers: []dnsq.RR{{Name: "example.com", Type: "NS", TTL: 86400, Value: "ns1.example.net"}}}, nil
	case k == "ns1.example.net A":
		return &dnsq.Response{Rcode: "NOERROR", Answers: []dnsq.RR{{Name: "ns1.example.net", Type: "A", Value: "198.51.100.53"}}}, nil
	}
	return &dnsq.Response{Rcode: "NOERROR", Answers: f.auth[k]}, nil
}

func setup(t *testing.T) (*Service, *Checker, *fakeDNS) {
	db := storetest.New(t)
	f := &fakeDNS{auth: map[string][]dnsq.RR{}, cache: map[string][]dnsq.RR{}}
	return &Service{DB: db, Audit: audit.New(db)}, &Checker{DB: db, Q: f, Resolvers: []string{"192.0.2.53"}}, f
}

func TestRegistryValidationAndUsage(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	for _, bad := range []string{"", "localhost", "1.2.3.4", "a..b.com", "-x.com", "*.example.com", "under_score.com"} {
		if _, err := s.Create(ctx, nil, bad, "general", ""); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	d, err := s.Create(ctx, nil, "Example.COM.", "website", "")
	if err != nil || d.FQDN != "example.com" || d.Status != "unknown" {
		t.Fatalf("%v %+v", err, d)
	}
	if _, err := s.Create(ctx, nil, "example.com", "", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.AddExpectation(ctx, nil, d.ID, Expect{Name: "other.org", Type: "A", Value: "192.0.2.1"}); err == nil {
		t.Fatal("expectation outside the domain accepted")
	}
	for _, e := range []Expect{{Type: "A", Value: "::1"}, {Type: "AAAA", Value: "1.2.3.4"}, {Type: "CAA", Value: "issue x"}, {Type: "MX", Value: "x"}, {Type: "CNAME", Value: "bad..x"}} {
		if _, err := s.AddExpectation(ctx, nil, d.ID, e); err == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
	if _, err := s.AddExpectation(ctx, nil, d.ID, Expect{Name: "@", Type: "A", Value: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	// A certificate covering a sub-name makes the domain in use.
	s.DB.ExecContext(ctx, `INSERT INTO certificates(id,name,source,sans_json,created_at,updated_at) VALUES('C1','c','uploaded','["*.example.com"]','x','x')`)
	u, _ := s.Usage(ctx, "example.com")
	if len(u) != 1 || u[0].Kind != "certificate" {
		t.Fatalf("usage %+v", u)
	}
	if err := s.Delete(ctx, nil, d.ID, d.Revision); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	if ok, _ := s.Registered(ctx, "deep.www.example.com"); !ok {
		t.Fatal("sub-name not recognised as registered")
	}
	if ok, _ := s.Registered(ctx, "badexample.com"); ok {
		t.Fatal("suffix confusion: badexample.com is not inside example.com")
	}
}

func TestCheckerAuthoritativeVsResolver(t *testing.T) {
	ctx := context.Background()
	s, c, f := setup(t)
	d, _ := s.Create(ctx, nil, "example.com", "general", "")
	ttl := 300
	s.AddExpectation(ctx, nil, d.ID, Expect{Name: "example.com", Type: "A", Value: "203.0.113.7", TTL: &ttl})
	s.AddExpectation(ctx, nil, d.ID, Expect{Name: "www.example.com", Type: "CNAME", Value: "example.com"})
	s.AddExpectation(ctx, nil, d.ID, Expect{Name: "example.com", Type: "TXT", Value: "v=spf1 -all"})
	f.auth["example.com A"] = []dnsq.RR{{Name: "example.com", Type: "A", TTL: 300, Value: "203.0.113.7"}}
	f.auth["www.example.com CNAME"] = []dnsq.RR{{Name: "www.example.com", Type: "CNAME", TTL: 300, Value: "other.example.net"}}
	f.auth["example.com CAA"] = []dnsq.RR{{Name: "example.com", Type: "CAA", Value: `0 issue "letsencrypt.org"`}}
	// The resolver still caches the old address.
	f.cache["example.com A"] = []dnsq.RR{{Name: "example.com", Type: "A", TTL: 120, Value: "203.0.113.9"}}
	d, _ = s.Get(ctx, d.ID)
	if err := c.Check(ctx, d); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Get(ctx, d.ID)
	got := map[string]Compare{}
	for _, cmp := range d.Comparison {
		got[cmp.Name+" "+cmp.Type] = cmp
	}
	if g := got["example.com A"]; g.Status != "propagating" || !strings.Contains(g.Detail, "120 s") {
		t.Fatalf("A: %+v", g)
	}
	if g := got["www.example.com CNAME"]; g.Status != "mismatch" || !strings.Contains(g.Detail, "other.example.net") {
		t.Fatalf("CNAME: %+v", g)
	}
	if g := got["example.com TXT"]; g.Status != "missing" {
		t.Fatalf("TXT: %+v", g)
	}
	if d.Status != "attention" {
		t.Fatalf("status %s", d.Status)
	}
	// The cache expires → match.
	delete(f.cache, "example.com A")
	c.Check(ctx, d)
	d, _ = s.Get(ctx, d.ID)
	for _, cmp := range d.Comparison {
		if cmp.Name == "example.com" && cmp.Type == "A" && cmp.Status != "match" {
			t.Fatalf("after cache expiry: %+v", cmp)
		}
	}
	// Authoritative server unreachable → unknown, never "ok".
	f.authErr = true
	c.Check(ctx, d)
	d, _ = s.Get(ctx, d.ID)
	for _, cmp := range d.Comparison {
		if cmp.Status != "unknown" {
			t.Fatalf("with authoritative failure: %+v", cmp)
		}
	}
	// Stale evidence → unknown.
	s.DB.ExecContext(ctx, "UPDATE dns_observations SET observed_at=?", time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339Nano))
	f.authErr = false
	d, _ = s.Get(ctx, d.ID)
	if d.Status != "unknown" {
		t.Fatalf("stale evidence status %s", d.Status)
	}
}

func TestCAAAllows(t *testing.T) {
	cases := []struct {
		caa  []string
		wild bool
		want bool
	}{
		{nil, false, true},
		{[]string{`0 issue "letsencrypt.org"`}, false, true},
		{[]string{`0 issue "digicert.com"`}, false, false},
		{[]string{`0 issue "digicert.com"`, `0 issue "LetsEncrypt.org; validationmethods=http-01"`}, false, true},
		{[]string{`0 issue "letsencrypt.org"`, `0 issuewild ";"`}, true, false},
		{[]string{`0 iodef "mailto:x@y"`}, false, true},
	}
	for i, c := range cases {
		if got := CAAAllows(c.caa, "letsencrypt.org", c.wild); got != c.want {
			t.Fatalf("case %d: %v", i, got)
		}
	}
}
