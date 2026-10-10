package domains

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCreateSubdomainManualAndConflicts(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	parent, err := s.Create(ctx, nil, "example.com", "general", "")
	if err != nil {
		t.Fatal(err)
	}
	ttl := 300
	d, err := s.CreateSubdomain(ctx, nil, SubdomainInput{ParentID: parent.ID, Label: "App-1", Type: "a", Value: "203.0.113.7", TTL: &ttl, Proxied: true})
	if err != nil {
		t.Fatal(err)
	}
	if d.FQDN != "app-1.example.com" || len(d.Expected) != 1 || d.Expected[0].Type != "A" || !d.Expected[0].Proxied || *d.Expected[0].TTL != 300 {
		t.Fatalf("unexpected result: %+v", d)
	}
	// Same name again → conflict (never overwritten).
	if _, err := s.CreateSubdomain(ctx, nil, SubdomainInput{ParentID: parent.ID, Label: "app-1", Type: "A", Value: "203.0.113.8"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate in the registry must conflict: %v", err)
	}
	// A name that already exists at the provider is refused even if unregistered.
	if _, err := s.CreateSubdomain(ctx, nil, SubdomainInput{ParentID: parent.ID, Label: "mail", Type: "A", Value: "203.0.113.9", Taken: []string{"MAIL.example.com."}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("provider collision must conflict: %v", err)
	}
	// Validation.
	for name, in := range map[string]SubdomainInput{
		"bad label":    {ParentID: parent.ID, Label: "a.b", Type: "A", Value: "203.0.113.1"},
		"leading dash": {ParentID: parent.ID, Label: "-x", Type: "A", Value: "203.0.113.1"},
		"A with IPv6":  {ParentID: parent.ID, Label: "v6", Type: "A", Value: "2001:db8::1"},
		"AAAA v4":      {ParentID: parent.ID, Label: "v4", Type: "AAAA", Value: "203.0.113.1"},
		"TXT type":     {ParentID: parent.ID, Label: "t", Type: "TXT", Value: "x"},
		"bad ttl":      {ParentID: parent.ID, Label: "ttl", Type: "A", Value: "203.0.113.1", TTL: func() *int { v := 5; return &v }()},
		"bad cname":    {ParentID: parent.ID, Label: "cn", Type: "CNAME", Value: "not a name"},
	} {
		if _, err := s.CreateSubdomain(ctx, nil, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAutoLabelAvoidsCollisions(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	p, _ := s.Create(ctx, nil, "example.com", "general", "")
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		d, err := s.CreateSubdomain(ctx, nil, SubdomainInput{ParentID: p.ID, Label: "auto", Type: "A", Value: "203.0.113.2"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(d.FQDN, ".example.com") || !ValidLabel(strings.TrimSuffix(d.FQDN, ".example.com")) || seen[d.FQDN] {
			t.Fatalf("bad or repeated automatic name %q", d.FQDN)
		}
		seen[d.FQDN] = true
	}
	// Names already taken at the provider are skipped.
	l, err := s.AutoLabel(ctx, "example.com", 8, []string{"anything.example.com"})
	if err != nil || l == "anything" {
		t.Fatalf("label %q %v", l, err)
	}
}

func TestProxiedOnlyForProxiableTypes(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	p, _ := s.Create(ctx, nil, "example.com", "general", "")
	if _, err := s.AddExpectation(ctx, nil, p.ID, Expect{Name: "example.com", Type: "TXT", Value: "x", Proxied: true}); err == nil {
		t.Fatal("a TXT record must not be proxiable")
	}
}
