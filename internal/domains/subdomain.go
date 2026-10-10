package domains

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/cloudflare"
)

// SubdomainInput describes a subdomain to create under a registered parent.
type SubdomainInput struct {
	ParentID string `json:"parent_id"`
	// Label is the subdomain label. Empty or "auto" requests a generated one.
	Label   string `json:"label"`
	Type    string `json:"type"`  // A | AAAA | CNAME
	Value   string `json:"value"` // destination IP (A/AAAA) or target name (CNAME)
	TTL     *int   `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	// Taken are existing names in the provider zone (lowercase FQDNs), supplied
	// by the caller after a read-only provider lookup, used for collision checks.
	Taken []string `json:"-"`
}

// ValidLabel reports whether s is a valid single DNS label.
func ValidLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || strings.ContainsAny(s, ".") {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// AutoLabel generates a collision-free label under parent. Collisions are
// checked against the NGM registry and the provider names in taken.
func (s *Service) AutoLabel(ctx context.Context, parent string, length int, taken []string) (string, error) {
	have := map[string]bool{}
	for _, n := range taken {
		have[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	if length < 6 || length > 20 {
		length = 8
	}
	for i := 0; i < 50; i++ {
		l := cloudflare.GenerateLabel(length, randByte)
		fqdn := l + "." + parent
		if have[fqdn] {
			continue
		}
		if ok, err := s.exists(ctx, fqdn); err != nil {
			return "", err
		} else if ok {
			continue
		}
		return l, nil
	}
	return "", fmt.Errorf("%w: no free label found after 50 attempts", ErrConflict)
}

func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// CreateSubdomain registers parent's subdomain and its expected DNS record in
// one step. It never overwrites: an existing registry entry or provider name
// is a conflict. The provider record itself is created later through the
// previewed, confirmed Cloudflare apply job.
func (s *Service) CreateSubdomain(ctx context.Context, actor *auth.Principal, in SubdomainInput) (*Domain, error) {
	parent, err := s.Get(ctx, in.ParentID)
	if err != nil {
		return nil, err
	}
	label := strings.ToLower(strings.TrimSpace(in.Label))
	if label == "" || label == "auto" {
		if label, err = s.AutoLabel(ctx, parent.FQDN, 8, in.Taken); err != nil {
			return nil, err
		}
	}
	if !ValidLabel(label) {
		return nil, invalid("%q is not a valid subdomain label (letters, digits and hyphens; 1–63 characters; no leading or trailing hyphen)", label)
	}
	fqdn := label + "." + parent.FQDN
	for _, n := range in.Taken {
		if strings.EqualFold(strings.TrimSuffix(n, "."), fqdn) {
			return nil, fmt.Errorf("%w: %s already has a DNS record at the provider; NGM never overwrites existing records", ErrConflict, fqdn)
		}
	}
	t := strings.ToUpper(strings.TrimSpace(in.Type))
	v := strings.TrimSpace(in.Value)
	switch t {
	case "A":
		a, perr := netip.ParseAddr(v)
		if perr != nil || !a.Is4() {
			return nil, invalid("an A record needs an IPv4 address")
		}
	case "AAAA":
		a, perr := netip.ParseAddr(v)
		if perr != nil || !a.Is6() {
			return nil, invalid("an AAAA record needs an IPv6 address")
		}
	case "CNAME":
		if _, nerr := NormalizeFQDN(v); nerr != nil {
			return nil, invalid("a CNAME needs a valid target name")
		}
	default:
		return nil, invalid("record type must be A, AAAA or CNAME")
	}
	if in.TTL != nil && *in.TTL != 1 && (*in.TTL < 60 || *in.TTL > 86400) {
		return nil, invalid("TTL must be 1 (automatic) or between 60 and 86400 seconds")
	}
	purpose := in.Purpose
	if purpose == "" {
		purpose = "general"
	}
	d, err := s.Create(ctx, actor, fqdn, purpose, "")
	if err != nil {
		return nil, err // includes ErrConflict when the name is already registered
	}
	if d, err = s.AddExpectation(ctx, actor, d.ID, Expect{Name: fqdn, Type: t, Value: v, TTL: in.TTL, Proxied: in.Proxied}); err != nil {
		return nil, err
	}
	return d, nil
}

// exists reports whether fqdn is registered exactly (not merely inside a
// registered domain, which is what Registered answers).
func (s *Service) exists(ctx context.Context, fqdn string) (bool, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM domains WHERE fqdn=?", fqdn).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}
