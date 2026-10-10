package gateway

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	labelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	alpnRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9/._-]{0,31}$`)
	pathRe    = regexp.MustCompile(`^/[A-Za-z0-9._~!*()+,;=:@%/-]{0,255}$`)
	versionRe = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)
)

func sscanVersion(v string, a, b, c *int) (int, error) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("bad version")
	}
	fmt.Sscan(m[1], a)
	fmt.Sscan(m[2], b)
	n := 2
	if m[3] != "" {
		fmt.Sscan(m[3], c)
		n = 3
	}
	return n, nil
}

// ValidHostname reports whether s is a lowercase ASCII (punycode) FQDN.
func ValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// HostPattern is a validated exact or leading-wildcard host name.
type HostPattern struct {
	Wildcard bool   // "*.suffix" — matches one or more labels before suffix (Nginx semantics)
	Name     string // exact name, or the suffix without "*."
}

func (h HostPattern) String() string {
	if h.Wildcard {
		return "*." + h.Name
	}
	return h.Name
}

// ParseHostPattern validates a host/SNI match value for an operator.
func ParseHostPattern(op, v string) (HostPattern, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch op {
	case OpExact:
		if !ValidHostname(v) {
			return HostPattern{}, fmt.Errorf("%q is not a valid host name (use punycode for IDN)", v)
		}
		return HostPattern{Name: v}, nil
	case OpWildcard:
		suf, ok := strings.CutPrefix(v, "*.")
		if !ok || !ValidHostname(suf) {
			return HostPattern{}, fmt.Errorf("%q is not a valid wildcard (form: *.example.com)", v)
		}
		return HostPattern{Wildcard: true, Name: suf}, nil
	}
	return HostPattern{}, fmt.Errorf("operator %q not allowed for host names", op)
}

// Matches reports whether name (lowercased by the caller) matches the pattern.
func (h HostPattern) Matches(name string) bool {
	if h.Wildcard {
		return strings.HasSuffix(name, "."+h.Name) && len(name) > len(h.Name)+1
	}
	return name == h.Name
}

// Overlaps reports whether two wildcard patterns can match a common name
// with neither being an exact match (ambiguous precedence → rejected).
func (h HostPattern) Overlaps(o HostPattern) bool {
	if !h.Wildcard || !o.Wildcard {
		return false
	}
	return h.Name == o.Name || strings.HasSuffix(h.Name, "."+o.Name) || strings.HasSuffix(o.Name, "."+h.Name)
}

// regex renders an anchored, case-insensitive-safe regex fragment for the pattern.
func (h HostPattern) regex() string {
	if h.Wildcard {
		return `.+\.` + regexp.QuoteMeta(h.Name)
	}
	return regexp.QuoteMeta(h.Name)
}

// ─── TLS front (ssl_preread) ordering ──────────────────────────────────────

// FrontRule is one SNI/ALPN dispatch entry of a stream_tls_front listener.
type FrontRule struct {
	SNI     HostPattern
	ALPN    string // "" = any
	RouteID string // passthrough route, or "" for the listener's TLS-termination hop
	Target  string // upstream name
	Kind    string // ProtoTLSPassthrough | ProtoTLSTerminate
}

// rank: lower sorts first. Exact SNI before wildcard; ALPN-qualified before
// unqualified; then longer (more specific) wildcard suffix; then name.
func (r FrontRule) rank() (int, int, int, string, string) {
	w := 0
	if r.SNI.Wildcard {
		w = 1
	}
	a := 1
	if r.ALPN != "" {
		a = 0
	}
	return w, a, -len(r.SNI.Name), r.SNI.Name, r.ALPN
}

// SortFrontRules orders rules by precedence (deterministic, total).
func SortFrontRules(rs []FrontRule) {
	sort.SliceStable(rs, func(i, j int) bool {
		a1, a2, a3, a4, a5 := rs[i].rank()
		b1, b2, b3, b4, b5 := rs[j].rank()
		if a1 != b1 {
			return a1 < b1
		}
		if a2 != b2 {
			return a2 < b2
		}
		if a3 != b3 {
			return a3 < b3
		}
		if a4 != b4 {
			return a4 < b4
		}
		return a5 < b5
	})
}

// Regex is the Nginx map key (applied to "$ssl_preread_server_name|$ssl_preread_alpn_protocols").
func (r FrontRule) Regex() string {
	s := "^" + r.SNI.regex() + `\|`
	if r.ALPN != "" {
		s += `(?:.*,)?` + regexp.QuoteMeta(r.ALPN) + `(?:,.*)?$`
	}
	return s
}

// MatchFront picks the first rule matching sni and the client's ALPN list,
// mirroring the generated map. An empty sni never matches a rule.
func MatchFront(rules []FrontRule, sni string, alpn []string) (FrontRule, bool) {
	sni = strings.ToLower(sni)
	if sni == "" {
		return FrontRule{}, false
	}
	for _, r := range rules {
		if !r.SNI.Matches(sni) {
			continue
		}
		if r.ALPN != "" && !contains(alpn, r.ALPN) {
			continue
		}
		return r, true
	}
	return FrontRule{}, false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ─── HTTP vhost/location selection (mirrors Nginx) ─────────────────────────

// Location is one HTTP location in a vhost.
type Location struct {
	Exact   bool
	Path    string
	RouteID string
}

// SelectVhost returns the index of the vhost whose names match host:
// exact names first, then the longest matching wildcard, else -1 (default server).
func SelectVhost(vhosts [][]HostPattern, host string) int {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	best, bestLen := -1, -1
	for i, names := range vhosts {
		for _, n := range names {
			if !n.Wildcard && n.Name == host {
				return i
			}
		}
	}
	for i, names := range vhosts {
		for _, n := range names {
			if n.Wildcard && n.Matches(host) && len(n.Name) > bestLen {
				best, bestLen = i, len(n.Name)
			}
		}
	}
	return best
}

// SelectLocation mirrors Nginx: exact match wins, else the longest prefix.
func SelectLocation(locs []Location, path string) (Location, bool) {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, l := range locs {
		if l.Exact && l.Path == path {
			return l, true
		}
	}
	var best Location
	found := false
	for _, l := range locs {
		if !l.Exact && strings.HasPrefix(path, l.Path) && (!found || len(l.Path) > len(best.Path)) {
			best, found = l, true
		}
	}
	return best, found
}
