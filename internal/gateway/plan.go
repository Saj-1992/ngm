package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Issue is a validation finding. Any Severity "error" blocks compilation.
type Issue struct {
	Severity string `json:"severity"` // error | warning
	Code     string `json:"code"`
	Message  string `json:"message"`
	Ref      string `json:"ref,omitempty"` // entity id
}

// BuildOptions carries host facts needed for safety checks.
type BuildOptions struct {
	ReservedPorts []int // e.g. SSH ports: listeners there are refused (management lockout, P0)
	APIListen     string
	// ManagementHost is the host of the configured HTTPS management origin
	// (config api.public_origin). Only a TLS route matching exactly this host
	// may point at the control API (publishing the Control Center).
	ManagementHost string
	// ManagementPath is the Control Center base path (config api.public_path),
	// e.g. "/a1b2c3d4"; the panel route may match this path_prefix to the API.
	ManagementPath string
	Now            time.Time
}

// Vhost is one HTTP server block.
type Vhost struct {
	Names     []HostPattern
	Default   bool
	CertID    string
	Locations []Location
}

// ListenerPlan is the compiled shape of one listener.
type ListenerPlan struct {
	L *Listener
	// http / https
	Vhosts []Vhost
	// stream_tls_front
	Rules         []FrontRule
	Fallback      *Route // nil → reject connections without a matching rule
	TermPort      int    // internal TLS-termination port (0 if no terminate routes)
	TermVhosts    []Vhost
	StripperPorts map[string]int // passthrough route id → internal PROXY-stripping port
	RejectPort    int            // internal port that closes unmatched connections (0 if fallback forwards)
	// stream
	StreamRoute *Route
}

// Plan is the validated, precedence-resolved configuration.
type Plan struct {
	Model     *Model
	Ix        *Index
	Listeners []*ListenerPlan
	RouteByID map[string]*Route
}

type checker struct {
	issues []Issue
}

func (c *checker) err(ref, code, f string, a ...any) {
	c.issues = append(c.issues, Issue{"error", code, fmt.Sprintf(f, a...), ref})
}
func (c *checker) warn(ref, code, f string, a ...any) {
	c.issues = append(c.issues, Issue{"warning", code, fmt.Sprintf(f, a...), ref})
}

// HasErrors reports whether any issue is an error.
func HasErrors(is []Issue) bool {
	for _, i := range is {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

func isHTTPModule(kind string) bool { return kind == KindHTTP || kind == KindHTTPS }

// Build validates the model and resolves precedence into a Plan.
func Build(m *Model, caps Caps, o BuildOptions) (*Plan, []Issue) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	c := &checker{}
	ix := NewIndex(m)
	p := &Plan{Model: m, Ix: ix, RouteByID: map[string]*Route{}}

	for i := range m.Endpoints {
		validateEndpoint(c, &m.Endpoints[i], o, managementOnly(m, &m.Endpoints[i], o.ManagementHost, o.ManagementPath))
	}
	for i := range m.Pools {
		validatePool(c, &m.Pools[i], ix)
	}
	validateListeners(c, m, caps, o)

	// Sort listeners and routes for deterministic output.
	ls := make([]*Listener, 0, len(m.Listeners))
	for i := range m.Listeners {
		ls = append(ls, &m.Listeners[i])
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Name < ls[j].Name })
	for i := range m.Routes {
		r := &m.Routes[i]
		p.RouteByID[r.ID] = r
		if _, ok := ix.Listener[r.ListenerID]; !ok {
			c.err(r.ID, "route_listener_missing", "route %q references a missing listener", r.Name)
		} else if !ix.Listener[r.ListenerID].Enabled && r.Enabled {
			c.warn(r.ID, "route_listener_disabled", "route %q is on a disabled listener and will not receive traffic", r.Name)
		}
		if !nameRe.MatchString(r.Name) {
			c.err(r.ID, "route_name", "route name %q is invalid", r.Name)
		}
	}
	next := InternalBase
	alloc := func() int { next++; return next - 1 }
	for _, l := range ls {
		if !l.Enabled {
			continue
		}
		routes := append([]*Route(nil), ix.ByListen[l.ID]...)
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Priority != routes[j].Priority {
				return routes[i].Priority < routes[j].Priority
			}
			return routes[i].Name < routes[j].Name
		})
		lp := &ListenerPlan{L: l, StripperPorts: map[string]int{}}
		for _, r := range routes {
			validateRouteCommon(c, r, l, ix, o)
		}
		switch l.Kind {
		case KindHTTP, KindHTTPS:
			lp.Vhosts = buildVhosts(c, l, routes, ix, l.Kind == KindHTTPS)
		case KindStream:
			var active []*Route
			for _, r := range routes {
				active = append(active, r)
			}
			if len(active) > 1 {
				c.err(l.ID, "stream_multiple_routes", "TCP listener %q has %d routes; a raw TCP stream has no visible match inputs, so exactly one route is allowed", l.Name, len(active))
			}
			if len(active) >= 1 {
				lp.StreamRoute = active[0]
			}
		case KindStreamTLSFront:
			buildFront(c, lp, routes, ix, alloc)
		}
		p.Listeners = append(p.Listeners, lp)
	}
	return p, c.issues
}

// ─── listeners ─────────────────────────────────────────────────────────────

func validateListeners(c *checker, m *Model, caps Caps, o BuildOptions) {
	type bind struct {
		addr   netip.Addr
		module string
		l      *Listener
	}
	byPort := map[int][]bind{}
	reserved := map[int]bool{}
	for _, p := range o.ReservedPorts {
		reserved[p] = true
	}
	apiPort := 0
	if _, ps, err := splitHostPort(o.APIListen); err == nil {
		apiPort = ps
	}
	for i := range m.Listeners {
		l := &m.Listeners[i]
		if !nameRe.MatchString(l.Name) {
			c.err(l.ID, "listener_name", "listener name %q is invalid", l.Name)
		}
		switch l.Kind {
		case KindHTTP, KindHTTPS, KindStream, KindStreamTLSFront:
		default:
			c.err(l.ID, "listener_kind", "unknown listener kind %q", l.Kind)
			continue
		}
		if l.Port < 1 || l.Port > 65535 {
			c.err(l.ID, "listener_port", "port %d out of range", l.Port)
			continue
		}
		a, err := netip.ParseAddr(l.Address)
		if err != nil || a.Zone() != "" {
			c.err(l.ID, "listener_address", "address %q must be an IP literal (use 0.0.0.0 or :: for all)", l.Address)
			continue
		}
		if (l.Family == "ipv4") != a.Is4() {
			c.err(l.ID, "listener_family", "address %s does not match family %s", l.Address, l.Family)
		}
		if a == InternalAddr {
			c.err(l.ID, "listener_internal", "address %s is reserved for NGM internal hops", a)
		}
		if !l.Enabled {
			continue
		}
		if reserved[l.Port] && !a.IsLoopback() {
			c.err(l.ID, "listener_reserved_port", "port %d is used for SSH management access; binding it would risk lockout", l.Port)
		}
		if l.Port == apiPort && (a.IsLoopback() || a.IsUnspecified()) {
			c.err(l.ID, "listener_api_port", "port %d is the NGM API port", l.Port)
		}
		if (l.Kind == KindStream || l.Kind == KindStreamTLSFront) && !caps.StreamModule {
			c.err(l.ID, "cap_stream", "listener %q needs the Nginx stream module, which is not available", l.Name)
		}
		if l.Kind == KindStreamTLSFront && !caps.SSLPreread {
			c.err(l.ID, "cap_ssl_preread", "listener %q needs ssl_preread, which this Nginx build lacks", l.Name)
		}
		if l.Options.HTTP2 && (l.Kind != KindHTTPS || !caps.HTTP2) {
			c.err(l.ID, "cap_http2", "HTTP/2 needs an https listener and an Nginx build with http_v2")
		}
		mod := "http"
		if !isHTTPModule(l.Kind) {
			mod = "stream"
		}
		byPort[l.Port] = append(byPort[l.Port], bind{a, mod, l})
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, port := range ports {
		bs := byPort[port]
		for i := 0; i < len(bs); i++ {
			for j := i + 1; j < len(bs); j++ {
				a, b := bs[i], bs[j]
				if a.addr.Is4() != b.addr.Is4() {
					continue // Nginx binds IPv6 with ipv6only=on by default
				}
				overlap := a.addr == b.addr || a.addr.IsUnspecified() || b.addr.IsUnspecified()
				if overlap && a.module != b.module {
					c.err(b.l.ID, "listener_module_conflict", "%s:%d is used by both an HTTP and a stream listener (%q, %q); one public IP:port can have only one owner — use a stream_tls_front listener with TLS termination routes for shared 443",
						b.addr, port, a.l.Name, b.l.Name)
				}
				if overlap && a.module == "stream" && b.module == "stream" {
					c.err(b.l.ID, "listener_stream_overlap", "stream listeners %q and %q overlap on port %d", a.l.Name, b.l.Name, port)
				}
			}
		}
	}
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("no port")
	}
	p, err := strconv.Atoi(s[i+1:])
	return s[:i], p, err
}

// ─── backends ──────────────────────────────────────────────────────────────

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), // link-local incl. cloud metadata 169.254.169.254
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

func validateEndpoint(c *checker, e *Endpoint, o BuildOptions, mgmtOK bool) {
	if !nameRe.MatchString(e.Name) {
		c.err(e.ID, "endpoint_name", "endpoint name %q is invalid", e.Name)
	}
	if e.Port < 1 || e.Port > 65535 {
		c.err(e.ID, "endpoint_port", "endpoint %q port %d out of range", e.Name, e.Port)
	}
	switch e.Transport {
	case "http", "https", "tcp":
	default:
		c.err(e.ID, "endpoint_transport", "endpoint %q transport %q invalid", e.Name, e.Transport)
	}
	if a, err := netip.ParseAddr(e.Host); err == nil {
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a == InternalAddr {
			c.err(e.ID, "endpoint_address", "endpoint %q address %s is not a valid backend", e.Name, a)
		}
		for _, p := range metadataPrefixes {
			if p.Contains(a) {
				c.err(e.ID, "endpoint_link_local", "endpoint %q points to link-local/metadata address %s (SSRF risk); not allowed", e.Name, a)
			}
		}
		if _, apiPort, err := splitHostPort(o.APIListen); err == nil && a.IsLoopback() && e.Port == apiPort && !mgmtOK {
			c.err(e.ID, "endpoint_api", "endpoint %q would expose the NGM control API", e.Name)
		}
	} else if !ValidHostname(strings.ToLower(e.Host)) || e.Host != strings.ToLower(e.Host) {
		c.err(e.ID, "endpoint_host", "endpoint %q host %q must be an IP literal or a lowercase host name", e.Name, e.Host)
	} else if e.Host == "localhost" {
		c.err(e.ID, "endpoint_host", "use 127.0.0.1 instead of localhost")
	} else {
		c.warn(e.ID, "endpoint_dns", "endpoint %q uses a host name; Nginx resolves it at reload time only (no re-resolution until the next apply)", e.Name)
	}
	if e.TLSServerName != "" && !ValidHostname(e.TLSServerName) {
		c.err(e.ID, "endpoint_sni", "endpoint %q TLS server name %q invalid", e.Name, e.TLSServerName)
	}
	if e.Weight < 1 || e.Weight > 1000 {
		c.err(e.ID, "endpoint_weight", "endpoint %q weight must be 1–1000", e.Name)
	}
	for _, t := range []int{e.ConnectTimeoutMS, e.ReadTimeoutMS, e.WriteTimeoutMS} {
		if t < 100 || t > 3_600_000 {
			c.err(e.ID, "endpoint_timeout", "endpoint %q timeouts must be 100 ms – 1 h", e.Name)
			break
		}
	}
	if e.Transport == "https" && !e.TLSVerify {
		c.warn(e.ID, "endpoint_tls_noverify", "endpoint %q does not verify the backend TLS certificate", e.Name)
	}
}

func validatePool(c *checker, p *Pool, ix *Index) {
	if !nameRe.MatchString(p.Name) {
		c.err(p.ID, "pool_name", "pool name %q is invalid", p.Name)
	}
	switch p.Strategy {
	case "round_robin", "least_conn", "hash", "failover":
	default:
		c.err(p.ID, "pool_strategy", "pool %q strategy %q invalid", p.Name, p.Strategy)
	}
	if len(p.Members) == 0 {
		c.err(p.ID, "pool_empty", "pool %q has no members", p.Name)
		return
	}
	transport, primaries, backups := "", 0, 0
	for _, m := range p.Members {
		e, ok := ix.Endpoint[m.EndpointID]
		if !ok {
			c.err(p.ID, "pool_member_missing", "pool %q references a missing endpoint", p.Name)
			continue
		}
		if transport == "" {
			transport = e.Transport
		} else if transport != e.Transport {
			c.err(p.ID, "pool_mixed_transport", "pool %q mixes %s and %s endpoints", p.Name, transport, e.Transport)
		}
		if m.Weight < 1 || m.Weight > 1000 {
			c.err(p.ID, "pool_member_weight", "pool %q member weight must be 1–1000", p.Name)
		}
		if e.Disabled {
			continue
		}
		if m.Backup {
			backups++
		} else {
			primaries++
		}
	}
	if primaries == 0 {
		c.err(p.ID, "pool_no_primary", "pool %q has no enabled primary member", p.Name)
	}
	if p.Strategy == "failover" && backups == 0 {
		c.err(p.ID, "pool_failover_backup", "failover pool %q needs at least one backup member", p.Name)
	}
	if p.Strategy == "hash" && backups > 0 {
		c.err(p.ID, "pool_hash_backup", "Nginx does not support backup servers with hash balancing (pool %q)", p.Name)
	}
}

// destTransport returns the transport of a route's destination or "".
func destTransport(r *Route, ix *Index) string {
	switch r.DestKind {
	case DestEndpoint:
		if e, ok := ix.Endpoint[r.DestID]; ok {
			return e.Transport
		}
	case DestPool:
		if p, ok := ix.Pool[r.DestID]; ok && len(p.Members) > 0 {
			if e, ok := ix.Endpoint[p.Members[0].EndpointID]; ok {
				return e.Transport
			}
		}
	}
	return ""
}

// ─── routes ────────────────────────────────────────────────────────────────

var protoForKind = map[string][]string{
	KindHTTP:           {ProtoHTTP},
	KindHTTPS:          {ProtoHTTP},
	KindStream:         {ProtoTCP},
	KindStreamTLSFront: {ProtoTLSPassthrough, ProtoTLSTerminate},
}

var fieldsForProto = map[string]map[string]bool{
	ProtoHTTP:           {FieldHost: true, FieldPathPrefix: true, FieldPathExact: true},
	ProtoTCP:            {},
	ProtoTLSPassthrough: {FieldSNI: true, FieldALPN: true},
	ProtoTLSTerminate:   {FieldSNI: true, FieldALPN: true, FieldPathPrefix: true, FieldPathExact: true},
}

func validateRouteCommon(c *checker, r *Route, l *Listener, ix *Index, o BuildOptions) {
	if !contains(protoForKind[l.Kind], r.Protocol) {
		c.err(r.ID, "route_protocol", "route %q protocol %s is not valid on a %s listener", r.Name, r.Protocol, l.Kind)
		return
	}
	for _, m := range r.Matches {
		if !fieldsForProto[r.Protocol][m.Field] {
			reason := ""
			if m.Field == FieldHost || m.Field == FieldPathPrefix || m.Field == FieldPathExact {
				reason = " (HTTP Host/path are not visible inside un-terminated TLS or raw TCP)"
			}
			c.err(r.ID, "route_match_field", "route %q cannot match on %s for protocol %s%s", r.Name, m.Field, r.Protocol, reason)
			continue
		}
		switch m.Field {
		case FieldHost, FieldSNI:
			if _, err := ParseHostPattern(m.Operator, m.Value); err != nil {
				c.err(r.ID, "route_match_value", "route %q: %v", r.Name, err)
			}
		case FieldPathPrefix, FieldPathExact:
			if m.Operator != OpExact && m.Operator != OpPrefix {
				c.err(r.ID, "route_match_op", "route %q: path operator must be exact or prefix", r.Name)
			}
			if !pathRe.MatchString(m.Value) || strings.Contains(m.Value, "..") || strings.Contains(m.Value, "//") {
				c.err(r.ID, "route_match_value", "route %q: path %q is invalid", r.Name, m.Value)
			}
			if l.Kind == KindHTTP && l.Port == 80 && strings.HasPrefix(m.Value+"/", AcmePrefix) {
				c.err(r.ID, "route_reserved_path", "route %q: %s is reserved on port 80 for ACME HTTP-01 challenges", r.Name, AcmePrefix)
			}
		case FieldALPN:
			if m.Operator != OpExact || !alpnRe.MatchString(m.Value) {
				c.err(r.ID, "route_match_value", "route %q: ALPN %q is invalid", r.Name, m.Value)
			}
		}
	}
	// Destination.
	switch r.DestKind {
	case DestPool:
		if _, ok := ix.Pool[r.DestID]; !ok {
			c.err(r.ID, "route_dest_missing", "route %q references a missing pool", r.Name)
		}
	case DestEndpoint:
		if e, ok := ix.Endpoint[r.DestID]; !ok {
			c.err(r.ID, "route_dest_missing", "route %q references a missing endpoint", r.Name)
		} else if e.Disabled {
			c.err(r.ID, "route_dest_disabled", "route %q targets disabled endpoint %q", r.Name, e.Name)
		}
	case DestRedirect:
		if r.Protocol != ProtoHTTP && r.Protocol != ProtoTLSTerminate {
			c.err(r.ID, "route_redirect_proto", "redirects are HTTP-only")
		}
		u, err := url.Parse(r.Options.RedirectURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(r.Options.RedirectURL, " \"'{};\\$\t\r\n") {
			c.err(r.ID, "route_redirect_url", "route %q: redirect URL must be an absolute http(s) URL without spaces, quotes, braces, ';' or '$'", r.Name)
		}
		switch r.Options.RedirectCode {
		case 0, 301, 302, 307, 308:
		default:
			c.err(r.ID, "route_redirect_code", "route %q: redirect code must be 301, 302, 307 or 308", r.Name)
		}
	case DestReject:
	case DestWebsite:
		w, ok := ix.Website[r.DestID]
		switch {
		case !ok:
			c.err(r.ID, "route_dest_missing", "route %q references a missing website", r.Name)
		case !w.Published:
			c.err(r.ID, "route_website_unpublished", "route %q: website %q has no published version yet; publish it first", r.Name, w.Name)
		}
		if r.Protocol != ProtoHTTP && r.Protocol != ProtoTLSTerminate {
			c.err(r.ID, "route_website_proto", "websites are served over HTTP or terminated TLS only")
		}
		for _, m := range r.Matches {
			if m.Field == FieldPathExact || m.Field == FieldPathPrefix && !strings.HasSuffix(m.Value, "/") {
				c.err(r.ID, "route_website_path", "route %q: a website is mounted on a path prefix ending in / (e.g. /docs/)", r.Name)
			}
		}
	default:
		c.err(r.ID, "route_dest_kind", "route %q destination kind %q invalid", r.Name, r.DestKind)
	}
	t := destTransport(r, ix)
	if t != "" {
		switch r.Protocol {
		case ProtoHTTP, ProtoTLSTerminate:
			if t == "tcp" {
				c.err(r.ID, "route_dest_transport", "route %q is HTTP but its backend is TCP", r.Name)
			}
		case ProtoTCP, ProtoTLSPassthrough:
			if t != "tcp" {
				c.err(r.ID, "route_dest_transport", "route %q forwards raw bytes; its backend transport must be tcp", r.Name)
			}
		}
	}
	if r.Options.WebSocket && r.Protocol != ProtoHTTP && r.Protocol != ProtoTLSTerminate {
		c.err(r.ID, "route_ws_proto", "WebSocket applies to HTTP routes only (TCP/passthrough already carry it transparently)")
	}
	for _, v := range []int{r.Options.ConnectTimeoutMS, r.Options.ReadTimeoutMS, r.Options.SendTimeoutMS, r.Options.StreamTimeoutMS} {
		if v != 0 && (v < 100 || v > 86_400_000) {
			c.err(r.ID, "route_timeout", "route %q: timeouts must be 100 ms – 24 h", r.Name)
			break
		}
	}
	if r.Options.ClientMaxBodyMB < 0 || r.Options.ClientMaxBodyMB > 10240 {
		c.err(r.ID, "route_body", "route %q: client body limit must be 0–10240 MB", r.Name)
	}
	if r.Fallback && (l.Kind == KindHTTP || l.Kind == KindHTTPS) {
		c.warn(r.ID, "route_fallback_http", "on HTTP listeners, routes without a host match form the default server; is_fallback is ignored")
	}
	needsCert := l.Kind == KindHTTPS || r.Protocol == ProtoTLSTerminate
	if needsCert {
		cert, ok := ix.Cert[r.CertificateID]
		switch {
		case r.CertificateID == "" && !(l.Kind == KindHTTPS && len(hosts(r, FieldHost)) == 0):
			c.err(r.ID, "route_cert_missing", "route %q terminates TLS and needs a certificate", r.Name)
		case r.CertificateID != "" && !ok:
			c.err(r.ID, "route_cert_missing", "route %q references a missing certificate", r.Name)
		case ok && !cert.HasKey:
			c.err(r.ID, "route_cert_key", "certificate %q has no private key", cert.Name)
		case ok && !cert.NotAfter.IsZero() && !o.Now.Before(cert.NotAfter):
			c.err(r.ID, "route_cert_expired", "certificate %q expired on %s", cert.Name, cert.NotAfter.Format("2006-01-02"))
		case ok && !cert.NotAfter.IsZero() && cert.NotAfter.Sub(o.Now) < 14*24*time.Hour:
			c.warn(r.ID, "route_cert_expiring", "certificate %q expires on %s", cert.Name, cert.NotAfter.Format("2006-01-02"))
		}
		if ok {
			field := FieldHost
			if r.Protocol == ProtoTLSTerminate {
				field = FieldSNI
			}
			for _, h := range hosts(r, field) {
				if !CertCovers(cert.SANs, h) {
					c.err(r.ID, "route_cert_san", "certificate %q does not cover %s", cert.Name, h)
				} else if h.Wildcard {
					c.warn(r.ID, "route_cert_wildcard_depth", "%s matches multiple labels in routing, but a TLS wildcard certificate covers only one label", h)
				}
			}
		}
	} else if r.CertificateID != "" {
		c.warn(r.ID, "route_cert_unused", "route %q has a certificate but does not terminate TLS", r.Name)
	}
}

// hosts returns the parsed host patterns of a route for a field (invalid ones skipped).
func hosts(r *Route, field string) []HostPattern {
	var out []HostPattern
	for _, m := range r.Matches {
		if m.Field == field {
			if h, err := ParseHostPattern(m.Operator, m.Value); err == nil {
				out = append(out, h)
			}
		}
	}
	return out
}

func paths(r *Route) []Location {
	var out []Location
	for _, m := range r.Matches {
		switch m.Field {
		case FieldPathExact:
			out = append(out, Location{Exact: true, Path: m.Value, RouteID: r.ID})
		case FieldPathPrefix:
			out = append(out, Location{Exact: m.Operator == OpExact, Path: m.Value, RouteID: r.ID})
		}
	}
	if len(out) == 0 {
		out = []Location{{Path: "/", RouteID: r.ID}}
	}
	return out
}

func alpns(r *Route) []string {
	var out []string
	for _, m := range r.Matches {
		if m.Field == FieldALPN {
			out = append(out, m.Value)
		}
	}
	return out
}

// CertCovers reports whether SANs cover the host pattern under TLS rules
// (a SAN wildcard covers exactly one left-most label).
func CertCovers(sans []string, h HostPattern) bool {
	for _, s := range sans {
		s = strings.ToLower(s)
		if h.Wildcard {
			if s == "*."+h.Name {
				return true
			}
			continue
		}
		if s == h.Name {
			return true
		}
		if suf, ok := strings.CutPrefix(s, "*."); ok {
			if i := strings.IndexByte(h.Name, '.'); i > 0 && h.Name[i+1:] == suf {
				return true
			}
		}
	}
	return false
}

// buildVhosts groups HTTP routes into server blocks and locations.
func buildVhosts(c *checker, l *Listener, routes []*Route, ix *Index, tls bool) []Vhost {
	type key struct {
		name string
		wild bool
	}
	vh := map[key]*Vhost{}
	var order []key
	var deflt *Vhost
	var allNames []HostPattern
	certOf := map[key]string{}
	addLoc := func(v *Vhost, r *Route, label string) {
		for _, loc := range paths(r) {
			for _, ex := range v.Locations {
				if ex.Exact == loc.Exact && ex.Path == loc.Path {
					other := ix.routeName(ex.RouteID)
					c.err(r.ID, "route_conflict", "routes %q and %q both claim %s %s on listener %q", other, r.Name, label, describeLoc(loc), l.Name)
				}
			}
			v.Locations = append(v.Locations, loc)
		}
	}
	for _, r := range routes {
		if r.Protocol != ProtoHTTP {
			continue
		}
		hs := hosts(r, FieldHost)
		if len(hs) == 0 {
			if deflt == nil {
				deflt = &Vhost{Default: true}
			}
			if tls && r.CertificateID != "" {
				deflt.CertID = r.CertificateID
			}
			addLoc(deflt, r, "the default server")
			continue
		}
		for _, h := range hs {
			k := key{h.Name, h.Wildcard}
			v, ok := vh[k]
			if !ok {
				for _, n := range allNames {
					if n.Overlaps(h) && n != h {
						c.err(r.ID, "route_wildcard_overlap", "wildcard %s overlaps %s on listener %q; overlapping wildcards make precedence ambiguous", h, n, l.Name)
					}
				}
				allNames = append(allNames, h)
				v = &Vhost{Names: []HostPattern{h}}
				vh[k] = v
				order = append(order, k)
			}
			if tls {
				if prev, seen := certOf[k]; seen && prev != r.CertificateID {
					c.err(r.ID, "route_cert_inconsistent", "host %s on listener %q uses different certificates across routes", h, l.Name)
				}
				certOf[k] = r.CertificateID
				v.CertID = r.CertificateID
			}
			addLoc(v, r, h.String())
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].wild != order[j].wild {
			return !order[i].wild
		}
		return order[i].name < order[j].name
	})
	out := make([]Vhost, 0, len(order)+1)
	for _, k := range order {
		out = append(out, *vh[k])
	}
	if deflt != nil {
		out = append(out, *deflt)
	}
	for i := range out {
		sort.Slice(out[i].Locations, func(a, b int) bool {
			x, y := out[i].Locations[a], out[i].Locations[b]
			if x.Exact != y.Exact {
				return x.Exact
			}
			return x.Path < y.Path
		})
	}
	return out
}

func describeLoc(l Location) string {
	if l.Exact {
		return "path = " + l.Path
	}
	return "path prefix " + l.Path
}

func (ix *Index) routeName(id string) string {
	for _, rs := range ix.ByListen {
		for _, r := range rs {
			if r.ID == id {
				return r.Name
			}
		}
	}
	return id
}

// buildFront resolves ssl_preread dispatch for a stream_tls_front listener.
func buildFront(c *checker, lp *ListenerPlan, routes []*Route, ix *Index, alloc func() int) {
	l := lp.L
	seen := map[string]string{} // sni|alpn → route name
	termHosts := map[string]bool{}
	var term []*Route
	var allSNI []HostPattern
	for _, r := range routes {
		if r.Fallback {
			if lp.Fallback != nil {
				c.err(r.ID, "route_fallback_dup", "listener %q has more than one fallback route (%q, %q)", l.Name, lp.Fallback.Name, r.Name)
				continue
			}
			if len(hosts(r, FieldSNI)) > 0 || len(alpns(r)) > 0 {
				c.err(r.ID, "route_fallback_match", "fallback route %q must not have SNI/ALPN matches; it handles connections no rule matches (including absent SNI and ECH)", r.Name)
			}
			if r.Protocol == ProtoTLSTerminate {
				c.err(r.ID, "route_fallback_terminate", "fallback route %q must be passthrough or reject: without a known SNI, NGM cannot choose a certificate", r.Name)
			}
			lp.Fallback = r
			continue
		}
		sn := hosts(r, FieldSNI)
		if len(sn) == 0 {
			c.err(r.ID, "route_sni_required", "route %q on a TLS front needs at least one SNI match (or mark it as the fallback)", r.Name)
			continue
		}
		al := alpns(r)
		if r.Protocol == ProtoTLSTerminate && len(al) > 0 {
			c.err(r.ID, "route_terminate_alpn", "route %q: ALPN conditions are only supported for passthrough routes", r.Name)
		}
		if len(al) == 0 {
			al = []string{""}
		}
		for _, h := range sn {
			for _, n := range allSNI {
				if n.Overlaps(h) && n != h {
					c.err(r.ID, "route_wildcard_overlap", "SNI wildcard %s overlaps %s on listener %q", h, n, l.Name)
				}
			}
			allSNI = append(allSNI, h)
			if r.Protocol == ProtoTLSTerminate {
				if prev, dup := seen[h.String()+"|"]; dup && !termHosts[h.String()] {
					c.err(r.ID, "route_conflict", "SNI %s is claimed by passthrough route %q and terminate route %q", h, prev, r.Name)
				}
				termHosts[h.String()] = true
				seen[h.String()+"|"] = r.Name
				continue
			}
			for _, a := range al {
				k := h.String() + "|" + a
				if prev, dup := seen[k]; dup {
					c.err(r.ID, "route_conflict", "routes %q and %q both claim SNI %s%s on listener %q", prev, r.Name, h, alpnSuffix(a), l.Name)
					continue
				}
				if termHosts[h.String()] && a == "" {
					c.err(r.ID, "route_conflict", "SNI %s is claimed by a terminate route and passthrough route %q", h, r.Name)
				}
				seen[k] = r.Name
				target := "ngm_r_" + r.ID
				if !r.Options.BackendProxyProto {
					if _, ok := lp.StripperPorts[r.ID]; !ok {
						lp.StripperPorts[r.ID] = alloc()
					}
					target = "ngm_strip_" + r.ID
				}
				lp.Rules = append(lp.Rules, FrontRule{SNI: h, ALPN: a, RouteID: r.ID, Target: target, Kind: ProtoTLSPassthrough})
			}
		}
		if r.Protocol == ProtoTLSTerminate {
			term = append(term, r)
		}
	}
	if len(term) > 0 {
		lp.TermPort = alloc()
		lp.TermVhosts = buildTermVhosts(c, l, term, ix)
		for _, v := range lp.TermVhosts {
			for _, n := range v.Names {
				lp.Rules = append(lp.Rules, FrontRule{SNI: n, Target: "ngm_term_" + l.ID, Kind: ProtoTLSTerminate})
			}
		}
	}
	switch {
	case lp.Fallback == nil || lp.Fallback.DestKind == DestReject:
		lp.RejectPort = alloc()
	case lp.Fallback.Protocol == ProtoTLSPassthrough && !lp.Fallback.Options.BackendProxyProto:
		lp.StripperPorts[lp.Fallback.ID] = alloc()
	}
	SortFrontRules(lp.Rules)
}

func alpnSuffix(a string) string {
	if a == "" {
		return ""
	}
	return " (ALPN " + a + ")"
}

// buildTermVhosts converts terminate routes into HTTP vhosts keyed by SNI.
func buildTermVhosts(c *checker, l *Listener, term []*Route, ix *Index) []Vhost {
	conv := make([]*Route, 0, len(term))
	for _, r := range term {
		cp := *r
		cp.Protocol = ProtoHTTP
		cp.Matches = nil
		for _, m := range r.Matches {
			switch m.Field {
			case FieldSNI:
				cp.Matches = append(cp.Matches, Match{Field: FieldHost, Operator: m.Operator, Value: m.Value})
			case FieldPathPrefix, FieldPathExact:
				cp.Matches = append(cp.Matches, m)
			}
		}
		conv = append(conv, &cp)
	}
	return buildVhosts(c, l, conv, ix, true)
}

// managementOnly reports whether every use of e is a TLS route whose host or
// SNI matches exactly the management host (and nothing else), and e is not a
// pool member. Only then may e point at the control API.
func managementOnly(m *Model, e *Endpoint, host, mgmtPath string) bool {
	if host == "" {
		return false
	}
	for _, p := range m.Pools {
		for _, mb := range p.Members {
			if mb.EndpointID == e.ID {
				return false
			}
		}
	}
	used := false
	for _, r := range m.Routes {
		if r.DestKind != "endpoint" || r.DestID != e.ID {
			continue
		}
		used = true
		tls := r.Protocol == "tls_terminate_http"
		for _, l := range m.Listeners {
			if l.ID == r.ListenerID && l.Kind == "https" {
				tls = true
			}
		}
		if !tls || len(r.Matches) == 0 {
			return false
		}
		for _, mt := range r.Matches {
			switch {
			case (mt.Field == "host" || mt.Field == "sni") && mt.Operator == "exact" && strings.EqualFold(mt.Value, host):
				// management host — allowed
			case mt.Field == "path_prefix" && mgmtPath != "" && mt.Value == mgmtPath+"/":
				// the panel's secret base path — allowed
			default:
				return false
			}
		}
	}
	return used
}

// OriginHost returns the lowercase host of an origin such as https://ngm.example.com:8443.
func OriginHost(origin string) string {
	o := strings.TrimPrefix(strings.ToLower(origin), "https://")
	if h, _, err := net.SplitHostPort(o); err == nil {
		return h
	}
	return strings.TrimSuffix(o, "/")
}
