package gateway

import (
	"fmt"
	"net/netip"
	"strings"
)

// SimInput is a hypothetical connection/request.
type SimInput struct {
	ListenerID string   `json:"listener_id,omitempty"`
	Address    string   `json:"address,omitempty"` // destination IP the client connects to
	Port       int      `json:"port,omitempty"`
	SNI        string   `json:"sni,omitempty"`  // empty = no SNI (or hidden by ECH)
	ALPN       []string `json:"alpn,omitempty"` // client-offered protocols
	Host       string   `json:"host,omitempty"` // HTTP Host header (defaults to SNI after termination)
	// FallbackSite is set by the caller when a fallback website is configured (ADR-036).
	FallbackSite bool   `json:"-"`
	Path         string `json:"path,omitempty"`
	ECH          bool   `json:"ech,omitempty"` // client uses Encrypted ClientHello
}

// SimStep is one decision in the trace.
type SimStep struct {
	Stage    string `json:"stage"` // listener | stream_rule | fallback | tls | vhost | location | destination
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// SimResult is the outcome.
type SimResult struct {
	Matched     bool      `json:"matched"`
	ListenerID  string    `json:"listener_id,omitempty"`
	RouteID     string    `json:"route_id,omitempty"`
	RouteName   string    `json:"route_name,omitempty"`
	Outcome     string    `json:"outcome"` // proxy_http | proxy_tcp | passthrough | redirect | reject | closed | misdirected | no_listener
	Destination string    `json:"destination,omitempty"`
	Fallback    bool      `json:"fallback"`
	Trace       []SimStep `json:"trace"`
	Uncertainty []string  `json:"uncertainty"`
}

// Simulate evaluates input against a plan (no I/O). It models the compiled
// configuration only; it cannot prove runtime packet behaviour.
func Simulate(p *Plan, in SimInput) SimResult {
	res := SimResult{Uncertainty: []string{"Simulation reflects the compiled configuration model, not live traffic, backend health or kernel behaviour."}}
	step := func(stage, dec, reason string, a ...any) {
		res.Trace = append(res.Trace, SimStep{stage, dec, fmt.Sprintf(reason, a...)})
	}
	lp := pickListener(p, in)
	if lp == nil {
		res.Outcome = "no_listener"
		step("listener", "none", "no enabled listener binds %s:%d", in.Address, in.Port)
		return res
	}
	l := lp.L
	res.ListenerID = l.ID
	step("listener", l.Name, "%s listener on %s (kind %s)", strings.ToUpper(l.Kind), hostPort(l.Address, l.Port), l.Kind)
	if in.ECH {
		res.Uncertainty = append(res.Uncertainty, "With ECH the outer SNI is a public name chosen by the client; routing uses only what is visible.")
	}
	switch l.Kind {
	case KindStream:
		if lp.StreamRoute == nil {
			res.Outcome = "closed"
			step("destination", "none", "listener has no route; Nginx does not bind it")
			return res
		}
		finishRoute(p, &res, lp.StreamRoute, step, "raw TCP: no SNI/Host/path is visible; the single route applies")
		return res
	case KindHTTP, KindHTTPS:
		host := in.Host
		if host == "" {
			host = in.SNI
		}
		if l.Kind == KindHTTPS && in.SNI == "" {
			res.Uncertainty = append(res.Uncertainty, "No SNI: the TLS default server answers the handshake.")
		}
		if l.Kind == KindHTTP && l.Port == 80 && strings.HasPrefix(in.Path, AcmePrefix) {
			res.Outcome = "acme_challenge"
			step("location", AcmePrefix, "every NGM server on plain-HTTP port 80 answers ACME HTTP-01 challenges here (files exist only during validation; otherwise 404)")
			break
		}
		simHTTP(p, &res, lp.Vhosts, host, in, l.Kind == KindHTTPS, step)
		return res
	case KindStreamTLSFront:
		if in.SNI == "" {
			step("stream_rule", "none", "no SNI in ClientHello (absent or hidden by ECH): SNI rules cannot match")
		}
		rule, ok := MatchFront(lp.Rules, in.SNI, in.ALPN)
		if !ok {
			if in.SNI != "" {
				step("stream_rule", "none", "SNI %q (ALPN %v) matches no rule", in.SNI, in.ALPN)
			}
			if lp.Fallback != nil && lp.Fallback.DestKind != DestReject {
				res.Fallback = true
				step("fallback", lp.Fallback.Name, "explicit fallback route handles unmatched connections")
				finishRoute(p, &res, lp.Fallback, step, "TLS bytes forwarded untouched")
				return res
			}
			res.Fallback = true
			if in.FallbackSite {
				res.Outcome = "fallback_site"
				step("fallback", "website", "no fallback route: TLS is terminated with the fallback certificate and the fallback website is served")
				return res
			}
			res.Outcome = "closed"
			step("fallback", "reject", "no fallback route: the connection is closed")
			return res
		}
		reason := fmt.Sprintf("SNI %q matched %s", in.SNI, rule.SNI)
		if rule.ALPN != "" {
			reason += fmt.Sprintf(" with ALPN %s", rule.ALPN)
		}
		if rule.Kind == ProtoTLSPassthrough {
			step("stream_rule", "passthrough", "%s; TLS is not decrypted, so HTTP Host/path are not visible", reason)
			finishRoute(p, &res, p.RouteByID[rule.RouteID], step, "backend terminates TLS")
			return res
		}
		step("stream_rule", "terminate", "%s; forwarded to NGM's internal TLS-termination hop", reason)
		step("tls", "terminated", "certificate selected by SNI %q", in.SNI)
		host := in.Host
		if host == "" {
			host = in.SNI
		}
		if !strings.EqualFold(stripPort(host), in.SNI) {
			res.Outcome = "misdirected"
			step("vhost", "421", "Host %q differs from SNI %q: NGM answers 421 Misdirected Request to prevent cross-host dispatch", host, in.SNI)
			return res
		}
		simHTTP(p, &res, lp.TermVhosts, host, in, true, step)
		return res
	}
	return res
}

func stripPort(h string) string {
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func pickListener(p *Plan, in SimInput) *ListenerPlan {
	if in.ListenerID != "" {
		for _, lp := range p.Listeners {
			if lp.L.ID == in.ListenerID {
				return lp
			}
		}
		return nil
	}
	a, err := netip.ParseAddr(in.Address)
	if err != nil {
		return nil
	}
	var wildcard *ListenerPlan
	for _, lp := range p.Listeners {
		if lp.L.Port != in.Port {
			continue
		}
		la, _ := netip.ParseAddr(lp.L.Address)
		if la == a {
			return lp // most specific address wins, as in the kernel/Nginx
		}
		if la.IsUnspecified() && la.Is4() == a.Is4() {
			wildcard = lp
		}
	}
	return wildcard
}

func simHTTP(p *Plan, res *SimResult, vhosts []Vhost, host string, in SimInput, tls bool, step func(string, string, string, ...any)) {
	names := make([][]HostPattern, len(vhosts))
	def := -1
	for i, v := range vhosts {
		names[i] = v.Names
		if v.Default {
			def = i
		}
	}
	i := SelectVhost(names, host)
	switch {
	case i >= 0:
		step("vhost", serverNames(vhosts[i]), "Host %q selected this server (exact names before wildcards)", host)
		if tls && in.SNI != "" && !strings.EqualFold(stripPort(host), in.SNI) {
			res.Outcome = "misdirected"
			step("vhost", "421", "Host %q differs from SNI %q: 421 Misdirected Request", host, in.SNI)
			return
		}
	case def >= 0:
		i = def
		res.Fallback = true
		step("vhost", "default", "Host %q matched no server name; default server applies", host)
	case tls:
		res.Outcome = "misdirected"
		res.Fallback = true
		step("vhost", "421", "Host %q matched no server name on this TLS listener: 421 Misdirected Request", host)
		return
	default:
		res.Fallback = true
		if in.FallbackSite {
			res.Outcome = "fallback_site"
			step("vhost", "default", "Host %q matched no server name: NGM's default server serves the fallback website", host)
			return
		}
		res.Outcome = "closed"
		step("vhost", "default", "Host %q matched no server name and there is no default route: NGM's default server closes the connection (444)", host)
		return
	}
	path := in.Path
	if path == "" {
		path = "/"
	}
	loc, ok := SelectLocation(vhosts[i].Locations, path)
	if !ok {
		res.Outcome = "closed"
		step("location", "none", "path %q matches no location; Nginx answers 404", path)
		return
	}
	kind := "prefix"
	if loc.Exact {
		kind = "exact"
	}
	step("location", loc.Path, "%s location (exact match first, else longest prefix)", kind)
	finishRoute(p, res, p.RouteByID[loc.RouteID], step, "")
}

func finishRoute(p *Plan, res *SimResult, r *Route, step func(string, string, string, ...any), note string) {
	res.Matched = true
	res.RouteID, res.RouteName = r.ID, r.Name
	switch r.DestKind {
	case DestReject:
		res.Outcome = "reject"
		step("destination", "reject", "route %q rejects", r.Name)
		return
	case DestWebsite:
		res.Outcome = "website"
		res.Destination = describeDest(p, r)
		step("destination", "website", "route %q serves the published version of %s (static files, no backend)", r.Name, res.Destination)
		return
	case DestRedirect:
		res.Outcome = "redirect"
		res.Destination = r.Options.RedirectURL
		step("destination", "redirect", "route %q redirects to %s", r.Name, r.Options.RedirectURL)
		return
	}
	res.Destination = describeDest(p, r)
	switch r.Protocol {
	case ProtoHTTP, ProtoTLSTerminate:
		res.Outcome = "proxy_http"
		if r.Options.WebSocket {
			note = strings.TrimSpace(note + " WebSocket upgrade enabled")
		}
	case ProtoTCP:
		res.Outcome = "proxy_tcp"
	case ProtoTLSPassthrough:
		res.Outcome = "passthrough"
	}
	step("destination", res.Destination, "route %q → %s. %s", r.Name, res.Destination, note)
	res.Uncertainty = append(res.Uncertainty, "Failover applies to new connections only; established sessions are not migrated.")
}

func describeDest(p *Plan, r *Route) string {
	switch r.DestKind {
	case DestEndpoint:
		if e := p.Ix.Endpoint[r.DestID]; e != nil {
			return fmt.Sprintf("endpoint %s (%s %s)", e.Name, e.Transport, hostPort(e.Host, e.Port))
		}
	case DestPool:
		if pl := p.Ix.Pool[r.DestID]; pl != nil {
			return fmt.Sprintf("pool %s (%s, %d members)", pl.Name, pl.Strategy, len(pl.Members))
		}
	case DestWebsite:
		if w := p.Ix.Website[r.DestID]; w != nil {
			return "website " + w.Name
		}
	}
	return r.DestKind
}
