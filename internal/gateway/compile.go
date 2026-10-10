package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Fixed paths of the NGM-owned Nginx tree (see helper layout).
const (
	NginxRoot = "/etc/nginx/ngm"
	GenDir    = NginxRoot + "/gen"
	KeyDir    = NginxRoot + "/keys"
	// PublicRoot is the NGM-owned tree Nginx workers can read (the
	// generation/key tree is root-only). AcmeDir holds HTTP-01 responses.
	PublicRoot = "/var/www/ngm"
	AcmeDir    = PublicRoot + "/acme"
	AcmePrefix = "/.well-known/acme-challenge/"
	// LogDir receives NGM's structured Nginx logs (read by ngm log-indexer).
	LogDir     = "/var/log/ngm/nginx"
	CABundle   = "/etc/ssl/certs/ca-certificates.crt"
	ProbeHdr   = "X-NGM-Probe"
	GenHdr     = "X-NGM-Generation"
	FileHTTP   = "http/ngm.conf"
	FileStream = "stream/ngm.conf"
)

// CompileInput carries per-generation data.
type CompileInput struct {
	GenID         string
	ProbeToken    string            // secret; responses carry the generation header only for probes presenting it
	CertPEM       map[string]string // certificate id → PEM chain (public)
	DefaultCertID string            // used for TLS default servers when ssl_reject_handshake is unavailable
	// KeyFile maps certificate id → deployed key file id (one file per key
	// version); missing entries fall back to the certificate id (legacy).
	KeyFile map[string]string
	// AnonymizeIP truncates client addresses in logs (IPv4 /24, IPv6 /48).
	AnonymizeIP bool
	// Performance tuning (rendered by package perf from validated numbers):
	// PerfHTTP goes into the http context, PerfServer into every NGM http
	// server; StreamTimeoutMS/StreamConnectMS are the stream defaults.
	PerfHTTP        []string
	PerfServer      []string
	StreamTimeoutMS int
	StreamConnectMS int
	// Fallback website (ADR-036): when both are set, every request that
	// matches no route (unknown Host, IP-only access, unknown or missing SNI)
	// is answered by this published website over this certificate instead of
	// a closed connection or a TLS alert, so the server looks like an
	// ordinary site to crawlers and probes.
	FallbackSite   string
	FallbackCertID string
}

func (in CompileInput) fallback() bool { return in.FallbackSite != "" && in.FallbackCertID != "" }

// writeFallbackSite serves the fallback website in a server block.
func writeFallbackSite(x *w, in CompileInput) {
	x.f(1, "root %s;", SiteRoot(in.FallbackSite))
	x.f(1, "index index.html;")
	x.f(1, "charset utf-8;")
	x.f(1, "autoindex off;")
	x.f(1, "error_page 404 /404.html;")
	x.f(1, "location = /404.html { internal; }")
	x.f(1, "location / { try_files $uri $uri/ =404; }")
	x.f(1, "add_header X-Content-Type-Options nosniff always;")
	x.f(1, "add_header Referrer-Policy strict-origin-when-cross-origin always;")
	x.f(1, "add_header X-Frame-Options SAMEORIGIN always;")
}

func (in CompileInput) streamTimeout() int {
	if in.StreamTimeoutMS > 0 {
		return in.StreamTimeoutMS
	}
	return 600000
}

func (in CompileInput) streamConnect() int {
	if in.StreamConnectMS > 0 {
		return in.StreamConnectMS
	}
	return 5000
}

// Log formats. Query strings are never logged ($uri, not $request_uri), and
// no header carrying credentials is part of any format.
const (
	httpLogFormat   = `'{"t":"$time_iso8601","c":"http","port":"$server_port","host":"$host","sni":"$ssl_server_name","route":"$ngm_route","m":"$request_method","p":"$uri","s":"$status","b":"$body_bytes_sent","rt":"$request_time","up":"$upstream_addr","us":"$upstream_status","urt":"$upstream_response_time","ip":"$ngm_client","tls":"$ssl_protocol"}'`
	streamLogFormat = `'{"t":"$time_iso8601","c":"stream","port":"$server_port","sni":"%s","up":"$upstream_addr","s":"$status","bi":"$bytes_received","bo":"$bytes_sent","d":"$session_time","ip":"$ngm_sclient"}'`
)

// writeClientMap defines the logged client address (optionally truncated).
func writeClientMap(x *w, name string, anonymize bool) {
	if !anonymize {
		x.f(0, "map $remote_addr %s { default $remote_addr; }", name)
		return
	}
	x.f(0, "map $remote_addr %s {", name)
	x.f(1, `"~^(?<a>\d+\.\d+\.\d+)\.\d+$" "$a.0";`)
	x.f(1, `"~^(?<b>[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F]*):" "$b::";`)
	x.f(1, "default \"-\";")
	x.f(0, "}")
}

// writeServerLogs sends a server's logs to NGM's files (server level, so
// non-NGM servers are never affected).
func writeServerLogs(x *w, stream bool) {
	if stream {
		x.f(1, "access_log %s/stream.jsonl ngm_stream;", LogDir)
	} else {
		x.f(1, "server_tokens off;") // no Nginx version in headers or error pages
		x.f(1, "set $ngm_route \"\";")
		x.f(1, "access_log %s/access.jsonl ngm_http;", LogDir)
	}
	x.f(1, "error_log %s/error.log warn;", LogDir)
}

func writePerf(x *w, in CompileInput) {
	for _, d := range in.PerfServer {
		x.f(1, "%s", d)
	}
}

// Probe describes a post-reload verification check.
type Probe struct {
	Kind     string `json:"kind"` // http | https
	Addr     string `json:"addr"` // host:port to connect to
	Host     string `json:"host"` // Host header / SNI
	CertID   string `json:"cert_id,omitempty"`
	Listener string `json:"listener"`
}

// Output is a compiled generation.
type Output struct {
	Files   map[string][]byte `json:"-"`
	Listens []string          `json:"listens"` // every addr:port Nginx must bind
	Probes  []Probe           `json:"probes"`
	Hash    string            `json:"hash"`
}

// ErrInvalid means the model has validation errors.
var ErrInvalid = errors.New("gateway model has validation errors")

func genDir(gen string) string { return GenDir + "/" + gen }

// CertPath / KeyPath are where a certificate's files are deployed.
func CertPath(gen, id string) string { return genDir(gen) + "/certs/" + id + ".crt" }
func KeyPath(id string) string       { return KeyDir + "/" + id + ".key" }

type w struct{ b strings.Builder }

func (x *w) f(indent int, format string, a ...any) {
	x.b.WriteString(strings.Repeat("    ", indent))
	fmt.Fprintf(&x.b, format, a...)
	x.b.WriteByte('\n')
}

func hostPort(addr string, port int) string {
	a, err := netip.ParseAddr(addr)
	if err == nil && a.Is6() {
		return "[" + a.String() + "]:" + strconv.Itoa(port)
	}
	return addr + ":" + strconv.Itoa(port)
}

func ms(v, def int) string {
	if v <= 0 {
		v = def
	}
	if v%1000 == 0 {
		return strconv.Itoa(v/1000) + "s"
	}
	return strconv.Itoa(v) + "ms"
}

func upName(prefix, id string) string { return prefix + strings.ToLower(id) }

// Compile renders Nginx configuration for a valid plan.
func Compile(p *Plan, issues []Issue, caps Caps, in CompileInput) (*Output, error) {
	if HasErrors(issues) {
		return nil, ErrInvalid
	}
	if in.GenID == "" || strings.ContainsAny(in.GenID, "/. \"';{}$") || strings.ContainsAny(in.ProbeToken, "\"';{}$ \\") {
		return nil, errors.New("invalid generation id or probe token")
	}
	if !caps.RejectHandshake && in.DefaultCertID == "" {
		for _, lp := range p.Listeners {
			if lp.L.Kind == KindHTTPS || lp.TermPort != 0 {
				return nil, errors.New("this Nginx lacks ssl_reject_handshake (< 1.19.4): a default TLS certificate is required for TLS default servers")
			}
		}
	}
	out := &Output{Files: map[string][]byte{}}
	ix := p.Ix
	httpUps := map[string]bool{}   // "pool:id"/"endpoint:id"
	streamUps := map[string]bool{} // same keys

	var hb, sb w
	header := fmt.Sprintf("# Generated by NGM — generation %s. DO NOT EDIT: this file is owned by NGM and replaced on every apply.", in.GenID)
	hb.f(0, "%s", header)
	sb.f(0, "%s", header)
	hb.f(0, "map $http_upgrade $ngm_connection_upgrade { default upgrade; '' close; }")
	hb.f(0, "map $http_%s $ngm_probe_generation { default \"\"; \"%s\" \"%s\"; }", strings.ToLower(strings.ReplaceAll(ProbeHdr, "-", "_")), in.ProbeToken, in.GenID)
	writeClientMap(&hb, "$ngm_client", in.AnonymizeIP)
	hb.f(0, "log_format ngm_http escape=json %s;", httpLogFormat)
	for _, d := range in.PerfHTTP {
		hb.f(0, "%s", d)
	}
	hb.f(0, "")
	if caps.StreamModule {
		writeClientMap(&sb, "$ngm_sclient", in.AnonymizeIP)
		sni := ""
		if caps.SSLPreread {
			sni = "$ssl_preread_server_name"
		}
		sb.f(0, "log_format ngm_stream escape=json %s;", fmt.Sprintf(streamLogFormat, sni))
		sb.f(0, "")
	}

	for _, lp := range p.Listeners {
		l := lp.L
		switch l.Kind {
		case KindHTTP, KindHTTPS:
			for _, v := range lp.Vhosts {
				writeVhost(&hb, p, caps, in, l, hostPort(l.Address, l.Port), l.Kind == KindHTTPS, false, v, httpUps)
				if !v.Default {
					out.Probes = append(out.Probes, vhostProbe(l, v, l.Kind == KindHTTPS))
				}
			}
			if !hasDefault(lp.Vhosts) {
				writeDefaultServer(&hb, caps, in, hostPort(l.Address, l.Port), l.Kind == KindHTTPS, false, l.Options.HTTP2, l.Kind == KindHTTP && l.Port == 80)
			}
			out.Listens = append(out.Listens, hostPort(l.Address, l.Port))
		case KindStream:
			if lp.StreamRoute == nil {
				continue
			}
			r := lp.StreamRoute
			sb.f(0, "# listener %q, route %q", l.Name, r.Name)
			sb.f(0, "server {")
			sb.f(1, "listen %s;", hostPort(l.Address, l.Port))
			writeServerLogs(&sb, true)
			if r.DestKind == DestReject {
				sb.f(1, "return \"\";")
			} else {
				sb.f(1, "proxy_pass %s;", streamUpstream(r, streamUps))
				sb.f(1, "proxy_connect_timeout %s;", ms(r.Options.ConnectTimeoutMS, destConnectTimeout(r, ix)))
				sb.f(1, "proxy_timeout %s;", ms(r.Options.StreamTimeoutMS, in.streamTimeout()))
			}
			sb.f(0, "}")
			sb.f(0, "")
			out.Listens = append(out.Listens, hostPort(l.Address, l.Port))
		case KindStreamTLSFront:
			writeFront(&sb, &hb, p, caps, in, lp, httpUps, streamUps, out)
		}
	}
	// Upstreams (sorted for determinism).
	writeUpstreams(&hb, ix, httpUps, false)
	writeUpstreams(&sb, ix, streamUps, true)

	out.Files[FileHTTP] = []byte(hb.b.String())
	out.Files[FileStream] = []byte(sb.b.String())
	certIDs := usedCerts(p)
	if in.DefaultCertID != "" && !caps.RejectHandshake {
		certIDs = append(certIDs, in.DefaultCertID)
	}
	if in.fallback() && !contains(certIDs, in.FallbackCertID) {
		certIDs = append(certIDs, in.FallbackCertID) // ADR-036: may be used by no route
	}
	for _, id := range certIDs {
		pem, ok := in.CertPEM[id]
		if !ok {
			return nil, fmt.Errorf("certificate %s material missing", id)
		}
		out.Files["certs/"+id+".crt"] = []byte(pem)
	}
	sort.Strings(out.Listens)
	h := sha256.New()
	names := make([]string, 0, len(out.Files))
	for n := range out.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n + "\x00"))
		h.Write(out.Files[n])
		h.Write([]byte{0})
	}
	out.Hash = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

func hasDefault(vs []Vhost) bool {
	for _, v := range vs {
		if v.Default {
			return true
		}
	}
	return false
}

// UsedCertIDs lists certificate ids the plan deploys (sorted, unique).
func UsedCertIDs(p *Plan) []string { return usedCerts(p) }

func usedCerts(p *Plan) []string {
	set := map[string]bool{}
	for _, lp := range p.Listeners {
		for _, v := range append(append([]Vhost(nil), lp.Vhosts...), lp.TermVhosts...) {
			if v.CertID != "" && (lp.L.Kind == KindHTTPS || lp.L.Kind == KindStreamTLSFront) {
				set[v.CertID] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func vhostProbe(l *Listener, v Vhost, tls bool) Probe {
	host := v.Names[0].Name
	if v.Names[0].Wildcard {
		host = "ngm-probe." + host
	}
	kind := "http"
	if tls {
		kind = "https"
	}
	return Probe{Kind: kind, Addr: probeAddr(l.Address, l.Port), Host: host, CertID: v.CertID, Listener: l.Name}
}

func probeAddr(addr string, port int) string {
	a, err := netip.ParseAddr(addr)
	if err == nil && a.IsUnspecified() {
		if a.Is4() {
			return "127.0.0.1:" + strconv.Itoa(port)
		}
		return "[::1]:" + strconv.Itoa(port)
	}
	return hostPort(addr, port)
}

func serverNames(v Vhost) string {
	var ns []string
	for _, n := range v.Names {
		ns = append(ns, n.String())
	}
	return strings.Join(ns, " ")
}

func writeTLS(x *w, in CompileInput, certID string) {
	kf := certID
	if f, ok := in.KeyFile[certID]; ok && f != "" {
		kf = f
	}
	x.f(1, "ssl_certificate %s;", CertPath(in.GenID, certID))
	x.f(1, "ssl_certificate_key %s;", KeyPath(kf))
	x.f(1, "ssl_protocols TLSv1.2 TLSv1.3;")
	x.f(1, "ssl_session_cache shared:ngm_ssl:10m;")
	x.f(1, "ssl_session_timeout 1h;")
}

func listenLine(bind string, tls, def, proxyProto, h2 bool, caps Caps) string {
	s := "listen " + bind
	if tls {
		s += " ssl"
		if h2 && !caps.HTTP2Directive {
			s += " http2"
		}
	}
	if proxyProto {
		s += " proxy_protocol"
	}
	if def {
		s += " default_server"
	}
	return s + ";"
}

func writeVhost(x *w, p *Plan, caps Caps, in CompileInput, l *Listener, bind string, tls, internal bool, v Vhost, ups map[string]bool) {
	name := "_"
	if !v.Default {
		name = serverNames(v)
	}
	x.f(0, "# listener %q%s", l.Name, map[bool]string{true: " (internal TLS termination hop)", false: ""}[internal])
	x.f(0, "server {")
	h2 := l.Options.HTTP2 && tls
	x.f(1, "%s", listenLine(bind, tls, v.Default, internal, h2, caps))
	if h2 && caps.HTTP2Directive {
		x.f(1, "http2 on;")
	}
	x.f(1, "server_name %s;", name)
	writeServerLogs(x, false)
	writePerf(x, in)
	if internal {
		// The hop is reachable only on loopback; the kernel picks a loopback
		// source address, so trust the whole loopback range for PROXY data.
		x.f(1, "set_real_ip_from 127.0.0.0/8;")
		x.f(1, "real_ip_header proxy_protocol;")
	}
	writeProbe(x, in)
	if tls {
		cert := v.CertID
		if cert == "" {
			cert = in.DefaultCertID
		}
		if cert != "" {
			writeTLS(x, in, cert)
		} else if caps.RejectHandshake {
			x.f(1, "ssl_reject_handshake on;")
		}
		if !v.Default {
			// Host must agree with SNI: prevents a client from using one
			// name's TLS session to reach another vhost (421 Misdirected Request).
			x.f(1, "if ($ssl_server_name != $host) { return 421; }")
		}
	}
	x.f(1, "add_header %s $ngm_probe_generation always;", GenHdr)
	if !tls && !internal && l.Kind == KindHTTP && l.Port == 80 {
		writeAcme(x)
	}
	for _, loc := range v.Locations {
		r := p.RouteByID[loc.RouteID]
		if loc.Exact {
			x.f(1, "location = %s {", loc.Path)
		} else {
			x.f(1, "location %s {", loc.Path)
		}
		x.f(2, "# route %q", r.Name)
		x.f(2, "set $ngm_route \"%s\";", r.ID)
		if r.DestKind == DestWebsite {
			writeWebsite(x, r, loc.Path)
		} else {
			writeHTTPRoute(x, p, r, ups)
		}
		x.f(1, "}")
	}
	// A named vhost that does not already own "/" serves the fallback website
	// for every unmatched path, so the host looks like an ordinary site on any
	// port instead of returning 404 (ADR-036). Unknown hosts/SNI are handled by
	// the default servers; this covers a configured host with partial paths
	// (e.g. the Control Center mounted under a secret path).
	if in.fallback() && !v.Default && !hasRootLocation(v) {
		writeFallbackSite(x, in)
	}
	x.f(0, "}")
	x.f(0, "")
}

// hasRootLocation reports whether the vhost already serves "/".
func hasRootLocation(v Vhost) bool {
	for _, loc := range v.Locations {
		if loc.Path == "/" {
			return true
		}
	}
	return false
}

// writeProbe answers verification probes at the server level, before any
// location or backend, so every vhost can prove which generation serves it.
// The token is per generation and secret; others never see the header.
func writeProbe(x *w, in CompileInput) {
	x.f(1, "if ($http_%s = \"%s\") { return 204; }", strings.ToLower(strings.ReplaceAll(ProbeHdr, "-", "_")), in.ProbeToken)
}

func destConnectTimeout(r *Route, ix *Index) int {
	if r.DestKind == DestEndpoint {
		if e, ok := ix.Endpoint[r.DestID]; ok {
			return e.ConnectTimeoutMS
		}
	}
	return 5000
}

func writeHTTPRoute(x *w, p *Plan, r *Route, ups map[string]bool) {
	ix := p.Ix
	switch r.DestKind {
	case DestReject:
		x.f(2, "return 444;")
		return
	case DestRedirect:
		code := r.Options.RedirectCode
		if code == 0 {
			code = 308
		}
		x.f(2, "return %d %s;", code, r.Options.RedirectURL)
		return
	}
	key := r.DestKind + ":" + r.DestID
	ups[key] = true
	scheme := "http"
	var ep *Endpoint
	if r.DestKind == DestEndpoint {
		ep = ix.Endpoint[r.DestID]
	} else if pl := ix.Pool[r.DestID]; pl != nil && len(pl.Members) > 0 {
		ep = ix.Endpoint[pl.Members[0].EndpointID]
	}
	if ep != nil && ep.Transport == "https" {
		scheme = "https"
	}
	x.f(2, "proxy_pass %s://%s;", scheme, upName("ngm_up_", r.DestID))
	x.f(2, "proxy_http_version 1.1;")
	if r.Options.PreserveHost == nil || *r.Options.PreserveHost {
		x.f(2, "proxy_set_header Host $host;")
	} else {
		x.f(2, "proxy_set_header Host $proxy_host;")
	}
	x.f(2, "proxy_set_header X-Real-IP $remote_addr;")
	x.f(2, "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	x.f(2, "proxy_set_header X-Forwarded-Proto $scheme;")
	x.f(2, "proxy_set_header %s \"\";", ProbeHdr) // never forward the probe secret
	if r.Options.WebSocket {
		x.f(2, "proxy_set_header Upgrade $http_upgrade;")
		x.f(2, "proxy_set_header Connection $ngm_connection_upgrade;")
	} else {
		x.f(2, "proxy_set_header Connection \"\";")
	}
	ct, rt, st := 5000, 60000, 60000
	if r.DestKind == DestEndpoint && ep != nil {
		ct, rt, st = ep.ConnectTimeoutMS, ep.ReadTimeoutMS, ep.WriteTimeoutMS
	}
	x.f(2, "proxy_connect_timeout %s;", ms(r.Options.ConnectTimeoutMS, ct))
	x.f(2, "proxy_read_timeout %s;", ms(r.Options.ReadTimeoutMS, rt))
	x.f(2, "proxy_send_timeout %s;", ms(r.Options.SendTimeoutMS, st))
	if r.Options.ClientMaxBodyMB > 0 {
		x.f(2, "client_max_body_size %dm;", r.Options.ClientMaxBodyMB)
	}
	if scheme == "https" && ep != nil {
		sni := ep.TLSServerName
		if sni == "" {
			sni = ep.Host
		}
		x.f(2, "proxy_ssl_server_name on;")
		x.f(2, "proxy_ssl_name %s;", sni)
		if ep.TLSVerify {
			x.f(2, "proxy_ssl_verify on;")
			x.f(2, "proxy_ssl_verify_depth 4;")
			x.f(2, "proxy_ssl_trusted_certificate %s;", CABundle)
		} else {
			x.f(2, "proxy_ssl_verify off;")
		}
	}
}

// writeAcme serves HTTP-01 challenge responses on plain-HTTP port 80 for
// every name (the CA connects by name; files exist only during validation).
func writeAcme(x *w) {
	x.f(1, "location ^~ %s {", AcmePrefix)
	x.f(2, "default_type text/plain;")
	x.f(2, "alias %s/;", AcmeDir)
	x.f(1, "}")
}

// SiteRoot is where a website's current published version is served from.
func SiteRoot(id string) string { return PublicRoot + "/sites/" + id + "/current" }

// writeWebsite serves a published static site. The per-site "current"
// pointer is followed per request, so publishing needs no reload.
func writeWebsite(x *w, r *Route, path string) {
	if path == "/" {
		x.f(2, "root %s;", SiteRoot(r.DestID))
		x.f(2, "try_files $uri $uri/ =404;")
		x.f(2, "error_page 404 /404.html;")
	} else {
		x.f(2, "alias %s/;", SiteRoot(r.DestID))
	}
	x.f(2, "index index.html;")
	x.f(2, "charset utf-8;")
	x.f(2, "autoindex off;")
	x.f(2, "add_header %s $ngm_probe_generation always;", GenHdr)
	x.f(2, "add_header X-Content-Type-Options nosniff always;")
	x.f(2, "add_header Referrer-Policy strict-origin-when-cross-origin always;")
	x.f(2, "add_header X-Frame-Options SAMEORIGIN always;")
}

func writeDefaultServer(x *w, caps Caps, in CompileInput, bind string, tls, internal, h2, acme bool) {
	x.f(0, "server {")
	x.f(1, "%s", listenLine(bind, tls, true, internal, h2, caps))
	x.f(1, "server_name _;")
	writeServerLogs(x, false)
	writePerf(x, in)
	if in.fallback() {
		// Unknown names look like an ordinary website (ADR-036).
		if tls {
			writeTLS(x, in, in.FallbackCertID)
		} else if acme {
			writeAcme(x)
		}
		writeFallbackSite(x, in)
	} else if tls {
		if caps.RejectHandshake {
			x.f(1, "ssl_reject_handshake on;")
		} else {
			writeTLS(x, in, in.DefaultCertID)
		}
		// Reached only when another vhost completed the handshake (via SNI)
		// but the Host header names no configured server.
		x.f(1, "return 421;")
	} else if acme {
		writeAcme(x)
		x.f(1, "location / { return 444; }")
	} else {
		x.f(1, "return 444;")
	}
	x.f(0, "}")
	x.f(0, "")
}

func streamUpstream(r *Route, ups map[string]bool) string {
	ups[r.DestKind+":"+r.DestID] = true
	return upName("ngm_sup_", r.DestID)
}

func writeFront(sb, hb *w, p *Plan, caps Caps, in CompileInput, lp *ListenerPlan, httpUps, streamUps map[string]bool, out *Output) {
	l := lp.L
	vname := "$ngm_front_" + strings.ToLower(l.ID)
	internal := func(port int) string { return hostPort(InternalAddr.String(), port) }
	target := func(r *Route) string {
		if port, ok := lp.StripperPorts[r.ID]; ok {
			_ = port
			return upName("ngm_strip_", r.ID)
		}
		return streamUpstream(r, streamUps)
	}
	sb.f(0, "# listener %q: TLS front, dispatch on ClientHello SNI/ALPN (ssl_preread; no decryption)", l.Name)
	sb.f(0, "map \"$ssl_preread_server_name|$ssl_preread_alpn_protocols\" %s {", vname)
	for _, rule := range lp.Rules {
		t := "ngm_term_" + strings.ToLower(l.ID)
		if rule.Kind == ProtoTLSPassthrough {
			t = target(p.RouteByID[rule.RouteID])
		}
		sb.f(1, "\"~*%s\" %s;", rule.Regex(), t)
	}
	switch {
	case lp.Fallback != nil && lp.Fallback.DestKind != DestReject:
		sb.f(1, "default %s; # fallback route %q (absent/unknown SNI, ECH)", target(lp.Fallback), lp.Fallback.Name)
	default:
		sb.f(1, "default ngm_reject_%s; # no matching rule → connection closed", strings.ToLower(l.ID))
	}
	sb.f(0, "}")
	sb.f(0, "server {")
	sb.f(1, "listen %s;", hostPort(l.Address, l.Port))
	writeServerLogs(sb, true)
	sb.f(1, "ssl_preread on;")
	sb.f(1, "proxy_protocol on;")
	sb.f(1, "proxy_pass %s;", vname)
	sb.f(1, "proxy_connect_timeout %s;", ms(0, in.streamConnect()))
	sb.f(1, "proxy_timeout %s;", ms(0, in.streamTimeout()))
	sb.f(0, "}")
	out.Listens = append(out.Listens, hostPort(l.Address, l.Port))
	// Reject hop.
	if lp.RejectPort != 0 {
		sb.f(0, "upstream ngm_reject_%s { server %s; }", strings.ToLower(l.ID), internal(lp.RejectPort))
		if in.fallback() {
			// Unknown or missing SNI: terminate TLS with the fallback
			// certificate and serve the fallback website (ADR-036).
			hb.f(0, "server {")
			hb.f(1, "listen %s ssl proxy_protocol;", internal(lp.RejectPort))
			hb.f(1, "server_name _;")
			writeServerLogs(hb, false)
			writePerf(hb, in)
			hb.f(1, "set_real_ip_from 127.0.0.0/8;")
			hb.f(1, "real_ip_header proxy_protocol;")
			writeTLS(hb, in, in.FallbackCertID)
			writeFallbackSite(hb, in)
			hb.f(0, "}")
		} else {
			sb.f(0, "server { listen %s proxy_protocol; return \"\"; }", internal(lp.RejectPort))
		}
		out.Listens = append(out.Listens, internal(lp.RejectPort))
	}
	// PROXY-stripping hops for passthrough backends without PROXY support.
	ids := make([]string, 0, len(lp.StripperPorts))
	for id := range lp.StripperPorts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := p.RouteByID[id]
		port := lp.StripperPorts[id]
		sb.f(0, "# route %q: strip PROXY header (client address kept in $proxy_protocol_addr), then pass TLS through", r.Name)
		sb.f(0, "upstream %s { server %s; }", upName("ngm_strip_", id), internal(port))
		sb.f(0, "server {")
		sb.f(1, "listen %s proxy_protocol;", internal(port))
		sb.f(1, "proxy_pass %s;", streamUpstream(r, streamUps))
		sb.f(1, "proxy_connect_timeout %s;", ms(r.Options.ConnectTimeoutMS, destConnectTimeout(r, p.Ix)))
		sb.f(1, "proxy_timeout %s;", ms(r.Options.StreamTimeoutMS, in.streamTimeout()))
		sb.f(0, "}")
		out.Listens = append(out.Listens, internal(port))
	}
	// TLS-termination hop (http module) for terminate routes.
	if lp.TermPort != 0 {
		sb.f(0, "upstream ngm_term_%s { server %s; }", strings.ToLower(l.ID), internal(lp.TermPort))
		sb.f(0, "")
		for _, v := range lp.TermVhosts {
			writeVhost(hb, p, caps, in, l, internal(lp.TermPort), true, true, v, httpUps)
			out.Probes = append(out.Probes, vhostProbe(l, v, true))
		}
		writeDefaultServer(hb, caps, in, internal(lp.TermPort), true, true, false, false)
		out.Listens = append(out.Listens, internal(lp.TermPort))
	}
	sb.f(0, "")
}

func writeUpstreams(x *w, ix *Index, used map[string]bool, stream bool) {
	keys := make([]string, 0, len(used))
	for k := range used {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	prefix := "ngm_up_"
	if stream {
		prefix = "ngm_sup_"
	}
	for _, k := range keys {
		kind, id, _ := strings.Cut(k, ":")
		x.f(0, "upstream %s {", upName(prefix, id))
		type srv struct {
			e      *Endpoint
			weight int
			backup bool
		}
		var servers []srv
		strategy := "round_robin"
		if kind == DestEndpoint {
			servers = []srv{{ix.Endpoint[id], 1, false}}
		} else {
			pl := ix.Pool[id]
			strategy = pl.Strategy
			for _, m := range pl.Members {
				if e := ix.Endpoint[m.EndpointID]; e != nil && !e.Disabled {
					servers = append(servers, srv{e, m.Weight, m.Backup})
				}
			}
		}
		switch strategy {
		case "least_conn":
			x.f(1, "least_conn;")
		case "hash":
			x.f(1, "hash $remote_addr consistent;")
		}
		for _, s := range servers {
			line := fmt.Sprintf("server %s weight=%d max_fails=1 fail_timeout=10s", hostPort(s.e.Host, s.e.Port), s.weight)
			if s.backup {
				line += " backup"
			}
			x.f(1, "%s;", line)
		}
		if !stream {
			x.f(1, "keepalive 16;")
		}
		x.f(0, "}")
		x.f(0, "")
	}
}
