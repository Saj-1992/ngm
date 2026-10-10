// Package gateway holds the routing model, its validator, the Nginx
// configuration compiler and the Route Simulation engine (MASTER_SPEC §5).
//
// The compiler and the simulator share one precedence implementation
// (ordering.go) so that simulation reflects exactly what is generated. The
// simulator models the compiled configuration; it does not prove runtime
// packet behaviour.
package gateway

import (
	"net/netip"
	"time"
)

// Listener kinds.
const (
	KindHTTP           = "http"             // plain HTTP server
	KindHTTPS          = "https"            // TLS terminated by NGM (http module)
	KindStream         = "stream"           // raw TCP proxy (stream module)
	KindStreamTLSFront = "stream_tls_front" // stream front with ssl_preread dispatch (shared 443)
)

// Route protocols.
const (
	ProtoHTTP           = "http"               // on http/https listeners
	ProtoTCP            = "tcp"                // on stream listeners
	ProtoTLSPassthrough = "tls_passthrough"    // on stream_tls_front: forward TLS bytes untouched
	ProtoTLSTerminate   = "tls_terminate_http" // on stream_tls_front: terminate at NGM, then HTTP routing
)

// Destination kinds.
const (
	DestPool     = "pool"
	DestEndpoint = "endpoint"
	DestWebsite  = "website"
	DestRedirect = "redirect"
	DestReject   = "reject"
)

// Match fields/operators.
const (
	FieldSNI        = "sni"
	FieldALPN       = "alpn"
	FieldHost       = "host"
	FieldPathPrefix = "path_prefix"
	FieldPathExact  = "path_exact"

	OpExact    = "exact"
	OpWildcard = "wildcard"
	OpPrefix   = "prefix"
)

// ListenerOptions are per-listener knobs.
type ListenerOptions struct {
	HTTP2 bool `json:"http2,omitempty"` // https listeners; requires capability
	// UDP makes a "stream" listener forward UDP datagrams instead of TCP
	// (Layer 4). A UDP and a TCP listener may share the same port.
	UDP bool `json:"udp,omitempty"`
}

// Listener is a bind point.
type Listener struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Address  string          `json:"address"`
	Port     int             `json:"port"`
	Family   string          `json:"family"`
	Enabled  bool            `json:"enabled"`
	Options  ListenerOptions `json:"options"`
	Revision int64           `json:"revision"`
}

// Match is one match condition. All conditions of a route must hold.
type Match struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// RouteOptions are per-route knobs.
type RouteOptions struct {
	WebSocket         bool   `json:"websocket,omitempty"`
	PreserveHost      *bool  `json:"preserve_host,omitempty"` // default true
	ConnectTimeoutMS  int    `json:"connect_timeout_ms,omitempty"`
	ReadTimeoutMS     int    `json:"read_timeout_ms,omitempty"`
	SendTimeoutMS     int    `json:"send_timeout_ms,omitempty"`
	ClientMaxBodyMB   int    `json:"client_max_body_mb,omitempty"`
	RedirectURL       string `json:"redirect_url,omitempty"`
	RedirectCode      int    `json:"redirect_code,omitempty"`
	StreamTimeoutMS   int    `json:"stream_timeout_ms,omitempty"`
	BackendProxyProto bool   `json:"backend_proxy_protocol,omitempty"` // passthrough backend accepts PROXY v1
}

// Route connects a listener and match conditions to a destination.
type Route struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	ListenerID    string       `json:"listener_id"`
	Protocol      string       `json:"protocol"`
	Priority      int          `json:"priority"`
	DestKind      string       `json:"destination_kind"`
	DestID        string       `json:"destination_id,omitempty"`
	Fallback      bool         `json:"is_fallback"`
	CertificateID string       `json:"certificate_id,omitempty"`
	Matches       []Match      `json:"matches"`
	Options       RouteOptions `json:"options"`
	Enabled       bool         `json:"enabled"`
	Revision      int64        `json:"revision"`
}

// Endpoint is one backend server.
type Endpoint struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Host             string       `json:"host"`
	Port             int          `json:"port"`
	Transport        string       `json:"transport"` // http | https | tcp
	TLSVerify        bool         `json:"tls_verify"`
	TLSServerName    string       `json:"tls_server_name,omitempty"`
	Weight           int          `json:"weight"`
	Priority         int          `json:"priority"`
	ConnectTimeoutMS int          `json:"connect_timeout_ms"`
	ReadTimeoutMS    int          `json:"read_timeout_ms"`
	WriteTimeoutMS   int          `json:"write_timeout_ms"`
	Disabled         bool         `json:"disabled"`
	Health           HealthPolicy `json:"health"`
	Revision         int64        `json:"revision"`
}

// HealthPolicy configures active health checks run by ngm-monitor.
type HealthPolicy struct {
	Disabled     bool   `json:"disabled,omitempty"`
	Path         string `json:"path,omitempty"`          // HTTP(S) probe path (default /)
	IntervalSec  int    `json:"interval_s,omitempty"`    // default 10, min 5
	TimeoutMS    int    `json:"timeout_ms,omitempty"`    // default 2000
	ExpectStatus string `json:"expect_status,omitempty"` // e.g. "200-399" (default)
}

// PoolMember references an endpoint.
type PoolMember struct {
	EndpointID string `json:"endpoint_id"`
	Weight     int    `json:"weight"`
	Backup     bool   `json:"backup"`
}

// Pool is a group of endpoints.
type Pool struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Strategy string       `json:"strategy"` // round_robin | least_conn | hash | failover
	Members  []PoolMember `json:"members"`
	Revision int64        `json:"revision"`
}

// Certificate is the compiler's view of a certificate.
type Certificate struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	SANs     []string  `json:"sans"`
	NotAfter time.Time `json:"not_after"`
	Status   string    `json:"status"`
	HasKey   bool      `json:"has_key"`
	// Fingerprint changes on renewal/re-import, so a new certificate always
	// makes a new generation even when names and expiry are unchanged.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Model is the complete desired (or active) gateway configuration.
type Model struct {
	Listeners    []Listener    `json:"listeners"`
	Routes       []Route       `json:"routes"`
	Endpoints    []Endpoint    `json:"endpoints"`
	Pools        []Pool        `json:"pools"`
	Certificates []Certificate `json:"certificates"`
	Websites     []Website     `json:"websites,omitempty"`
}

// Website is a route-visible website. Only "published" matters to Nginx: the
// served version is a per-site pointer switched without a reload.
type Website struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Published bool   `json:"published"`
}

// Caps describes what the installed Nginx supports (from runtime observation).
type Caps struct {
	Version         string `json:"version"` // e.g. "1.24.0"
	StreamModule    bool   `json:"stream_module"`
	SSLPreread      bool   `json:"ssl_preread"`
	HTTP2           bool   `json:"http2"`
	RejectHandshake bool   `json:"reject_handshake"` // ssl_reject_handshake (>= 1.19.4)
	HTTP2Directive  bool   `json:"http2_directive"`  // "http2 on;" (>= 1.25.1); else "listen ... http2"
}

// CapsFromVersion derives version-gated capabilities.
func CapsFromVersion(v string, stream, preread, h2 bool) Caps {
	return Caps{Version: v, StreamModule: stream, SSLPreread: preread, HTTP2: h2,
		RejectHandshake: versionAtLeast(v, 1, 19, 4), HTTP2Directive: versionAtLeast(v, 1, 25, 1)}
}

func versionAtLeast(v string, maj, min, patch int) bool {
	var a, b, c int
	n, _ := sscanVersion(v, &a, &b, &c)
	if n < 2 {
		return false
	}
	if a != maj {
		return a > maj
	}
	if b != min {
		return b > min
	}
	return c >= patch
}

// Reserved addresses/ports that NGM itself uses.
var (
	InternalAddr = netip.MustParseAddr("127.0.42.1") // internal hops (TLS termination, PROXY stripping)
	InternalBase = 10001
)

// Index provides lookups over a model.
type Index struct {
	Listener map[string]*Listener
	Endpoint map[string]*Endpoint
	Pool     map[string]*Pool
	Cert     map[string]*Certificate
	Website  map[string]*Website
	ByListen map[string][]*Route // enabled routes per listener id
}

// NewIndex builds lookups.
func NewIndex(m *Model) *Index {
	ix := &Index{Listener: map[string]*Listener{}, Endpoint: map[string]*Endpoint{}, Pool: map[string]*Pool{}, Cert: map[string]*Certificate{}, Website: map[string]*Website{}, ByListen: map[string][]*Route{}}
	for i := range m.Listeners {
		ix.Listener[m.Listeners[i].ID] = &m.Listeners[i]
	}
	for i := range m.Endpoints {
		ix.Endpoint[m.Endpoints[i].ID] = &m.Endpoints[i]
	}
	for i := range m.Pools {
		ix.Pool[m.Pools[i].ID] = &m.Pools[i]
	}
	for i := range m.Certificates {
		ix.Cert[m.Certificates[i].ID] = &m.Certificates[i]
	}
	for i := range m.Websites {
		ix.Website[m.Websites[i].ID] = &m.Websites[i]
	}
	for i := range m.Routes {
		r := &m.Routes[i]
		if r.Enabled {
			ix.ByListen[r.ListenerID] = append(ix.ByListen[r.ListenerID], r)
		}
	}
	return ix
}
