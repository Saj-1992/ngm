// Package monitor implements ngm-monitor: active, protocol-correct backend
// health checks (MASTER_SPEC §5.2, §13.2). Nginx OSS has no general active
// health checking, so NGM probes from Go and records evidence; Nginx's own
// passive max_fails behaviour remains a separate supplement.
//
// Probes target only administrator-configured endpoints, dial the address that
// was resolved and vetted once (no re-resolution → no DNS rebinding), never
// follow redirects, and are rate limited per endpoint and globally.
package monitor

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/sse"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Status values (shared with the API).
const (
	Healthy  = "healthy"
	Degraded = "degraded"
	Down     = "down"
	Unknown  = "unknown"
	Disabled = "disabled"
)

// Result is one probe outcome.
type Result struct {
	Status    string
	LatencyMS int64
	Detail    string
}

// blocked are destinations health probes must never reach (SSRF).
var blocked = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.PrefixFrom(gateway.InternalAddr, 32),
}

// Resolver resolves host names (replaceable in tests).
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Guard vets a target and returns the single address to dial.
type Guard struct {
	Resolve Resolver
	APIPort int // loopback API port is never probed
}

// Target resolves host once and refuses blocked destinations.
func (g Guard) Target(ctx context.Context, host string, port int) (netip.AddrPort, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		r := g.Resolve
		if r == nil {
			r = defaultResolver
		}
		rs, err := r(ctx, host)
		if err != nil || len(rs) == 0 {
			return netip.AddrPort{}, fmt.Errorf("resolve %s: %v", host, err)
		}
		addrs = rs
	}
	// Every resolved address must be acceptable: a mixed answer is treated
	// as hostile (rebinding attempts often mix public and internal IPs).
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsUnspecified() || a.IsMulticast() {
			return netip.AddrPort{}, fmt.Errorf("blocked address %s", a)
		}
		for _, p := range blocked {
			if p.Contains(a) {
				return netip.AddrPort{}, fmt.Errorf("blocked address %s (link-local/metadata/internal)", a)
			}
		}
		if a.IsLoopback() && port == g.APIPort {
			return netip.AddrPort{}, errors.New("refusing to probe the NGM API")
		}
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}

// Probe checks one endpoint.
func Probe(ctx context.Context, g Guard, e *gateway.Endpoint) Result {
	h := e.Health
	timeout := time.Duration(h.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	ap, err := g.Target(ctx, e.Host, e.Port)
	if err != nil {
		return Result{Status: Unknown, Detail: err.Error()}
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ap.String())
	}
	if e.Transport == "tcp" {
		c, err := dial(ctx, "", "")
		if err != nil {
			return Result{Status: Down, LatencyMS: time.Since(start).Milliseconds(), Detail: "tcp connect: " + shortErr(err)}
		}
		c.Close()
		return Result{Status: Healthy, LatencyMS: time.Since(start).Milliseconds(), Detail: "tcp connect ok"}
	}
	host := e.Host
	if e.TLSServerName != "" {
		host = e.TLSServerName
	}
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true, ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: !e.TLSVerify}} //nolint:gosec // per-endpoint policy
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	path := h.Path
	if path == "" {
		path = "/"
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", e.Transport+"://"+net.JoinHostPort(host, strconv.Itoa(e.Port))+path, nil)
	req.Header.Set("User-Agent", "ngm-monitor")
	resp, err := c.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{Status: Down, LatencyMS: lat, Detail: e.Transport + ": " + shortErr(err)}
	}
	resp.Body.Close()
	lo, hi, ok := gwstore.ParseStatusRange(h.ExpectStatus)
	if !ok {
		lo, hi = 200, 399
	}
	switch {
	case resp.StatusCode >= lo && resp.StatusCode <= hi:
		return Result{Status: Healthy, LatencyMS: lat, Detail: "HTTP " + strconv.Itoa(resp.StatusCode)}
	case resp.StatusCode >= 500:
		return Result{Status: Down, LatencyMS: lat, Detail: "HTTP " + strconv.Itoa(resp.StatusCode)}
	default:
		return Result{Status: Degraded, LatencyMS: lat, Detail: fmt.Sprintf("HTTP %d (expected %s)", resp.StatusCode, h.ExpectStatus)}
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// Monitor schedules probes.
type Monitor struct {
	DB          *store.DB
	GW          *gwstore.Service
	Broker      *sse.Broker
	Guard       Guard
	Log         *slog.Logger
	Concurrency int // default 8
	// ConcurrencyFn, when set, is consulted every round (adaptive perf profile).
	ConcurrencyFn func(context.Context) int
	// FailThreshold consecutive failures before Down (anti-flap; default 2).
	FailThreshold int
	Retain        int // samples kept per endpoint (default 200)

	mu       sync.Mutex
	next     map[string]time.Time
	failures map[string]int
	last     map[string]string
}

// Tick probes every endpoint that is due. It is safe to call every second.
func (m *Monitor) Tick(ctx context.Context) error {
	m.mu.Lock()
	if m.next == nil {
		m.next, m.failures, m.last = map[string]time.Time{}, map[string]int{}, map[string]string{}
	}
	m.mu.Unlock()
	eps, err := m.GW.ListEndpoints(ctx)
	if err != nil {
		return err
	}
	conc := m.Concurrency
	if m.ConcurrencyFn != nil {
		if c := m.ConcurrencyFn(ctx); c > 0 {
			conc = c
		}
	}
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	now := time.Now()
	for _, e := range eps {
		m.mu.Lock()
		due := m.next[e.ID]
		m.mu.Unlock()
		if now.Before(due) {
			continue
		}
		iv := time.Duration(max(e.Health.IntervalSec, 5)) * time.Second
		m.mu.Lock()
		m.next[e.ID] = now.Add(iv)
		m.mu.Unlock()
		if e.Disabled || e.Health.Disabled {
			m.record(ctx, e, Result{Status: Disabled, Detail: "health checks disabled"})
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(e *gateway.Endpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			m.record(ctx, e, Probe(ctx, m.Guard, e))
		}(e)
	}
	wg.Wait()
	return nil
}

// record applies the anti-flap threshold and stores the sample.
func (m *Monitor) record(ctx context.Context, e *gateway.Endpoint, r Result) {
	th := m.FailThreshold
	if th <= 0 {
		th = 2
	}
	m.mu.Lock()
	if r.Status == Down {
		m.failures[e.ID]++
		if m.failures[e.ID] < th {
			r.Status = Degraded
			r.Detail = fmt.Sprintf("%s (failure %d/%d)", r.Detail, m.failures[e.ID], th)
		}
	} else if r.Status == Healthy {
		m.failures[e.ID] = 0
	}
	prev := m.last[e.ID]
	m.last[e.ID] = r.Status
	m.mu.Unlock()
	retain := m.Retain
	if retain <= 0 {
		retain = 200
	}
	err := m.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO health_samples(subject_kind,subject_id,status,latency_ms,detail,observed_at) VALUES('endpoint',?,?,?,?,?)",
			e.ID, r.Status, r.LatencyMS, r.Detail, store.FormatTime(time.Now())); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM health_samples WHERE subject_kind='endpoint' AND subject_id=? AND seq NOT IN
			(SELECT seq FROM health_samples WHERE subject_kind='endpoint' AND subject_id=? ORDER BY seq DESC LIMIT ?)`, e.ID, e.ID, retain)
		return err
	})
	if err != nil && m.Log != nil {
		m.Log.Warn("monitor: record", "endpoint", e.ID, "err", err)
	}
	if prev != r.Status && m.Broker != nil {
		_, _ = m.Broker.Publish(ctx, "health.changed", "global", map[string]string{"endpoint": e.ID, "status": r.Status, "previous": prev})
	}
}

// EndpointHealth is the latest evidence for an endpoint.
type EndpointHealth struct {
	EndpointID string    `json:"endpoint_id"`
	Status     string    `json:"status"`
	LatencyMS  int64     `json:"latency_ms"`
	Detail     string    `json:"detail"`
	ObservedAt time.Time `json:"observed_at"`
	Stale      bool      `json:"stale"`
}

// Latest returns the newest sample per endpoint; stale evidence (older than
// 3× the endpoint's interval, min 60 s) is reported as Unknown.
func Latest(ctx context.Context, db *store.DB, eps []*gateway.Endpoint) ([]EndpointHealth, error) {
	out := make([]EndpointHealth, 0, len(eps))
	now := time.Now()
	for _, e := range eps {
		h := EndpointHealth{EndpointID: e.ID, Status: Unknown, Detail: "no health evidence yet"}
		var at string
		err := db.QueryRowContext(ctx, `SELECT status, COALESCE(latency_ms,0), detail, observed_at FROM health_samples
			WHERE subject_kind='endpoint' AND subject_id=? ORDER BY seq DESC LIMIT 1`, e.ID).Scan(&h.Status, &h.LatencyMS, &h.Detail, &at)
		if errors.Is(err, sql.ErrNoRows) {
			out = append(out, h)
			continue
		}
		if err != nil {
			return nil, err
		}
		h.ObservedAt, _ = store.ParseTime(at)
		limit := 3 * time.Duration(max(e.Health.IntervalSec, 10)) * time.Second
		if limit < time.Minute {
			limit = time.Minute
		}
		if now.Sub(h.ObservedAt) > limit {
			h.Stale, h.Status = true, Unknown
			h.Detail = "evidence stale since " + h.ObservedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, h)
	}
	return out, nil
}
