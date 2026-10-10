// Package perf implements performance profiles and guarded tuning
// (MASTER_SPEC §14). Profiles are provisional until benchmarked. Only an
// allowlist of directives is managed, rendered from validated numbers into
// NGM's own server blocks (never into nginx.conf, which NGM does not own:
// worker_processes/worker_connections are reported read-only). Every change
// takes effect only through a Safe Apply (diff, nginx -t, verify, rollback).
package perf

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ngm-gateway/ngm/internal/store"
)

// Profiles (provisional sizing targets).
var Profiles = []string{"low", "balanced", "high"}

// Spec describes one tunable.
type Spec struct {
	Name     string         `json:"name"`
	Context  string         `json:"context"` // http-server | http | stream-server
	Unit     string         `json:"unit"`
	Min      int            `json:"min"`
	Max      int            `json:"max"`
	Defaults map[string]int `json:"defaults"` // per profile; 0 = off (where allowed)
	Note     string         `json:"note,omitempty"`
}

// Specs is the allowlist.
var Specs = []Spec{
	{Name: "keepalive_timeout", Context: "http-server", Unit: "s", Min: 1, Max: 300, Defaults: map[string]int{"low": 30, "balanced": 65, "high": 75}},
	{Name: "client_header_timeout", Context: "http-server", Unit: "s", Min: 1, Max: 300, Defaults: map[string]int{"low": 15, "balanced": 30, "high": 60}},
	{Name: "client_body_timeout", Context: "http-server", Unit: "s", Min: 1, Max: 600, Defaults: map[string]int{"low": 30, "balanced": 60, "high": 60}},
	{Name: "send_timeout", Context: "http-server", Unit: "s", Min: 1, Max: 600, Defaults: map[string]int{"low": 30, "balanced": 60, "high": 60}},
	{Name: "client_max_body_size", Context: "http-server", Unit: "MiB", Min: 1, Max: 4096, Defaults: map[string]int{"low": 16, "balanced": 64, "high": 256}, Note: "routes may set their own limit"},
	{Name: "proxy_buffer_size", Context: "http-server", Unit: "KiB", Min: 4, Max: 64, Defaults: map[string]int{"low": 4, "balanced": 8, "high": 16}},
	{Name: "proxy_buffers", Context: "http-server", Unit: "buffers (of proxy_buffer_size)", Min: 2, Max: 64, Defaults: map[string]int{"low": 4, "balanced": 8, "high": 16}},
	{Name: "limit_req_rate", Context: "http", Unit: "requests/s per client IP (0 = off)", Min: 0, Max: 10000, Defaults: map[string]int{"low": 0, "balanced": 0, "high": 0}, Note: "uses limit_req_zone ngm_req (10 MiB shared memory)"},
	{Name: "limit_req_burst", Context: "http-server", Unit: "requests", Min: 0, Max: 10000, Defaults: map[string]int{"low": 20, "balanced": 50, "high": 100}},
	{Name: "limit_conn_per_ip", Context: "http-server", Unit: "connections per client IP (0 = off)", Min: 0, Max: 100000, Defaults: map[string]int{"low": 0, "balanced": 0, "high": 0}},
	{Name: "stream_proxy_timeout", Context: "stream-server", Unit: "s", Min: 1, Max: 86400, Defaults: map[string]int{"low": 600, "balanced": 600, "high": 3600}, Note: "routes may set their own timeout"},
	{Name: "stream_proxy_connect_timeout", Context: "stream-server", Unit: "s", Min: 1, Max: 60, Defaults: map[string]int{"low": 5, "balanced": 5, "high": 5}},
}

// Internal (non-Nginx) knobs the profile adapts automatically.
type Internal struct {
	MonitorConcurrency int `json:"monitor_concurrency"`
	LogBatch           int `json:"log_batch"`
}

var internals = map[string]Internal{"low": {4, 2000}, "balanced": {8, 5000}, "high": {16, 10000}}

// Settings are stored under the "performance" setting.
type Settings struct {
	Profile   string         `json:"profile"`             // "" = recommended
	Overrides map[string]int `json:"overrides,omitempty"` // kept across profile changes until reset
}

// Value is one directive's default/override/effective view.
type Value struct {
	Spec
	Default   int  `json:"default"`
	Override  *int `json:"override,omitempty"`
	Effective int  `json:"effective"`
}

// View is the full performance state.
type View struct {
	Recommended string   `json:"recommended"`
	Profile     string   `json:"profile"` // effective profile
	Selected    string   `json:"selected,omitempty"`
	Values      []Value  `json:"values"`
	Internal    Internal `json:"internal"`
	Reason      string   `json:"reason"`
}

// Recommend picks a profile from usable memory and CPUs (provisional).
func Recommend(memBytes uint64, cpus int) (string, string) {
	gib := float64(memBytes) / (1 << 30)
	switch {
	case memBytes == 0:
		return "balanced", "no memory evidence yet; balanced assumed"
	case gib < 1.5 || cpus <= 1:
		return "low", fmt.Sprintf("%.1f GiB RAM, %d CPU(s)", gib, cpus)
	case gib < 3.5:
		return "balanced", fmt.Sprintf("%.1f GiB RAM, %d CPU(s)", gib, cpus)
	}
	return "high", fmt.Sprintf("%.1f GiB RAM, %d CPU(s)", gib, cpus)
}

const settingKey = "performance"

// Load reads the settings.
func Load(ctx context.Context, db *store.DB) Settings {
	var s Settings
	var raw string
	if db.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", settingKey).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

// ErrInvalid wraps validation errors.
var ErrInvalid = errors.New("invalid performance settings")

// Validate checks a settings document.
func (s Settings) Validate() error {
	if s.Profile != "" && !contains(Profiles, s.Profile) {
		return fmt.Errorf("%w: unknown profile %q", ErrInvalid, s.Profile)
	}
	for k, v := range s.Overrides {
		sp, ok := spec(k)
		if !ok {
			return fmt.Errorf("%w: %s is not a managed directive", ErrInvalid, k)
		}
		if v < sp.Min || v > sp.Max {
			return fmt.Errorf("%w: %s must be %d–%d %s", ErrInvalid, k, sp.Min, sp.Max, sp.Unit)
		}
	}
	return nil
}

// Save stores validated settings (they reach Nginx with the next apply).
func Save(ctx context.Context, db *store.DB, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	return db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, revision=revision+1, updated_at=excluded.updated_at`, settingKey, string(b), store.FormatTime(time.Now()))
		return err
	})
}

func spec(n string) (Spec, bool) {
	for _, s := range Specs {
		if s.Name == n {
			return s, true
		}
	}
	return Spec{}, false
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Resolve computes the effective view.
func Resolve(s Settings, memBytes uint64, cpus int) View {
	rec, why := Recommend(memBytes, cpus)
	p := rec
	if s.Profile != "" {
		p = s.Profile
	}
	v := View{Recommended: rec, Profile: p, Selected: s.Profile, Internal: internals[p], Reason: why}
	for _, sp := range Specs {
		val := Value{Spec: sp, Default: sp.Defaults[p]}
		val.Effective = val.Default
		if o, ok := s.Overrides[sp.Name]; ok {
			o := o
			val.Override, val.Effective = &o, o
		}
		v.Values = append(v.Values, val)
	}
	return v
}

// Rendered is what the compiler writes.
type Rendered struct {
	HTTP         []string `json:"http"`          // http context (our include)
	HTTPServer   []string `json:"http_server"`   // every NGM http server
	StreamServer []string `json:"stream_server"` // every NGM stream server
	Hash         string   `json:"hash"`
}

// Render turns the effective values into directives (numbers only).
func (v View) Render() Rendered {
	e := map[string]int{}
	for _, x := range v.Values {
		e[x.Name] = x.Effective
	}
	r := Rendered{}
	for _, n := range []string{"keepalive_timeout", "client_header_timeout", "client_body_timeout", "send_timeout"} {
		r.HTTPServer = append(r.HTTPServer, fmt.Sprintf("%s %ds;", n, e[n]))
	}
	r.HTTPServer = append(r.HTTPServer, fmt.Sprintf("client_max_body_size %dm;", e["client_max_body_size"]),
		fmt.Sprintf("proxy_buffer_size %dk;", e["proxy_buffer_size"]),
		fmt.Sprintf("proxy_buffers %d %dk;", e["proxy_buffers"], e["proxy_buffer_size"]))
	// proxy_busy_buffers_size must be < total buffers - one buffer.
	busy := e["proxy_buffer_size"] * 2
	if max := (e["proxy_buffers"] - 1) * e["proxy_buffer_size"]; busy > max {
		busy = max
	}
	r.HTTPServer = append(r.HTTPServer, fmt.Sprintf("proxy_busy_buffers_size %dk;", busy))
	if rate := e["limit_req_rate"]; rate > 0 {
		r.HTTP = append(r.HTTP, fmt.Sprintf("limit_req_zone $binary_remote_addr zone=ngm_req:10m rate=%dr/s;", rate))
		r.HTTPServer = append(r.HTTPServer, fmt.Sprintf("limit_req zone=ngm_req burst=%d nodelay;", e["limit_req_burst"]), "limit_req_status 429;")
	}
	if c := e["limit_conn_per_ip"]; c > 0 {
		r.HTTP = append(r.HTTP, "limit_conn_zone $binary_remote_addr zone=ngm_conn:10m;")
		r.HTTPServer = append(r.HTTPServer, fmt.Sprintf("limit_conn ngm_conn %d;", c), "limit_conn_status 429;")
	}
	r.StreamServer = append(r.StreamServer, fmt.Sprintf("proxy_timeout %ds;", e["stream_proxy_timeout"]), fmt.Sprintf("proxy_connect_timeout %ds;", e["stream_proxy_connect_timeout"]))
	all := append(append(append([]string{}, r.HTTP...), r.HTTPServer...), r.StreamServer...)
	sort.Strings(all)
	h := sha256.Sum256([]byte(fmt.Sprint(all)))
	r.Hash = hex.EncodeToString(h[:8])
	return r
}

// Current resolves the stored settings against the latest system metrics
// evidence (memory, CPUs recorded by ngm-monitor).
func Current(ctx context.Context, db *store.DB) View {
	var m struct {
		MemTotal uint64 `json:"mem_total"`
		CPUs     int    `json:"cpus"`
	}
	var raw string
	_ = db.QueryRowContext(ctx, "SELECT data_json FROM runtime_observations WHERE kind='system' ORDER BY observed_at DESC LIMIT 1").Scan(&raw)
	_ = json.Unmarshal([]byte(raw), &m)
	return Resolve(Load(ctx, db), m.MemTotal, m.CPUs)
}
