// Package gwstore persists the desired gateway model (listeners, routes,
// endpoints, pools, certificates). Changes here are Desired state only; Nginx
// is touched exclusively by the Deployment Coordinator (MASTER_SPEC §7.2).
package gwstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

var (
	ErrNotFound = errors.New("not found")
	ErrStale    = errors.New("revision changed")
	ErrInUse    = errors.New("resource is in use")
	ErrConflict = errors.New("conflict")
)

// ValidationError is a client-safe input problem.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{fmt.Sprintf(f, a...)} }

// Service is the gateway store.
type Service struct {
	db    *store.DB
	vault *vault.Vault
	audit *audit.Logger
	now   func() time.Time
	// OnChange is called after a committed mutation (e.g. to publish SSE).
	OnChange func(ctx context.Context, kind, id string)
}

// New returns a Service.
func New(db *store.DB, v *vault.Vault, a *audit.Logger) *Service {
	return &Service{db: db, vault: v, audit: a, now: time.Now}
}

func (s *Service) changed(ctx context.Context, kind, id string) {
	if s.OnChange != nil {
		s.OnChange(ctx, kind, id)
	}
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor *auth.Principal, action, kind, id string, c map[string]any) error {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: kind, TargetID: id, Result: "success", Context: c, RequestID: auth.RequestIDFrom(ctx)}
	if actor != nil {
		e.ActorKind, e.ActorID = actor.Kind, actor.UserID
		if actor.Kind == "local" {
			e.ActorKind = "cli"
		}
	}
	_, err := s.audit.RecordTx(ctx, tx, e)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func uniqueErr(err error, what string) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("%w: %s", ErrConflict, what)
	}
	return err
}

// checkRev verifies optimistic concurrency inside tx.
func checkRev(ctx context.Context, tx *sql.Tx, table, id string, rev int64) error {
	var cur int64
	if err := tx.QueryRowContext(ctx, "SELECT revision FROM "+table+" WHERE id=?", id).Scan(&cur); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if cur != rev {
		return ErrStale
	}
	return nil
}

func validName(n string) error {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > 64 {
		return invalid("name is required (max 64 characters)")
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ' ' || r == '.' || r == '_' || r == '-') {
			return invalid("name may contain letters, digits, space, '.', '_' and '-'")
		}
	}
	return nil
}

// ─── listeners ─────────────────────────────────────────────────────────────

const listenerCols = "id,name,kind,address,port,family,options_json,enabled,revision"

func scanListener(sc interface{ Scan(...any) error }) (*gateway.Listener, error) {
	var l gateway.Listener
	var opt string
	var en int
	if err := sc.Scan(&l.ID, &l.Name, &l.Kind, &l.Address, &l.Port, &l.Family, &opt, &en, &l.Revision); err != nil {
		return nil, err
	}
	l.Enabled = en == 1
	_ = json.Unmarshal([]byte(opt), &l.Options)
	return &l, nil
}

// ListListeners returns all listeners.
func (s *Service) ListListeners(ctx context.Context) ([]*gateway.Listener, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+listenerCols+" FROM listeners ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*gateway.Listener{}
	for rows.Next() {
		l, err := scanListener(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetListener loads one listener.
func (s *Service) GetListener(ctx context.Context, id string) (*gateway.Listener, error) {
	l, err := scanListener(s.db.QueryRowContext(ctx, "SELECT "+listenerCols+" FROM listeners WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return l, err
}

func normalizeListener(l *gateway.Listener) error {
	if err := validName(l.Name); err != nil {
		return err
	}
	switch l.Kind {
	case gateway.KindHTTP, gateway.KindHTTPS, gateway.KindStream, gateway.KindStreamTLSFront:
	default:
		return invalid("kind must be http, https, stream or stream_tls_front")
	}
	if l.Port < 1 || l.Port > 65535 {
		return invalid("port must be 1–65535")
	}
	if strings.Contains(l.Address, ":") {
		l.Family = "ipv6"
	} else {
		l.Family = "ipv4"
	}
	return nil
}

// SaveListener creates (id=="") or updates a listener.
func (s *Service) SaveListener(ctx context.Context, actor *auth.Principal, l *gateway.Listener, rev int64) (*gateway.Listener, error) {
	if err := normalizeListener(l); err != nil {
		return nil, err
	}
	opt, _ := json.Marshal(l.Options)
	now := store.FormatTime(s.now())
	create := l.ID == ""
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if create {
			l.ID = ids.New()
			_, err := tx.ExecContext(ctx, `INSERT INTO listeners(id,name,kind,address,port,family,options_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				l.ID, strings.TrimSpace(l.Name), l.Kind, l.Address, l.Port, l.Family, string(opt), b2i(l.Enabled), now, now)
			if err := uniqueErr(err, "a listener with this name or address:port exists"); err != nil {
				return err
			}
		} else {
			if err := checkRev(ctx, tx, "listeners", l.ID, rev); err != nil {
				return err
			}
			var routes int
			_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE listener_id=?", l.ID).Scan(&routes)
			var oldKind string
			_ = tx.QueryRowContext(ctx, "SELECT kind FROM listeners WHERE id=?", l.ID).Scan(&oldKind)
			if routes > 0 && oldKind != l.Kind {
				return invalid("cannot change the kind of a listener that has routes")
			}
			_, err := tx.ExecContext(ctx, `UPDATE listeners SET name=?, kind=?, address=?, port=?, family=?, options_json=?, enabled=?, revision=revision+1, updated_at=? WHERE id=?`,
				strings.TrimSpace(l.Name), l.Kind, l.Address, l.Port, l.Family, string(opt), b2i(l.Enabled), now, l.ID)
			if err := uniqueErr(err, "a listener with this name or address:port exists"); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, actor, map[bool]string{true: "listener.create", false: "listener.update"}[create], "listener", l.ID,
			map[string]any{"name": l.Name, "kind": l.Kind, "bind": fmt.Sprintf("%s:%d", l.Address, l.Port)})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "listener", l.ID)
	return s.GetListener(ctx, l.ID)
}

// DeleteListener deletes a listener without routes.
func (s *Service) DeleteListener(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkRev(ctx, tx, "listeners", id, rev); err != nil {
			return err
		}
		var n int
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE listener_id=?", id).Scan(&n)
		if n > 0 {
			return fmt.Errorf("%w: %d route(s) use this listener", ErrInUse, n)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM listeners WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "listener.delete", "listener", id, nil)
	})
	if err == nil {
		s.changed(ctx, "listener", id)
	}
	return err
}

// ─── endpoints ─────────────────────────────────────────────────────────────

const endpointCols = "id,name,host,port,transport,tls_verify,COALESCE(tls_server_name,''),weight,priority,connect_timeout_ms,read_timeout_ms,write_timeout_ms,disabled,health_policy_json,revision"

func scanEndpoint(sc interface{ Scan(...any) error }) (*gateway.Endpoint, error) {
	var e gateway.Endpoint
	var v, d int
	var hp string
	if err := sc.Scan(&e.ID, &e.Name, &e.Host, &e.Port, &e.Transport, &v, &e.TLSServerName, &e.Weight, &e.Priority,
		&e.ConnectTimeoutMS, &e.ReadTimeoutMS, &e.WriteTimeoutMS, &d, &hp, &e.Revision); err != nil {
		return nil, err
	}
	e.TLSVerify, e.Disabled = v == 1, d == 1
	_ = json.Unmarshal([]byte(hp), &e.Health)
	return &e, nil
}

// ListEndpoints returns all endpoints.
func (s *Service) ListEndpoints(ctx context.Context) ([]*gateway.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+endpointCols+" FROM backend_endpoints ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*gateway.Endpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEndpoint loads one endpoint.
func (s *Service) GetEndpoint(ctx context.Context, id string) (*gateway.Endpoint, error) {
	e, err := scanEndpoint(s.db.QueryRowContext(ctx, "SELECT "+endpointCols+" FROM backend_endpoints WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func normalizeEndpoint(e *gateway.Endpoint) error {
	if err := validName(e.Name); err != nil {
		return err
	}
	e.Host = strings.TrimSpace(e.Host)
	if e.Host == "" || len(e.Host) > 253 {
		return invalid("host is required")
	}
	if e.Port < 1 || e.Port > 65535 {
		return invalid("port must be 1–65535")
	}
	switch e.Transport {
	case "http", "https", "tcp":
	default:
		return invalid("transport must be http, https or tcp")
	}
	if e.Weight == 0 {
		e.Weight = 1
	}
	if e.ConnectTimeoutMS == 0 {
		e.ConnectTimeoutMS = 5000
	}
	if e.ReadTimeoutMS == 0 {
		e.ReadTimeoutMS = 60000
	}
	if e.WriteTimeoutMS == 0 {
		e.WriteTimeoutMS = 60000
	}
	h := &e.Health
	if h.Path == "" {
		h.Path = "/"
	}
	if !strings.HasPrefix(h.Path, "/") || len(h.Path) > 256 || strings.ContainsAny(h.Path, " \t\r\n") {
		return invalid("health path must start with / and contain no whitespace")
	}
	if h.IntervalSec == 0 {
		h.IntervalSec = 10
	}
	if h.IntervalSec < 5 || h.IntervalSec > 3600 {
		return invalid("health interval must be 5–3600 s")
	}
	if h.TimeoutMS == 0 {
		h.TimeoutMS = 2000
	}
	if h.TimeoutMS < 100 || h.TimeoutMS > 30000 {
		return invalid("health timeout must be 100–30000 ms")
	}
	if h.ExpectStatus == "" {
		h.ExpectStatus = "200-399"
	}
	if _, _, ok := ParseStatusRange(h.ExpectStatus); !ok {
		return invalid("expect_status must look like 200-399 or 204")
	}
	return nil
}

// ParseStatusRange parses "200-399" or "204".
func ParseStatusRange(s string) (lo, hi int, ok bool) {
	a, b, found := strings.Cut(s, "-")
	if !found {
		b = a
	}
	lo, e1 := strconv.Atoi(strings.TrimSpace(a))
	hi, e2 := strconv.Atoi(strings.TrimSpace(b))
	return lo, hi, e1 == nil && e2 == nil && lo >= 100 && hi <= 599 && lo <= hi
}

// SaveEndpoint creates or updates an endpoint.
func (s *Service) SaveEndpoint(ctx context.Context, actor *auth.Principal, e *gateway.Endpoint, rev int64) (*gateway.Endpoint, error) {
	if err := normalizeEndpoint(e); err != nil {
		return nil, err
	}
	now := store.FormatTime(s.now())
	create := e.ID == ""
	var sni any
	if e.TLSServerName != "" {
		sni = e.TLSServerName
	}
	hj, _ := json.Marshal(e.Health)
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if create {
			e.ID = ids.New()
			_, err := tx.ExecContext(ctx, `INSERT INTO backend_endpoints(id,name,host,port,transport,tls_verify,tls_server_name,weight,priority,connect_timeout_ms,read_timeout_ms,write_timeout_ms,disabled,health_policy_json,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.ID, strings.TrimSpace(e.Name), e.Host, e.Port, e.Transport, b2i(e.TLSVerify), sni, e.Weight, e.Priority,
				e.ConnectTimeoutMS, e.ReadTimeoutMS, e.WriteTimeoutMS, b2i(e.Disabled), string(hj), now, now)
			if err := uniqueErr(err, "an endpoint with this name exists"); err != nil {
				return err
			}
		} else {
			if err := checkRev(ctx, tx, "backend_endpoints", e.ID, rev); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE backend_endpoints SET name=?, host=?, port=?, transport=?, tls_verify=?, tls_server_name=?, weight=?, priority=?,
				connect_timeout_ms=?, read_timeout_ms=?, write_timeout_ms=?, disabled=?, health_policy_json=?, revision=revision+1, updated_at=? WHERE id=?`,
				strings.TrimSpace(e.Name), e.Host, e.Port, e.Transport, b2i(e.TLSVerify), sni, e.Weight, e.Priority, e.ConnectTimeoutMS, e.ReadTimeoutMS, e.WriteTimeoutMS, b2i(e.Disabled), string(hj), now, e.ID)
			if err := uniqueErr(err, "an endpoint with this name exists"); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, actor, map[bool]string{true: "endpoint.create", false: "endpoint.update"}[create], "endpoint", e.ID,
			map[string]any{"name": e.Name, "target": fmt.Sprintf("%s:%d", e.Host, e.Port), "transport": e.Transport})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "endpoint", e.ID)
	return s.GetEndpoint(ctx, e.ID)
}

// DeleteEndpoint deletes an unused endpoint.
func (s *Service) DeleteEndpoint(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkRev(ctx, tx, "backend_endpoints", id, rev); err != nil {
			return err
		}
		var routes, pools int
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE destination_kind='endpoint' AND destination_id=?", id).Scan(&routes)
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM backend_pool_members WHERE endpoint_id=?", id).Scan(&pools)
		if routes+pools > 0 {
			return fmt.Errorf("%w: referenced by %d route(s) and %d pool(s)", ErrInUse, routes, pools)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM backend_endpoints WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "endpoint.delete", "endpoint", id, nil)
	})
	if err == nil {
		s.changed(ctx, "endpoint", id)
	}
	return err
}

// ─── pools ─────────────────────────────────────────────────────────────────

// ListPools returns pools with members.
func (s *Service) ListPools(ctx context.Context) ([]*gateway.Pool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,strategy,revision FROM backend_pools ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := []*gateway.Pool{}
	for rows.Next() {
		var p gateway.Pool
		if err := rows.Scan(&p.ID, &p.Name, &p.Strategy, &p.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, &p)
	}
	rows.Close()
	for _, p := range out {
		if p.Members, err = s.members(ctx, s.db, p.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Service) members(ctx context.Context, q querier, id string) ([]gateway.PoolMember, error) {
	rows, err := q.QueryContext(ctx, "SELECT endpoint_id, weight, is_backup FROM backend_pool_members WHERE pool_id=? ORDER BY endpoint_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gateway.PoolMember{}
	for rows.Next() {
		var m gateway.PoolMember
		var b int
		if err := rows.Scan(&m.EndpointID, &m.Weight, &b); err != nil {
			return nil, err
		}
		m.Backup = b == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetPool loads one pool.
func (s *Service) GetPool(ctx context.Context, id string) (*gateway.Pool, error) {
	var p gateway.Pool
	err := s.db.QueryRowContext(ctx, "SELECT id,name,strategy,revision FROM backend_pools WHERE id=?", id).Scan(&p.ID, &p.Name, &p.Strategy, &p.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Members, err = s.members(ctx, s.db, id)
	return &p, err
}

// SavePool creates or updates a pool (members replaced).
func (s *Service) SavePool(ctx context.Context, actor *auth.Principal, p *gateway.Pool, rev int64) (*gateway.Pool, error) {
	if err := validName(p.Name); err != nil {
		return nil, err
	}
	switch p.Strategy {
	case "round_robin", "least_conn", "hash", "failover":
	default:
		return nil, invalid("strategy must be round_robin, least_conn, hash or failover")
	}
	if len(p.Members) == 0 || len(p.Members) > 64 {
		return nil, invalid("a pool needs 1–64 members")
	}
	now := store.FormatTime(s.now())
	create := p.ID == ""
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if create {
			p.ID = ids.New()
			_, err := tx.ExecContext(ctx, "INSERT INTO backend_pools(id,name,strategy,created_at,updated_at) VALUES(?,?,?,?,?)", p.ID, strings.TrimSpace(p.Name), p.Strategy, now, now)
			if err := uniqueErr(err, "a pool with this name exists"); err != nil {
				return err
			}
		} else {
			if err := checkRev(ctx, tx, "backend_pools", p.ID, rev); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "UPDATE backend_pools SET name=?, strategy=?, revision=revision+1, updated_at=? WHERE id=?", strings.TrimSpace(p.Name), p.Strategy, now, p.ID)
			if err := uniqueErr(err, "a pool with this name exists"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM backend_pool_members WHERE pool_id=?", p.ID); err != nil {
				return err
			}
		}
		for _, m := range p.Members {
			w := m.Weight
			if w == 0 {
				w = 1
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO backend_pool_members(pool_id,endpoint_id,weight,is_backup) VALUES(?,?,?,?)", p.ID, m.EndpointID, w, b2i(m.Backup))
			if err != nil {
				if strings.Contains(err.Error(), "FOREIGN KEY") {
					return invalid("pool member references an unknown endpoint")
				}
				return uniqueErr(err, "duplicate pool member")
			}
		}
		return s.auditTx(ctx, tx, actor, map[bool]string{true: "pool.create", false: "pool.update"}[create], "pool", p.ID, map[string]any{"name": p.Name, "members": len(p.Members)})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "pool", p.ID)
	return s.GetPool(ctx, p.ID)
}

// DeletePool deletes an unused pool.
func (s *Service) DeletePool(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkRev(ctx, tx, "backend_pools", id, rev); err != nil {
			return err
		}
		var n int
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE destination_kind='pool' AND destination_id=?", id).Scan(&n)
		if n > 0 {
			return fmt.Errorf("%w: %d route(s) use this pool", ErrInUse, n)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM backend_pools WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "pool.delete", "pool", id, nil)
	})
	if err == nil {
		s.changed(ctx, "pool", id)
	}
	return err
}

// ─── routes ────────────────────────────────────────────────────────────────

const routeCols = "id,name,listener_id,protocol,priority,destination_kind,COALESCE(destination_id,''),is_fallback,COALESCE(certificate_id,''),options_json,enabled,revision"

func scanRoute(sc interface{ Scan(...any) error }) (*gateway.Route, error) {
	var r gateway.Route
	var fb, en int
	var opt string
	if err := sc.Scan(&r.ID, &r.Name, &r.ListenerID, &r.Protocol, &r.Priority, &r.DestKind, &r.DestID, &fb, &r.CertificateID, &opt, &en, &r.Revision); err != nil {
		return nil, err
	}
	r.Fallback, r.Enabled = fb == 1, en == 1
	_ = json.Unmarshal([]byte(opt), &r.Options)
	return &r, nil
}

func (s *Service) matches(ctx context.Context, q querier, id string) ([]gateway.Match, error) {
	rows, err := q.QueryContext(ctx, "SELECT field, operator, value FROM match_rules WHERE route_id=? ORDER BY field, value", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gateway.Match{}
	for rows.Next() {
		var m gateway.Match
		if err := rows.Scan(&m.Field, &m.Operator, &m.Value); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListRoutes returns all routes with matches.
func (s *Service) ListRoutes(ctx context.Context) ([]*gateway.Route, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+routeCols+" FROM routes ORDER BY listener_id, priority, name")
	if err != nil {
		return nil, err
	}
	out := []*gateway.Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	for _, r := range out {
		if r.Matches, err = s.matches(ctx, s.db, r.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetRoute loads one route.
func (s *Service) GetRoute(ctx context.Context, id string) (*gateway.Route, error) {
	r, err := scanRoute(s.db.QueryRowContext(ctx, "SELECT "+routeCols+" FROM routes WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Matches, err = s.matches(ctx, s.db, id)
	return r, err
}

func normalizeRoute(r *gateway.Route) error {
	if err := validName(r.Name); err != nil {
		return err
	}
	switch r.Protocol {
	case gateway.ProtoHTTP, gateway.ProtoTCP, gateway.ProtoTLSPassthrough, gateway.ProtoTLSTerminate:
	default:
		return invalid("unknown protocol")
	}
	switch r.DestKind {
	case gateway.DestPool, gateway.DestEndpoint, gateway.DestRedirect, gateway.DestReject, gateway.DestWebsite:
	default:
		return invalid("unknown destination kind")
	}
	if r.DestKind == gateway.DestRedirect || r.DestKind == gateway.DestReject {
		r.DestID = ""
	}
	if len(r.Matches) > 32 {
		return invalid("at most 32 match conditions per route")
	}
	for i := range r.Matches {
		m := &r.Matches[i]
		m.Value = strings.TrimSpace(m.Value)
		if m.Field == gateway.FieldHost || m.Field == gateway.FieldSNI {
			m.Value = strings.ToLower(m.Value)
		}
		if len(m.Value) == 0 || len(m.Value) > 256 {
			return invalid("match values must be 1–256 characters")
		}
	}
	if r.Priority < 0 || r.Priority > 10000 {
		return invalid("priority must be 0–10000")
	}
	return nil
}

// SaveRoute creates or updates a route (matches replaced).
func (s *Service) SaveRoute(ctx context.Context, actor *auth.Principal, r *gateway.Route, rev int64) (*gateway.Route, error) {
	if err := normalizeRoute(r); err != nil {
		return nil, err
	}
	opt, _ := json.Marshal(r.Options)
	now := store.FormatTime(s.now())
	create := r.ID == ""
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var exists int
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM listeners WHERE id=?", r.ListenerID).Scan(&exists)
		if exists == 0 {
			return invalid("unknown listener")
		}
		if r.CertificateID != "" {
			_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM certificates WHERE id=?", r.CertificateID).Scan(&exists)
			if exists == 0 {
				return invalid("unknown certificate")
			}
		}
		if create {
			r.ID = ids.New()
			_, err := tx.ExecContext(ctx, `INSERT INTO routes(id,name,listener_id,protocol,priority,destination_kind,destination_id,is_fallback,certificate_id,options_json,enabled,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.ID, strings.TrimSpace(r.Name), r.ListenerID, r.Protocol, r.Priority, r.DestKind, nullable(r.DestID), b2i(r.Fallback),
				nullable(r.CertificateID), string(opt), b2i(r.Enabled), now, now)
			if err := uniqueErr(err, "a route with this name exists"); err != nil {
				return err
			}
		} else {
			if err := checkRev(ctx, tx, "routes", r.ID, rev); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE routes SET name=?, listener_id=?, protocol=?, priority=?, destination_kind=?, destination_id=?, is_fallback=?, certificate_id=?,
				options_json=?, enabled=?, revision=revision+1, updated_at=? WHERE id=?`, strings.TrimSpace(r.Name), r.ListenerID, r.Protocol, r.Priority, r.DestKind,
				nullable(r.DestID), b2i(r.Fallback), nullable(r.CertificateID), string(opt), b2i(r.Enabled), now, r.ID)
			if err := uniqueErr(err, "a route with this name exists"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM match_rules WHERE route_id=?", r.ID); err != nil {
				return err
			}
		}
		for _, m := range r.Matches {
			_, err := tx.ExecContext(ctx, "INSERT INTO match_rules(id,route_id,field,operator,value) VALUES(?,?,?,?,?)", ids.New(), r.ID, m.Field, m.Operator, m.Value)
			if err != nil {
				if strings.Contains(err.Error(), "CHECK") {
					return invalid("invalid match field or operator")
				}
				return uniqueErr(err, "duplicate match condition")
			}
		}
		return s.auditTx(ctx, tx, actor, map[bool]string{true: "route.create", false: "route.update"}[create], "route", r.ID,
			map[string]any{"name": r.Name, "protocol": r.Protocol, "destination": r.DestKind})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "route", r.ID)
	return s.GetRoute(ctx, r.ID)
}

// DeleteRoute deletes a route.
func (s *Service) DeleteRoute(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkRev(ctx, tx, "routes", id, rev); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM routes WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "route.delete", "route", id, nil)
	})
	if err == nil {
		s.changed(ctx, "route", id)
	}
	return err
}

// ─── model ─────────────────────────────────────────────────────────────────

// LoadModel reads the desired model.
func (s *Service) LoadModel(ctx context.Context) (*gateway.Model, error) {
	m := &gateway.Model{}
	wrows, err := s.db.QueryContext(ctx, "SELECT id, name, active_version_id IS NOT NULL AND active_version_id<>'' FROM websites ORDER BY id")
	if err != nil {
		return nil, err
	}
	for wrows.Next() {
		var w gateway.Website
		var pub int
		if err := wrows.Scan(&w.ID, &w.Name, &pub); err != nil {
			wrows.Close()
			return nil, err
		}
		w.Published = pub == 1
		m.Websites = append(m.Websites, w)
	}
	wrows.Close()
	ls, err := s.ListListeners(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range ls {
		m.Listeners = append(m.Listeners, *l)
	}
	es, err := s.ListEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		m.Endpoints = append(m.Endpoints, *e)
	}
	ps, err := s.ListPools(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		m.Pools = append(m.Pools, *p)
	}
	rs, err := s.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		m.Routes = append(m.Routes, *r)
	}
	cs, err := s.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		m.Certificates = append(m.Certificates, gateway.Certificate{ID: c.ID, Name: c.Name, SANs: c.SANs, NotAfter: c.NotAfter, Status: c.Status, HasKey: c.HasKey, Fingerprint: c.Fingerprint})
	}
	return m, nil
}
