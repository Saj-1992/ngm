// Package domains is the Domain Registry (MASTER_SPEC §6.1): the single
// place that records which domains NGM manages, what DNS records they are
// expected to have, the DNS evidence observed for them, and which routes,
// certificates and websites depend on them.
package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/dnsq"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

var (
	ErrNotFound = errors.New("domain not found")
	ErrStale    = errors.New("revision changed")
	ErrConflict = errors.New("conflict")
	ErrInUse    = errors.New("domain is in use")
)

// ValidationError is a client-safe input problem.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{fmt.Sprintf(f, a...)} }

// Domain is a registered domain.
type Domain struct {
	ID         string    `json:"id"`
	FQDN       string    `json:"fqdn"`
	Purpose    string    `json:"purpose"`
	Notes      string    `json:"notes"`
	Provider   string    `json:"dns_provider"`
	ZoneID     string    `json:"provider_zone_id,omitempty"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Status     string    `json:"dns_status"` // ok | attention | unknown (from latest evidence)
	CheckedAt  time.Time `json:"checked_at,omitzero"`
	Expected   []Expect  `json:"expectations"`
	Observed   []Obs     `json:"observations"`
	Comparison []Compare `json:"comparison"`
}

// Expect is an expected DNS record.
type Expect struct {
	ID    string `json:"id"`
	Name  string `json:"name"` // FQDN (the domain or a sub-name)
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   *int   `json:"ttl,omitempty"`
}

// Obs is the latest observation of one name/type from one source.
type Obs struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Source     string    `json:"source"` // authoritative | resolver
	Server     string    `json:"server"`
	Values     []string  `json:"values"`
	TTL        *int      `json:"ttl,omitempty"`
	Rcode      string    `json:"rcode"`
	Error      string    `json:"error,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// Compare is the evaluation of one expectation against the evidence.
type Compare struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Status string `json:"status"` // match | mismatch | missing | propagating | unknown
	Detail string `json:"detail"`
}

// Service is the registry.
type Service struct {
	DB    *store.DB
	Audit *audit.Logger
	// PublicOrigin is the configured management origin (dependency check).
	PublicOrigin string
}

var purposes = map[string]bool{"general": true, "management": true, "website": true, "route": true}

// NormalizeFQDN validates and lower-cases a domain name.
func NormalizeFQDN(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if !dnsq.ValidName(s) || !strings.Contains(s, ".") || strings.Contains(s, "_") {
		return "", invalid("invalid domain name %q", s)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", invalid("an IP address is not a domain")
	}
	return s, nil
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor *auth.Principal, action, id string, c map[string]any) error {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: "domain", TargetID: id, Result: "success", Context: c, RequestID: auth.RequestIDFrom(ctx)}
	if actor != nil {
		e.ActorKind, e.ActorID = actor.Kind, actor.UserID
	}
	_, err := s.Audit.RecordTx(ctx, tx, e)
	return err
}

const cols = "id,fqdn,purpose,notes,dns_provider,provider_zone_id,revision,created_at,updated_at"

func scan(sc interface{ Scan(...any) error }) (*Domain, error) {
	var d Domain
	var c, u string
	if err := sc.Scan(&d.ID, &d.FQDN, &d.Purpose, &d.Notes, &d.Provider, &d.ZoneID, &d.Revision, &c, &u); err != nil {
		return nil, err
	}
	d.CreatedAt, _ = store.ParseTime(c)
	d.UpdatedAt, _ = store.ParseTime(u)
	return &d, nil
}

// List returns all domains with their evidence status.
func (s *Service) List(ctx context.Context) ([]*Domain, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+cols+" FROM domains ORDER BY fqdn")
	if err != nil {
		return nil, err
	}
	var out []*Domain
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	for _, d := range out {
		if err := s.fill(ctx, d); err != nil {
			return nil, err
		}
		// The list view carries the comparison only; details come from Get.
		d.Expected, d.Observed = []Expect{}, []Obs{}
	}
	if out == nil {
		out = []*Domain{}
	}
	return out, nil
}

// Get returns one domain with expectations, evidence and comparison.
func (s *Service) Get(ctx context.Context, id string) (*Domain, error) {
	d, err := scan(s.DB.QueryRowContext(ctx, "SELECT "+cols+" FROM domains WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return d, s.fill(ctx, d)
}

func (s *Service) fill(ctx context.Context, d *Domain) error {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,rtype,value,ttl FROM dns_record_expectations WHERE domain_id=? ORDER BY name,rtype,value", d.ID)
	if err != nil {
		return err
	}
	d.Expected = []Expect{}
	for rows.Next() {
		var e Expect
		var ttl sql.NullInt64
		if err := rows.Scan(&e.ID, &e.Name, &e.Type, &e.Value, &ttl); err != nil {
			rows.Close()
			return err
		}
		if ttl.Valid {
			v := int(ttl.Int64)
			e.TTL = &v
		}
		d.Expected = append(d.Expected, e)
	}
	rows.Close()
	orows, err := s.DB.QueryContext(ctx, "SELECT name,rtype,source,server,values_json,ttl,rcode,error,observed_at FROM dns_observations WHERE domain_id=? ORDER BY name,rtype,source", d.ID)
	if err != nil {
		return err
	}
	d.Observed = []Obs{}
	for orows.Next() {
		var o Obs
		var vj, at string
		var ttl sql.NullInt64
		if err := orows.Scan(&o.Name, &o.Type, &o.Source, &o.Server, &vj, &ttl, &o.Rcode, &o.Error, &at); err != nil {
			orows.Close()
			return err
		}
		_ = json.Unmarshal([]byte(vj), &o.Values)
		if ttl.Valid {
			v := int(ttl.Int64)
			o.TTL = &v
		}
		o.ObservedAt, _ = store.ParseTime(at)
		if o.ObservedAt.After(d.CheckedAt) {
			d.CheckedAt = o.ObservedAt
		}
		d.Observed = append(d.Observed, o)
	}
	orows.Close()
	d.Comparison = Evaluate(d.Expected, d.Observed)
	d.Status = overall(d.Comparison, d.Observed, d.CheckedAt)
	return nil
}

// staleAfter: evidence older than this is not trusted.
const staleAfter = 30 * time.Minute

func overall(cs []Compare, obs []Obs, at time.Time) string {
	if len(obs) == 0 || time.Since(at) > staleAfter {
		return "unknown"
	}
	for _, c := range cs {
		if c.Status != "match" {
			return "attention"
		}
	}
	for _, o := range obs {
		if o.Source == "authoritative" && o.Error != "" {
			return "unknown"
		}
	}
	return "ok"
}

func norm(t, v string) string {
	v = strings.TrimSpace(v)
	switch t {
	case "CNAME", "NS":
		return strings.ToLower(strings.TrimSuffix(v, "."))
	case "A", "AAAA":
		if a, err := netip.ParseAddr(v); err == nil {
			return a.String()
		}
	case "CAA":
		return strings.ToLower(v)
	}
	return v
}

func has(vals []string, t, v string) bool {
	for _, x := range vals {
		if norm(t, x) == norm(t, v) {
			return true
		}
	}
	return false
}

// Evaluate compares expectations with evidence: the authoritative answer
// decides match/mismatch; a resolver still serving something else is
// "propagating" (its cache TTL bounds how long that can last).
func Evaluate(exp []Expect, obs []Obs) []Compare {
	find := func(name, t, src string) *Obs {
		for i := range obs {
			if obs[i].Name == name && obs[i].Type == t && obs[i].Source == src {
				return &obs[i]
			}
		}
		return nil
	}
	out := []Compare{}
	for _, e := range exp {
		c := Compare{Name: e.Name, Type: e.Type, Value: e.Value}
		auth, res := find(e.Name, e.Type, "authoritative"), find(e.Name, e.Type, "resolver")
		switch {
		case auth == nil:
			c.Status, c.Detail = "unknown", "not checked yet"
		case auth.Error != "":
			c.Status, c.Detail = "unknown", "authoritative query failed: "+auth.Error
		case !has(auth.Values, e.Type, e.Value) && len(auth.Values) == 0:
			c.Status, c.Detail = "missing", "the authoritative server has no "+e.Type+" record for "+e.Name
		case !has(auth.Values, e.Type, e.Value):
			c.Status, c.Detail = "mismatch", "authoritative answer: "+strings.Join(auth.Values, ", ")
		case res != nil && res.Error == "" && !has(res.Values, e.Type, e.Value):
			c.Status = "propagating"
			c.Detail = "authoritative data is correct; the resolver still answers " + strings.Join(res.Values, ", ")
			if res.TTL != nil {
				c.Detail += fmt.Sprintf(" (cached up to %d s more; NGM cannot shorten caches)", *res.TTL)
			}
		default:
			c.Status = "match"
			if e.TTL != nil && auth.TTL != nil && *auth.TTL != *e.TTL {
				c.Detail = fmt.Sprintf("value matches; TTL %d differs from expected %d", *auth.TTL, *e.TTL)
			}
		}
		out = append(out, c)
	}
	return out
}

// Create registers a domain.
func (s *Service) Create(ctx context.Context, actor *auth.Principal, fqdn, purpose, notes string) (*Domain, error) {
	f, err := NormalizeFQDN(fqdn)
	if err != nil {
		return nil, err
	}
	if purpose == "" {
		purpose = "general"
	}
	if !purposes[purpose] {
		return nil, invalid("purpose must be general, management, website or route")
	}
	if len(notes) > 2000 {
		return nil, invalid("notes too long")
	}
	id := ids.New()
	now := store.FormatTime(time.Now())
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO domains(id,fqdn,purpose,notes,created_at,updated_at) VALUES(?,?,?,?,?,?)", id, f, purpose, notes, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: %s is already registered", ErrConflict, f)
			}
			return err
		}
		return s.auditTx(ctx, tx, actor, "domain.create", id, map[string]any{"fqdn": f, "purpose": purpose})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Update changes purpose/notes (the name is immutable; delete and re-add).
func (s *Service) Update(ctx context.Context, actor *auth.Principal, id string, rev int64, purpose, notes string) (*Domain, error) {
	if !purposes[purpose] {
		return nil, invalid("purpose must be general, management, website or route")
	}
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE domains SET purpose=?, notes=?, revision=revision+1, updated_at=? WHERE id=? AND revision=?", purpose, notes, store.FormatTime(time.Now()), id, rev)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return s.missingOrStale(ctx, tx, id)
		}
		return s.auditTx(ctx, tx, actor, "domain.update", id, map[string]any{"purpose": purpose})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Service) missingOrStale(ctx context.Context, tx *sql.Tx, id string) error {
	var n int
	_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM domains WHERE id=?", id).Scan(&n)
	if n == 0 {
		return ErrNotFound
	}
	return ErrStale
}

// Delete removes a domain that nothing depends on.
func (s *Service) Delete(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	d, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	u, err := s.Usage(ctx, d.FQDN)
	if err != nil {
		return err
	}
	if len(u) > 0 {
		var what []string
		for _, x := range u {
			what = append(what, x.Kind+" "+x.Name)
		}
		return fmt.Errorf("%w: %s", ErrInUse, strings.Join(what, ", "))
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM domains WHERE id=? AND revision=?", id, rev)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return s.missingOrStale(ctx, tx, id)
		}
		return s.auditTx(ctx, tx, actor, "domain.delete", id, map[string]any{"fqdn": d.FQDN})
	})
}

var rtypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "CAA": true, "NS": true, "TXT": true}

// AddExpectation records an expected record for name (the domain or a sub-name).
func (s *Service) AddExpectation(ctx context.Context, actor *auth.Principal, id string, e Expect) (*Domain, error) {
	d, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	name, err := NormalizeFQDN(e.Name)
	if e.Name == "" || e.Name == "@" {
		name, err = d.FQDN, nil
	}
	if err != nil {
		return nil, err
	}
	if name != d.FQDN && !strings.HasSuffix(name, "."+d.FQDN) {
		return nil, invalid("%s is not inside %s", name, d.FQDN)
	}
	e.Type = strings.ToUpper(e.Type)
	if !rtypes[e.Type] {
		return nil, invalid("record type must be A, AAAA, CNAME, CAA, NS or TXT")
	}
	v := strings.TrimSpace(e.Value)
	switch e.Type {
	case "A":
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is4() {
			return nil, invalid("A value must be an IPv4 address")
		}
		v = a.String()
	case "AAAA":
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is6() || a.Is4In6() {
			return nil, invalid("AAAA value must be an IPv6 address")
		}
		v = a.String()
	case "CNAME", "NS":
		if v, err = NormalizeFQDN(v); err != nil {
			return nil, err
		}
	case "CAA":
		if !caaRe(v) {
			return nil, invalid(`CAA value must look like: 0 issue "letsencrypt.org"`)
		}
	case "TXT":
		if v == "" || len(v) > 1024 {
			return nil, invalid("TXT value must be 1–1024 characters")
		}
	}
	if e.TTL != nil && (*e.TTL < 1 || *e.TTL > 604800) {
		return nil, invalid("TTL must be 1–604800 seconds")
	}
	var ttl any
	if e.TTL != nil {
		ttl = *e.TTL
	}
	now := store.FormatTime(time.Now())
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO dns_record_expectations(id,domain_id,name,rtype,value,ttl,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
			ids.New(), id, name, e.Type, v, ttl, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: this expectation exists", ErrConflict)
			}
			return err
		}
		return s.auditTx(ctx, tx, actor, "domain.expectation_add", id, map[string]any{"name": name, "type": e.Type, "value": v})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func caaRe(v string) bool {
	f := strings.SplitN(v, " ", 3)
	if len(f) != 3 || (f[0] != "0" && f[0] != "128") {
		return false
	}
	switch strings.ToLower(f[1]) {
	case "issue", "issuewild", "iodef":
	default:
		return false
	}
	return len(f[2]) >= 2 && strings.HasPrefix(f[2], `"`) && strings.HasSuffix(f[2], `"`)
}

// DeleteExpectation removes one expectation.
func (s *Service) DeleteExpectation(ctx context.Context, actor *auth.Principal, id, expID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM dns_record_expectations WHERE id=? AND domain_id=?", expID, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return s.auditTx(ctx, tx, actor, "domain.expectation_delete", id, map[string]any{"expectation": expID})
	})
}

// Use is one dependency on a domain.
type Use struct {
	Kind string `json:"kind"` // route | certificate | website | management_origin
	ID   string `json:"id"`
	Name string `json:"name"`
	What string `json:"what"` // the matching name
}

// covers reports whether pattern (exact or "*.x") covers name or is inside fqdn.
func inDomain(fqdn, v string) bool {
	v = strings.ToLower(strings.TrimSuffix(v, "."))
	v = strings.TrimPrefix(v, "*.")
	return v == fqdn || strings.HasSuffix(v, "."+fqdn)
}

// Usage lists routes, certificates, websites and the management origin
// that use fqdn or a name inside it.
func (s *Service) Usage(ctx context.Context, fqdn string) ([]Use, error) {
	out := []Use{}
	rows, err := s.DB.QueryContext(ctx, `SELECT r.id, r.name, m.value FROM match_rules m JOIN routes r ON r.id=m.route_id WHERE m.field IN ('host','sni')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name, v string
		if err := rows.Scan(&id, &name, &v); err != nil {
			rows.Close()
			return nil, err
		}
		if inDomain(fqdn, v) {
			out = append(out, Use{Kind: "route", ID: id, Name: name, What: v})
		}
	}
	rows.Close()
	crows, err := s.DB.QueryContext(ctx, "SELECT id, name, sans_json FROM certificates")
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var id, name, sj string
		if err := crows.Scan(&id, &name, &sj); err != nil {
			crows.Close()
			return nil, err
		}
		var sans []string
		_ = json.Unmarshal([]byte(sj), &sans)
		for _, n := range sans {
			if inDomain(fqdn, n) {
				out = append(out, Use{Kind: "certificate", ID: id, Name: name, What: n})
				break
			}
		}
	}
	crows.Close()
	if o := s.PublicOrigin; o != "" {
		h := strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
		h = strings.SplitN(strings.SplitN(h, "/", 2)[0], ":", 2)[0]
		if inDomain(fqdn, h) {
			out = append(out, Use{Kind: "management_origin", Name: "Control Center", What: h})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}

// Registered reports whether name lies inside any registered domain.
func (s *Service) Registered(ctx context.Context, name string) (bool, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT fqdn FROM domains")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return false, err
		}
		if inDomain(f, name) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// RequestCheck asks ngm-monitor to observe a domain now (picked up within ~10 s).
func (s *Service) RequestCheck(ctx context.Context, id string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`,
		"dns.check_request."+id, "true", store.FormatTime(time.Now()))
	return err
}

// PendingChecks lists domains with an outstanding check request.
func PendingChecks(ctx context.Context, db *store.DB) []string {
	rows, err := db.QueryContext(ctx, "SELECT key FROM settings WHERE key LIKE 'dns.check_request.%'")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out = append(out, strings.TrimPrefix(k, "dns.check_request."))
		}
	}
	return out
}
