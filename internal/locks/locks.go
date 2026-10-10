// Package locks implements durable lease locks with fencing tokens
// (MASTER_SPEC §8.2, DECISIONS ADR-005).
//
// A job declares its full lock set and acquires it atomically in one
// transaction, which makes deadlock impossible; the documented total order is
// still enforced so that the declared set is canonical and auditable. Every
// grant issues a new, globally monotonic fencing token. Writers holding a lease
// must call CheckFence inside the transaction (or helper call) that commits
// their effect; a stale worker whose lease expired and was re-granted fails.
package locks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ngm-gateway/ngm/internal/store"
)

// Resource is a lockable resource.
type Resource string

const (
	SystemUpdate   Resource = "system-update"
	BackupRestore  Resource = "backup-restore"
	GatewayConfig  Resource = "gateway-config"
	Certificate    Resource = "certificate"
	WebsitePublish Resource = "website-publish"
	Firewall       Resource = "firewall"
	DNSProvider    Resource = "dns-provider"
)

// Rank is the total acquisition order.
var Rank = map[Resource]int{
	SystemUpdate:   1,
	BackupRestore:  2,
	GatewayConfig:  3,
	Certificate:    4,
	WebsitePublish: 5,
	Firewall:       6,
	DNSProvider:    7,
}

var (
	ErrHeld        = errors.New("resource locked by another job")
	ErrLeaseLost   = errors.New("lease lost (expired or superseded)")
	ErrStaleFence  = errors.New("stale fencing token")
	ErrBadResource = errors.New("unknown lock resource")
)

// HeldError describes the current holder of a contended resource.
type HeldError struct {
	Resource  Resource
	HolderJob string
	ExpiresAt time.Time
}

func (e *HeldError) Error() string {
	return fmt.Sprintf("%s held by job %s until %s", e.Resource, e.HolderJob, e.ExpiresAt.Format(time.RFC3339))
}
func (e *HeldError) Unwrap() error { return ErrHeld }

// Lease is a granted lock set.
type Lease struct {
	JobID     string
	Worker    string
	Resources []Resource
	Token     int64
	ExpiresAt time.Time
}

// Manager grants and verifies leases.
type Manager struct {
	db  *store.DB
	now func() time.Time
}

// NewManager returns a Manager.
func NewManager(db *store.DB) *Manager { return &Manager{db: db, now: time.Now} }

// SetClock overrides the time source (tests).
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// Canonical validates and sorts a lock set by Rank, rejecting duplicates.
func Canonical(rs []Resource) ([]Resource, error) {
	out := append([]Resource(nil), rs...)
	seen := map[Resource]bool{}
	for _, r := range out {
		if _, ok := Rank[r]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrBadResource, r)
		}
		if seen[r] {
			return nil, fmt.Errorf("duplicate lock resource %q", r)
		}
		seen[r] = true
	}
	sort.Slice(out, func(i, j int) bool { return Rank[out[i]] < Rank[out[j]] })
	return out, nil
}

// Acquire atomically grants all resources to jobID or none. Expired leases
// held by others are taken over (their holders will fail fencing checks).
// Re-acquiring a set the same job already holds issues a fresh token.
func (m *Manager) Acquire(ctx context.Context, jobID, worker string, rs []Resource, ttl time.Duration) (*Lease, error) {
	set, err := Canonical(rs)
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, errors.New("empty lock set")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	var lease *Lease
	err = m.db.Tx(ctx, func(tx *sql.Tx) error {
		now := m.now()
		for _, r := range set {
			var holder, exp string
			err := tx.QueryRowContext(ctx, "SELECT holder_job_id, expires_at FROM lock_leases WHERE resource=?", string(r)).Scan(&holder, &exp)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			expT, _ := store.ParseTime(exp)
			if holder != jobID && now.Before(expT) {
				return &HeldError{Resource: r, HolderJob: holder, ExpiresAt: expT}
			}
		}
		var token int64
		if err := tx.QueryRowContext(ctx, "UPDATE fencing_counter SET value=value+1 WHERE id=1 RETURNING value").Scan(&token); err != nil {
			return err
		}
		nowS, expS := store.FormatTime(now), store.FormatTime(now.Add(ttl))
		for _, r := range set {
			if _, err := tx.ExecContext(ctx, `INSERT INTO lock_leases(resource,holder_job_id,holder_worker,fencing_token,acquired_at,heartbeat_at,expires_at)
				VALUES(?,?,?,?,?,?,?)
				ON CONFLICT(resource) DO UPDATE SET holder_job_id=excluded.holder_job_id, holder_worker=excluded.holder_worker,
				fencing_token=excluded.fencing_token, acquired_at=excluded.acquired_at, heartbeat_at=excluded.heartbeat_at, expires_at=excluded.expires_at`,
				string(r), jobID, worker, token, nowS, nowS, expS); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO lock_fences(resource,latest_token) VALUES(?,?)
				ON CONFLICT(resource) DO UPDATE SET latest_token=excluded.latest_token`, string(r), token); err != nil {
				return err
			}
		}
		lease = &Lease{JobID: jobID, Worker: worker, Resources: set, Token: token, ExpiresAt: now.Add(ttl)}
		return nil
	})
	return lease, err
}

// Heartbeat extends a lease. It fails with ErrLeaseLost if any resource is no
// longer held with this token, or the lease already expired.
func (m *Manager) Heartbeat(ctx context.Context, l *Lease, ttl time.Duration) error {
	return m.db.Tx(ctx, func(tx *sql.Tx) error {
		now := m.now()
		if !now.Before(l.ExpiresAt) {
			return ErrLeaseLost
		}
		exp := now.Add(ttl)
		for _, r := range l.Resources {
			res, err := tx.ExecContext(ctx, `UPDATE lock_leases SET heartbeat_at=?, expires_at=? WHERE resource=? AND holder_job_id=? AND fencing_token=?`,
				store.FormatTime(now), store.FormatTime(exp), string(r), l.JobID, l.Token)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ErrLeaseLost
			}
		}
		l.ExpiresAt = exp
		return nil
	})
}

// Release drops the lease's resources still held with its token. Releasing a
// lost lease is a no-op.
func (m *Manager) Release(ctx context.Context, l *Lease) error {
	return m.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, r := range l.Resources {
			if _, err := tx.ExecContext(ctx, "DELETE FROM lock_leases WHERE resource=? AND holder_job_id=? AND fencing_token=?",
				string(r), l.JobID, l.Token); err != nil {
				return err
			}
		}
		return nil
	})
}

// CheckFence verifies, inside tx, that token is the latest token for r and the
// lease is unexpired. Call it in the same transaction as the guarded write.
func (m *Manager) CheckFence(ctx context.Context, tx *sql.Tx, r Resource, token int64) error {
	var latest int64
	if err := tx.QueryRowContext(ctx, "SELECT latest_token FROM lock_fences WHERE resource=?", string(r)).Scan(&latest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStaleFence
		}
		return err
	}
	if latest != token {
		return fmt.Errorf("%w: have %d, latest %d", ErrStaleFence, token, latest)
	}
	var exp string
	err := tx.QueryRowContext(ctx, "SELECT expires_at FROM lock_leases WHERE resource=? AND fencing_token=?", string(r), token).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: lease released", ErrStaleFence)
	}
	if err != nil {
		return err
	}
	expT, _ := store.ParseTime(exp)
	if !m.now().Before(expT) {
		return fmt.Errorf("%w: lease expired", ErrStaleFence)
	}
	return nil
}

// FenceFunc adapts CheckFence for jobs.TransitionOpts.Fence.
func (m *Manager) FenceFunc(l *Lease) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		for _, r := range l.Resources {
			if err := m.CheckFence(ctx, tx, r, l.Token); err != nil {
				return err
			}
		}
		return nil
	}
}

// Holding describes a current lease row.
type Holding struct {
	Resource  Resource  `json:"resource"`
	JobID     string    `json:"job_id"`
	Worker    string    `json:"worker"`
	Token     int64     `json:"fencing_token"`
	ExpiresAt time.Time `json:"expires_at"`
	Expired   bool      `json:"expired"`
}

// List returns all lease rows (expired ones flagged), for diagnostics/recovery.
func (m *Manager) List(ctx context.Context) ([]Holding, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT resource,holder_job_id,holder_worker,fencing_token,expires_at FROM lock_leases")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := m.now()
	var out []Holding
	for rows.Next() {
		var h Holding
		var r, exp string
		if err := rows.Scan(&r, &h.JobID, &h.Worker, &h.Token, &exp); err != nil {
			return nil, err
		}
		h.Resource = Resource(r)
		h.ExpiresAt, _ = store.ParseTime(exp)
		h.Expired = !now.Before(h.ExpiresAt)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return Rank[out[i].Resource] < Rank[out[j].Resource] })
	return out, rows.Err()
}
