// Package fwstore persists the desired NGM-owned UFW rules (MASTER_SPEC §9).
// Only rules recorded here are ever created or removed by NGM.
package fwstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/fwspec"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

var (
	ErrNotFound = errors.New("not found")
	ErrStale    = errors.New("revision changed")
	ErrConflict = errors.New("conflict")
)

// ValidationError is a client-safe input problem.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Rule is a desired firewall rule.
type Rule struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	Action      string    `json:"action"`
	Proto       string    `json:"proto"`
	Port        int       `json:"port"`
	Source      string    `json:"source"`
	ActiveState string    `json:"active_state"` // present | absent | unknown (last applied evidence)
	Revision    int64     `json:"revision"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Typed converts to the helper representation.
func (r Rule) Typed() fwspec.Rule {
	return fwspec.Rule{Key: r.Key, Action: r.Action, Proto: r.Proto, Port: r.Port, Source: r.Source}
}

// Service stores rules.
type Service struct {
	DB    *store.DB
	Audit *audit.Logger
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor *auth.Principal, action, id string, c map[string]any) error {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: "firewall_rule", TargetID: id, Result: "success", Context: c, RequestID: auth.RequestIDFrom(ctx)}
	if actor != nil {
		e.ActorKind, e.ActorID = actor.Kind, actor.UserID
	}
	_, err := s.Audit.RecordTx(ctx, tx, e)
	return err
}

// List returns desired rules.
func (s *Service) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,rule_key,action,proto,port,source,active_state,revision,updated_at FROM managed_firewall_rules
		WHERE desired_state='present' ORDER BY port, rule_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var u string
		if err := rows.Scan(&r.ID, &r.Key, &r.Action, &r.Proto, &r.Port, &r.Source, &r.ActiveState, &r.Revision, &u); err != nil {
			return nil, err
		}
		r.UpdatedAt, _ = store.ParseTime(u)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Create adds a desired rule.
func (s *Service) Create(ctx context.Context, actor *auth.Principal, r Rule) (*Rule, error) {
	r.Key = strings.ToLower(strings.TrimSpace(r.Key))
	if r.Source == "" {
		r.Source = "any"
	}
	if strings.HasPrefix(r.Key, fwspec.SSHGuardKey) {
		return nil, &ValidationError{"the ssh-guard key is reserved"}
	}
	if err := r.Typed().Validate(); err != nil {
		return nil, &ValidationError{err.Error()}
	}
	if r.Source != "any" {
		if p, err := netip.ParsePrefix(r.Source); err == nil && p.Bits() == 0 {
			r.Source = "any"
		}
	}
	r.ID = ids.New()
	now := store.FormatTime(time.Now())
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO managed_firewall_rules(id,rule_key,action,proto,port,source,family,refcount,desired_state,active_state,created_at,updated_at)
			VALUES(?,?,?,?,?,?,'both',1,'present','unknown',?,?)`, r.ID, r.Key, r.Action, r.Proto, r.Port, r.Source, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: rule key exists", ErrConflict)
			}
			return err
		}
		return s.auditTx(ctx, tx, actor, "firewall.rule_create", r.ID, map[string]any{"rule": r.Key, "action": r.Action, "port": r.Port, "source": r.Source})
	})
	if err != nil {
		return nil, err
	}
	r.ActiveState, r.Revision = "unknown", 1
	return &r, nil
}

// Delete removes a desired rule (applied by the next firewall job).
func (s *Service) Delete(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM managed_firewall_rules WHERE id=? AND desired_state='present'", id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if cur != rev {
			return ErrStale
		}
		if _, err := tx.ExecContext(ctx, "UPDATE managed_firewall_rules SET desired_state='absent', revision=revision+1, updated_at=? WHERE id=?", store.FormatTime(time.Now()), id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "firewall.rule_delete", id, nil)
	})
}

// Removed returns rules marked absent that may still exist in UFW.
func (s *Service) Removed(ctx context.Context) ([]Rule, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,rule_key,action,proto,port,source,active_state,revision,updated_at FROM managed_firewall_rules WHERE desired_state='absent'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var u string
		if err := rows.Scan(&r.ID, &r.Key, &r.Action, &r.Proto, &r.Port, &r.Source, &r.ActiveState, &r.Revision, &u); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkApplied records the observed outcome after a firewall job.
func (s *Service) MarkApplied(ctx context.Context, present map[string]bool) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := store.FormatTime(time.Now())
		rows, err := tx.QueryContext(ctx, "SELECT id, rule_key, desired_state FROM managed_firewall_rules")
		if err != nil {
			return err
		}
		type rr struct{ id, key, desired string }
		var all []rr
		for rows.Next() {
			var x rr
			rows.Scan(&x.id, &x.key, &x.desired)
			all = append(all, x)
		}
		rows.Close()
		for _, x := range all {
			st := "absent"
			if present[x.key] {
				st = "present"
			}
			if x.desired == "absent" && st == "absent" {
				if _, err := tx.ExecContext(ctx, "DELETE FROM managed_firewall_rules WHERE id=?", x.id); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, "UPDATE managed_firewall_rules SET active_state=?, updated_at=? WHERE id=?", st, now, x.id); err != nil {
				return err
			}
		}
		return nil
	})
}

// SettingConfirm is the settings key a confirmation writes for a job.
func SettingConfirm(jobID string) string { return "fw.confirm." + jobID }

// Confirm records that an operator confirmed access after a risky change.
func (s *Service) Confirm(ctx context.Context, actor *auth.Principal, jobID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var state, kind string
		if err := tx.QueryRowContext(ctx, "SELECT state, kind FROM jobs WHERE id=?", jobID).Scan(&state, &kind); err != nil {
			return ErrNotFound
		}
		if kind != "firewall.apply" || state != "Verifying" {
			return fmt.Errorf("%w: job is not awaiting confirmation (state %s)", ErrConflict, state)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`, SettingConfirm(jobID), `true`, store.FormatTime(time.Now())); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "firewall.confirm", jobID, nil)
	})
}
