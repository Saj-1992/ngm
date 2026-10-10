// Package alerts evaluates alert rules from recorded evidence, keeps the
// alert lifecycle (firing → acknowledged → resolved, de-duplicated per
// rule+subject) and delivers notifications (Telegram, webhook) with retry,
// backoff and rate limiting (MASTER_SPEC §13.2). Delivery is best effort:
// NGM never claims guaranteed delivery, and records every attempt.
package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Condition is a rule that currently holds for a subject.
type Condition struct {
	Rule     string         `json:"rule"`
	Subject  string         `json:"subject"`
	Severity string         `json:"severity"` // info | warning | critical
	Message  string         `json:"message"`
	Details  map[string]any `json:"details,omitempty"`
}

// Alert is a stored alert.
type Alert struct {
	ID         string          `json:"id"`
	Rule       string          `json:"rule"`
	Subject    string          `json:"subject"`
	Severity   string          `json:"severity"`
	State      string          `json:"state"`
	Message    string          `json:"message"`
	Details    json.RawMessage `json:"details"`
	FirstAt    time.Time       `json:"first_at"`
	LastAt     time.Time       `json:"last_at"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
	AckBy      string          `json:"acknowledged_by,omitempty"`
}

// Transition is a change notifications are sent for.
type Transition struct {
	Event string // firing | resolved
	Alert Alert
}

// Store manages alerts.
type Store struct{ DB *store.DB }

const cols = "id,rule,subject,severity,state,message,details_json,first_at,last_at,COALESCE(resolved_at,''),COALESCE(acknowledged_by,'')"

func scan(sc interface{ Scan(...any) error }) (*Alert, error) {
	var a Alert
	var d, f, l, r string
	if err := sc.Scan(&a.ID, &a.Rule, &a.Subject, &a.Severity, &a.State, &a.Message, &d, &f, &l, &r, &a.AckBy); err != nil {
		return nil, err
	}
	a.Details = json.RawMessage(d)
	a.FirstAt, _ = store.ParseTime(f)
	a.LastAt, _ = store.ParseTime(l)
	if r != "" {
		t, _ := store.ParseTime(r)
		a.ResolvedAt = &t
	}
	return &a, nil
}

// List returns alerts (open first, newest first).
func (s *Store) List(ctx context.Context, openOnly bool, limit int) ([]*Alert, error) {
	q := "SELECT " + cols + " FROM alerts"
	if openOnly {
		q += " WHERE state<>'resolved'"
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, q+" ORDER BY state='resolved', CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Alert{}
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrNotFound is returned for unknown or resolved alerts.
var ErrNotFound = errors.New("alert not found or already resolved")

// Acknowledge marks a firing alert as acknowledged (it still resolves by itself).
func (s *Store) Acknowledge(ctx context.Context, id, actor string) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE alerts SET state='acknowledged', acknowledged_by=?, acknowledged_at=?, revision=revision+1 WHERE id=? AND state='firing'",
		actor, store.FormatTime(time.Now()), id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// Sync records the current conditions: new ones fire, changed severities are
// updated, and open alerts whose condition no longer holds resolve.
func (s *Store) Sync(ctx context.Context, conds []Condition, now time.Time) ([]Transition, error) {
	var out []Transition
	ts := store.FormatTime(now)
	seen := map[string]bool{}
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		for _, c := range conds {
			key := c.Rule + "\x00" + c.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			dj, _ := json.Marshal(c.Details)
			var id, sev string
			err := tx.QueryRowContext(ctx, "SELECT id, severity FROM alerts WHERE rule=? AND subject=? AND state<>'resolved'", c.Rule, c.Subject).Scan(&id, &sev)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				id = ids.New()
				if _, err := tx.ExecContext(ctx, `INSERT INTO alerts(id,rule,subject,severity,state,details_json,first_at,last_at,message) VALUES(?,?,?,?,'firing',?,?,?,?)`,
					id, c.Rule, c.Subject, c.Severity, string(dj), ts, ts, c.Message); err != nil {
					return err
				}
				out = append(out, Transition{Event: "firing", Alert: Alert{ID: id, Rule: c.Rule, Subject: c.Subject, Severity: c.Severity, State: "firing", Message: c.Message, FirstAt: now, LastAt: now}})
			case err != nil:
				return err
			default:
				// Escalation re-notifies; otherwise just refresh evidence.
				state := ""
				if sevRank(c.Severity) > sevRank(sev) {
					state = ", state='firing'"
					out = append(out, Transition{Event: "firing", Alert: Alert{ID: id, Rule: c.Rule, Subject: c.Subject, Severity: c.Severity, State: "firing", Message: c.Message, LastAt: now}})
				}
				if _, err := tx.ExecContext(ctx, "UPDATE alerts SET severity=?, message=?, details_json=?, last_at=?"+state+" WHERE id=?", c.Severity, c.Message, string(dj), ts, id); err != nil {
					return err
				}
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+cols+" FROM alerts WHERE state<>'resolved'")
		if err != nil {
			return err
		}
		var open []*Alert
		for rows.Next() {
			a, err := scan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			open = append(open, a)
		}
		rows.Close()
		for _, a := range open {
			if seen[a.Rule+"\x00"+a.Subject] {
				continue
			}
			if _, err := tx.ExecContext(ctx, "UPDATE alerts SET state='resolved', resolved_at=?, last_at=? WHERE id=?", ts, ts, a.ID); err != nil {
				return err
			}
			a.State, a.ResolvedAt = "resolved", &now
			out = append(out, Transition{Event: "resolved", Alert: *a})
		}
		// Keep the history bounded.
		_, err = tx.ExecContext(ctx, "DELETE FROM alerts WHERE state='resolved' AND resolved_at<?", store.FormatTime(now.Add(-90*24*time.Hour)))
		return err
	})
	return out, err
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 2
	case "warning":
		return 1
	}
	return 0
}

// Text renders a notification message (no secrets: evidence summaries only).
func Text(t Transition, host string) string {
	icon := map[string]string{"critical": "🔴", "warning": "🟠", "info": "🔵"}[t.Alert.Severity]
	if t.Event == "resolved" {
		icon = "✅"
	}
	return strings.TrimSpace(fmt.Sprintf("%s NGM %s on %s\n%s [%s] %s\n%s", icon, strings.ToUpper(t.Event), host, t.Alert.Severity, t.Alert.Rule, t.Alert.Subject, t.Alert.Message))
}
