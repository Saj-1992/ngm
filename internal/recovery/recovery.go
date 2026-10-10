// Package recovery backs the Recovery Center (MASTER_SPEC §8.3): incidents
// opened when a job could not prove a safe outcome. Resolving one is a
// supervised, audited operator action; NGM never cleans up blindly.
package recovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

var (
	ErrNotFound = errors.New("incident not found")
	ErrResolved = errors.New("incident already resolved")
	ErrOutcome  = errors.New("outcome must be rolled_back, failed or succeeded")
	ErrNote     = errors.New("a note of 10–2000 characters describing the manual action is required")
	// ErrDrift: the data plane does not serve the recorded generation, so no
	// outcome can be attested by hand; a supervised reconcile is required.
	ErrDrift = errors.New("the data plane does not serve the recorded active generation")
	// ErrNoEvidence: no fresh observation of the data plane to check against.
	ErrNoEvidence = errors.New("no fresh observation of the data-plane pointer (is ngm-ops running?)")
)

// gatewayKinds are incidents whose resolution must agree with the data plane.
var gatewayKinds = map[string]bool{"deploy.gateway": true, "deploy.rollback": true, "deploy.reconcile": true}

// Drift describes a mismatch between the record and the serving generation.
type Drift struct {
	Serving    string    `json:"serving"`
	Recorded   string    `json:"recorded"`
	ObservedAt time.Time `json:"observed_at"`
}

// CurrentDrift compares the latest pointer observation with active_state.
// It returns (nil, nil) when they agree.
func CurrentDrift(ctx context.Context, db *store.DB) (*Drift, error) {
	var p observe.Pointer
	at, err := observe.Latest(ctx, db, observe.KindPointer, &p)
	if err != nil || time.Since(at) > 2*time.Minute {
		return nil, ErrNoEvidence
	}
	var rec sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT generation_id FROM active_state WHERE id=1").Scan(&rec)
	recorded := "empty" // = helper.EmptyGen (not imported: the API must not link privileged code)
	if rec.Valid && rec.String != "" {
		recorded = rec.String
	}
	if p.Current == recorded {
		return nil, nil
	}
	return &Drift{Serving: p.Current, Recorded: recorded, ObservedAt: at}, nil
}

// Incident is a recovery incident with its job context.
type Incident struct {
	ID         string          `json:"id"`
	JobID      string          `json:"job_id,omitempty"`
	JobKind    string          `json:"job_kind,omitempty"`
	JobState   string          `json:"job_state,omitempty"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	Evidence   json.RawMessage `json:"evidence"`
	OpenedAt   time.Time       `json:"opened_at"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
	ResolvedBy string          `json:"resolved_by,omitempty"`
	Revision   int64           `json:"revision"`
	// Actions are guided manual steps (codes; the UI localises them).
	Actions []Action `json:"actions"`
}

// Action is one guided manual step.
type Action struct {
	Code    string `json:"code"`
	Command string `json:"command,omitempty"` // shell command for the operator (never run by NGM)
}

// Service reads and resolves incidents.
type Service struct {
	DB    *store.DB
	Audit *audit.Logger
}

func guidance(kind, jobID string) []Action {
	switch kind {
	case "firewall.apply":
		return []Action{
			{Code: "fw_inspect", Command: "sudo ufw status numbered"},
			{Code: "fw_revert_plan", Command: "sudo /opt/ngm/current/ngm fw-revert " + jobID},
			{Code: "verify_ssh"},
		}
	case "backup.create":
		return []Action{{Code: "backup_check_disk", Command: "df -h /var/lib/ngm"}, {Code: "backup_retry"}}
	default: // deploy.gateway / deploy.rollback
		return []Action{
			{Code: "nginx_test", Command: "sudo nginx -t"},
			{Code: "nginx_current", Command: "readlink -f /etc/nginx/ngm/current"},
			{Code: "rollback_last_good"},
			{Code: "check_traffic"},
		}
	}
}

const sel = `SELECT r.id, COALESCE(r.job_id,''), COALESCE(j.kind,''), COALESCE(j.state,''), r.status, r.summary, r.evidence_json, r.opened_at,
	COALESCE(r.resolved_at,''), COALESCE(r.resolved_by,''), r.revision FROM recovery_incidents r LEFT JOIN jobs j ON j.id=r.job_id`

func scan(rows interface{ Scan(...any) error }) (*Incident, error) {
	var in Incident
	var ev, opened, resolved string
	if err := rows.Scan(&in.ID, &in.JobID, &in.JobKind, &in.JobState, &in.Status, &in.Summary, &ev, &opened, &resolved, &in.ResolvedBy, &in.Revision); err != nil {
		return nil, err
	}
	in.Evidence = json.RawMessage(ev)
	in.OpenedAt, _ = store.ParseTime(opened)
	if resolved != "" {
		t, _ := store.ParseTime(resolved)
		in.ResolvedAt = &t
	}
	in.Actions = guidance(in.JobKind, in.JobID)
	return &in, nil
}

// List returns incidents; open ones first, newest first.
func (s *Service) List(ctx context.Context, onlyOpen bool) ([]*Incident, error) {
	q := sel
	if onlyOpen {
		q += " WHERE r.status<>'resolved'"
	}
	rows, err := s.DB.QueryContext(ctx, q+" ORDER BY r.status='resolved', r.opened_at DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Incident{}
	for rows.Next() {
		in, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// Get returns one incident.
func (s *Service) Get(ctx context.Context, id string) (*Incident, error) {
	in, err := scan(s.DB.QueryRowContext(ctx, sel+" WHERE r.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return in, err
}

// OpenFor returns the first open incident whose job kind is in kinds.
func OpenFor(ctx context.Context, db *store.DB, kinds ...string) (*Incident, error) {
	for _, k := range kinds {
		in, err := scan(db.QueryRowContext(ctx, sel+" WHERE r.status<>'resolved' AND j.kind=? ORDER BY r.opened_at LIMIT 1", k))
		if err == nil {
			return in, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return nil, nil
}

// Resolve records the operator's supervised outcome. The job (if still in
// RecoveryRequired) moves to the state the operator attests.
func (s *Service) Resolve(ctx context.Context, id, actorID, outcome, note string) (*Incident, error) {
	var to jobs.State
	switch outcome {
	case "rolled_back":
		to = jobs.RolledBack
	case "failed":
		to = jobs.Failed
	case "succeeded":
		to = jobs.Succeeded
	default:
		return nil, ErrOutcome
	}
	if n := len([]rune(note)); n < 10 || n > 2000 {
		return nil, ErrNote
	}
	in, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Status == "resolved" {
		return nil, ErrResolved
	}
	if gatewayKinds[in.JobKind] {
		d, err := CurrentDrift(ctx, s.DB)
		if err != nil {
			return nil, err
		}
		if d != nil {
			return nil, fmt.Errorf("%w (serving %s, recorded %s): use reconcile (adopt or restore)", ErrDrift, d.Serving, d.Recorded)
		}
	}
	return s.resolve(ctx, in, actorID, to, outcome, note)
}

// ResolveVerified closes an incident after a job has proven the outcome
// (used by the reconcile job, which has just satisfied the drift check).
func (s *Service) ResolveVerified(ctx context.Context, id, actorID, outcome, note string) (*Incident, error) {
	to, ok := map[string]jobs.State{"rolled_back": jobs.RolledBack, "failed": jobs.Failed, "succeeded": jobs.Succeeded}[outcome]
	if !ok {
		return nil, ErrOutcome
	}
	in, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Status == "resolved" {
		return nil, ErrResolved
	}
	return s.resolve(ctx, in, actorID, to, outcome, note)
}

func (s *Service) resolve(ctx context.Context, in *Incident, actorID string, to jobs.State, outcome, note string) (*Incident, error) {
	id := in.ID
	now := time.Now().UTC()
	var by any
	if actorID != "" {
		by = actorID
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE recovery_incidents SET status='resolved', resolved_at=?, resolved_by=?, revision=revision+1 WHERE id=? AND revision=? AND status<>'resolved'",
		store.FormatTime(now), by, id, in.Revision)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrResolved
	}
	if in.JobID != "" && in.JobState == string(jobs.RecoveryRequired) {
		ev := map[string]any{"incident": id, "outcome": outcome, "note": note, "by": actorID}
		o := jobs.TransitionOpts{StepName: "operator_resolved", Evidence: ev}
		if to != jobs.Succeeded {
			o.Error = map[string]string{"code": "operator_resolved", "message": "resolved by operator: " + outcome}
		} else {
			o.Result = ev
		}
		if _, err := jobs.NewJournal(s.DB).Transition(ctx, in.JobID, jobs.RecoveryRequired, to, o); err != nil {
			return nil, fmt.Errorf("incident resolved but job transition failed: %w", err)
		}
	}
	if s.Audit != nil {
		_, _ = s.Audit.Record(ctx, audit.Event{ActorKind: "user", ActorID: actorID, Action: "recovery.resolve", TargetKind: "recovery_incident", TargetID: id,
			JobID: in.JobID, Result: "success", Context: map[string]any{"outcome": outcome, "note": note}})
	}
	return s.Get(ctx, id)
}
