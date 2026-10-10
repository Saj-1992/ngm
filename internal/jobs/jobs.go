// Package jobs is the durable job journal and Safe Apply state machine
// (MASTER_SPEC §8.1, DEPLOYMENT_CONTRACT.md). SQLite is the source of truth.
package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

// State is a job lifecycle state.
type State string

const (
	Queued           State = "Queued"
	Validating       State = "Validating"
	ImpactAnalyzed   State = "ImpactAnalyzed"
	Staging          State = "Staging"
	Preflight        State = "Preflight"
	Applying         State = "Applying"
	Verifying        State = "Verifying"
	Succeeded        State = "Succeeded"
	Blocked          State = "Blocked"
	Failed           State = "Failed"
	Compensating     State = "Compensating"
	RolledBack       State = "RolledBack"
	RecoveryRequired State = "RecoveryRequired"
	Cancelled        State = "Cancelled"
)

var transitions = map[State][]State{
	Queued:         {Validating, Blocked, Failed, Cancelled},
	Validating:     {ImpactAnalyzed, Blocked, Failed, Cancelled},
	ImpactAnalyzed: {Staging, Blocked, Failed, Cancelled},
	Staging:        {Preflight, Blocked, Failed, Cancelled},
	Preflight:      {Applying, Blocked, Failed, Cancelled},
	Applying:       {Verifying, Compensating, RecoveryRequired},
	Verifying:      {Succeeded, Compensating, RecoveryRequired},
	Compensating:   {RolledBack, RecoveryRequired},
	// RecoveryRequired is resolved only by a supervised operator action.
	RecoveryRequired: {RolledBack, Failed, Succeeded},
}

// ValidTransition reports whether from -> to is allowed.
func ValidTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Terminal reports whether no automatic transition leaves s.
func (s State) Terminal() bool {
	switch s {
	case Succeeded, Blocked, Failed, RolledBack, Cancelled:
		return true
	}
	return false
}

// Cancellable reports whether s is at or before a safe cancellation boundary
// (no external side effects have been made).
func (s State) Cancellable() bool {
	switch s {
	case Queued, Validating, ImpactAnalyzed, Staging, Preflight:
		return true
	}
	return false
}

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	if s.Terminal() {
		return true
	}
	_, ok := transitions[s]
	return ok
}

// StepClass marks whether a step may be safely re-run after a crash.
type StepClass string

const (
	Idempotent StepClass = "idempotent"
	External   StepClass = "external"
)

// Job is a persisted job row.
type Job struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	State          State           `json:"state"`
	ActorID        string          `json:"actor_id,omitempty"`
	RequestID      string          `json:"request_id,omitempty"`
	IdempotencyKey string          `json:"-"`
	BaseRevision   *int64          `json:"base_revision,omitempty"`
	LockSet        []string        `json:"lock_set"`
	Payload        json.RawMessage `json:"payload"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          json.RawMessage `json:"error,omitempty"`
	Attempts       int             `json:"attempts"`
	Revision       int64           `json:"revision"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
}

// Step is one journaled step of a job.
type Step struct {
	ID           string          `json:"id"`
	Seq          int             `json:"seq"`
	Name         string          `json:"name"`
	FromState    State           `json:"from_state,omitempty"`
	ToState      State           `json:"to_state,omitempty"`
	Class        StepClass       `json:"class"`
	Status       string          `json:"status"`
	FencingToken *int64          `json:"fencing_token,omitempty"`
	Evidence     json.RawMessage `json:"evidence"`
	StartedAt    time.Time       `json:"started_at"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
}

var (
	ErrNotFound          = errors.New("job not found")
	ErrInvalidTransition = errors.New("invalid job state transition")
	ErrStaleRevision     = errors.New("job revision changed concurrently")
	ErrNotCancellable    = errors.New("job is past its safe cancellation boundary")
)

// Journal persists jobs and steps.
type Journal struct {
	db  *store.DB
	now func() time.Time
}

// NewJournal returns a Journal using db.
func NewJournal(db *store.DB) *Journal { return &Journal{db: db, now: time.Now} }

// SubmitRequest describes a new job.
type SubmitRequest struct {
	Kind           string
	ActorID        string
	RequestID      string
	IdempotencyKey string
	BaseRevision   *int64
	LockSet        []string
	Payload        any
}

// Submit inserts a Queued job. If an idempotency key is given and a job with
// the same (actor, kind, key) exists, the existing job is returned with
// created=false; the caller must compare payloads if it needs strictness.
func (j *Journal) Submit(ctx context.Context, r SubmitRequest) (job *Job, created bool, err error) {
	if r.Kind == "" {
		return nil, false, errors.New("job kind required")
	}
	payload, err := json.Marshal(r.Payload)
	if err != nil {
		return nil, false, fmt.Errorf("encode payload: %w", err)
	}
	if r.Payload == nil {
		payload = []byte("{}")
	}
	locks, _ := json.Marshal(nonNil(r.LockSet))
	err = j.db.Tx(ctx, func(tx *sql.Tx) error {
		if r.IdempotencyKey != "" {
			var id string
			err := tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE actor_id IS ? AND kind=? AND idempotency_key=?`,
				nullStr(r.ActorID), r.Kind, r.IdempotencyKey).Scan(&id)
			if err == nil {
				job, err = getTx(ctx, tx, id)
				return err
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		now := store.FormatTime(j.now())
		id := ids.New()
		_, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,kind,state,actor_id,request_id,idempotency_key,base_revision,lock_set_json,payload_json,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			id, r.Kind, string(Queued), nullStr(r.ActorID), nullStr(r.RequestID), nullStr(r.IdempotencyKey), r.BaseRevision, string(locks), string(payload), now, now)
		if err != nil {
			return err
		}
		created = true
		job, err = getTx(ctx, tx, id)
		return err
	})
	return job, created, err
}

// Get loads a job by ID.
func (j *Journal) Get(ctx context.Context, id string) (*Job, error) {
	return getTx(ctx, j.db, id)
}

type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

const jobCols = `id,kind,state,actor_id,request_id,idempotency_key,base_revision,lock_set_json,payload_json,result_json,error_json,attempts,revision,created_at,updated_at,started_at,finished_at`

func scanJob(sc interface{ Scan(...any) error }) (*Job, error) {
	var (
		jb                                  Job
		actor, req, idem, res, errj         sql.NullString
		started, finished                   sql.NullString
		base                                sql.NullInt64
		locks, payload, created, updated, s string
	)
	if err := sc.Scan(&jb.ID, &jb.Kind, &s, &actor, &req, &idem, &base, &locks, &payload, &res, &errj,
		&jb.Attempts, &jb.Revision, &created, &updated, &started, &finished); err != nil {
		return nil, err
	}
	jb.State = State(s)
	jb.ActorID, jb.RequestID, jb.IdempotencyKey = actor.String, req.String, idem.String
	if base.Valid {
		v := base.Int64
		jb.BaseRevision = &v
	}
	_ = json.Unmarshal([]byte(locks), &jb.LockSet)
	jb.Payload = json.RawMessage(payload)
	if res.Valid {
		jb.Result = json.RawMessage(res.String)
	}
	if errj.Valid {
		jb.Error = json.RawMessage(errj.String)
	}
	jb.CreatedAt, _ = store.ParseTime(created)
	jb.UpdatedAt, _ = store.ParseTime(updated)
	jb.StartedAt = parseOpt(started)
	jb.FinishedAt = parseOpt(finished)
	return &jb, nil
}

func getTx(ctx context.Context, q querier, id string) (*Job, error) {
	jb, err := scanJob(q.QueryRowContext(ctx, "SELECT "+jobCols+" FROM jobs WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return jb, err
}

// ListFilter selects jobs for List.
type ListFilter struct {
	State  State
	Kind   string
	Limit  int
	Before string // cursor: return jobs with id < Before (newest first)
}

// List returns jobs newest-first with keyset pagination.
func (j *Journal) List(ctx context.Context, f ListFilter) ([]*Job, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	q := "SELECT " + jobCols + " FROM jobs WHERE 1=1"
	var args []any
	if f.State != "" {
		q += " AND state=?"
		args = append(args, string(f.State))
	}
	if f.Kind != "" {
		q += " AND kind=?"
		args = append(args, f.Kind)
	}
	if f.Before != "" {
		q += " AND id<?"
		args = append(args, f.Before)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := j.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		jb, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, jb)
	}
	return out, rows.Err()
}

// TransitionOpts carries the step record written with a transition.
type TransitionOpts struct {
	StepName     string
	Class        StepClass
	FencingToken *int64
	Evidence     any
	Result       any // set on terminal success
	Error        any // set on failure states
	// Fence, if non-nil, is called inside the transaction and must return an
	// error if the caller no longer holds authority (see locks.CheckFence).
	Fence func(ctx context.Context, tx *sql.Tx) error
}

// Transition moves job id from `from` to `to`, journaling a completed step,
// guarded by the expected current state (compare-and-swap).
func (j *Journal) Transition(ctx context.Context, id string, from, to State, o TransitionOpts) (*Job, error) {
	if !ValidTransition(from, to) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	if o.Class == "" {
		o.Class = Idempotent
	}
	if o.StepName == "" {
		o.StepName = string(to)
	}
	ev, err := json.Marshal(o.Evidence)
	if err != nil || o.Evidence == nil {
		ev = []byte("{}")
	}
	var job *Job
	err = j.db.Tx(ctx, func(tx *sql.Tx) error {
		if o.Fence != nil {
			if err := o.Fence(ctx, tx); err != nil {
				return err
			}
		}
		now := store.FormatTime(j.now())
		set := "state=?, updated_at=?, revision=revision+1"
		args := []any{string(to), now}
		if from == Queued {
			set += ", started_at=COALESCE(started_at, ?), attempts=attempts+1"
			args = append(args, now)
		}
		if to.Terminal() {
			set += ", finished_at=?"
			args = append(args, now)
		}
		if o.Result != nil {
			b, err := json.Marshal(o.Result)
			if err != nil {
				return err
			}
			set += ", result_json=?"
			args = append(args, string(b))
		}
		if o.Error != nil {
			b, err := json.Marshal(o.Error)
			if err != nil {
				return err
			}
			set += ", error_json=?"
			args = append(args, string(b))
		}
		args = append(args, id, string(from))
		res, err := tx.ExecContext(ctx, "UPDATE jobs SET "+set+" WHERE id=? AND state=?", args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			if _, err := getTx(ctx, tx, id); errors.Is(err, ErrNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("%w: expected state %s", ErrStaleRevision, from)
		}
		var seq int
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(seq),0)+1 FROM job_steps WHERE job_id=?", id).Scan(&seq); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_steps(id,job_id,seq,name,from_state,to_state,step_class,status,fencing_token,evidence_json,started_at,finished_at)
			VALUES(?,?,?,?,?,?,?,'completed',?,?,?,?)`,
			ids.New(), id, seq, o.StepName, string(from), string(to), string(o.Class), o.FencingToken, string(ev), now, now); err != nil {
			return err
		}
		job, err = getTx(ctx, tx, id)
		return err
	})
	return job, err
}

// Cancel cancels a job that has not passed its safe cancellation boundary.
func (j *Journal) Cancel(ctx context.Context, id, actor string) (*Job, error) {
	cur, err := j.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !cur.State.Cancellable() {
		return nil, ErrNotCancellable
	}
	return j.Transition(ctx, id, cur.State, Cancelled, TransitionOpts{StepName: "cancel", Evidence: map[string]string{"actor": actor}})
}

// BeginStep records the start of an external-effect step so crash
// reconciliation can see that a side effect may have happened.
func (j *Journal) BeginStep(ctx context.Context, jobID, name string, class StepClass, fencing *int64) (stepID string, err error) {
	err = j.db.Tx(ctx, func(tx *sql.Tx) error {
		var seq int
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(seq),0)+1 FROM job_steps WHERE job_id=?", jobID).Scan(&seq); err != nil {
			return err
		}
		stepID = ids.New()
		_, err := tx.ExecContext(ctx, `INSERT INTO job_steps(id,job_id,seq,name,step_class,status,fencing_token,started_at) VALUES(?,?,?,?,?,'started',?,?)`,
			stepID, jobID, seq, name, string(class), fencing, store.FormatTime(j.now()))
		return err
	})
	return stepID, err
}

// FinishStep closes a step started with BeginStep.
func (j *Journal) FinishStep(ctx context.Context, stepID, status string, evidence any) error {
	switch status {
	case "completed", "failed", "compensated":
	default:
		return fmt.Errorf("invalid step status %q", status)
	}
	ev, err := json.Marshal(evidence)
	if err != nil || evidence == nil {
		ev = []byte("{}")
	}
	res, err := j.db.ExecContext(ctx, `UPDATE job_steps SET status=?, evidence_json=?, finished_at=? WHERE id=? AND status='started'`,
		status, string(ev), store.FormatTime(j.now()), stepID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("step %s not open", stepID)
	}
	return nil
}

// Steps returns the journal for a job in order.
func (j *Journal) Steps(ctx context.Context, jobID string) ([]Step, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT id,seq,name,from_state,to_state,step_class,status,fencing_token,evidence_json,started_at,finished_at
		FROM job_steps WHERE job_id=? ORDER BY seq`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var s Step
		var from, to, fin sql.NullString
		var fence sql.NullInt64
		var class, ev, started string
		if err := rows.Scan(&s.ID, &s.Seq, &s.Name, &from, &to, &class, &s.Status, &fence, &ev, &started, &fin); err != nil {
			return nil, err
		}
		s.FromState, s.ToState, s.Class = State(from.String), State(to.String), StepClass(class)
		if fence.Valid {
			v := fence.Int64
			s.FencingToken = &v
		}
		s.Evidence = json.RawMessage(ev)
		s.StartedAt, _ = store.ParseTime(started)
		s.FinishedAt = parseOpt(fin)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Unfinished returns non-terminal jobs, oldest first, for startup reconciliation.
func (j *Journal) Unfinished(ctx context.Context) ([]*Job, error) {
	rows, err := j.db.QueryContext(ctx, "SELECT "+jobCols+` FROM jobs
		WHERE state NOT IN ('Succeeded','Blocked','Failed','RolledBack','Cancelled') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		jb, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, jb)
	}
	return out, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func parseOpt(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t, err := store.ParseTime(s.String)
	if err != nil {
		return nil
	}
	return &t
}
