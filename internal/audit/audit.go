// Package audit records tamper-evident audit events (DECISIONS ADR-007).
// Each row's hash covers the previous row's hash and the row's canonical
// content, so edits or deletions inside the chain are detectable by Verify.
// This is tamper-evident, not an immutable external ledger.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Genesis is the prev_hash of the first event.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is an audit record. Context must contain only minimal, non-secret data.
type Event struct {
	ID         string         `json:"id"`
	At         time.Time      `json:"at"`
	ActorKind  string         `json:"actor_kind"` // user | token | system | cli
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind"`
	TargetID   string         `json:"target_id"`
	Result     string         `json:"result"` // success | failure | denied
	RequestID  string         `json:"request_id"`
	JobID      string         `json:"job_id"`
	Context    map[string]any `json:"context"`
}

// Logger appends events.
type Logger struct {
	db  *store.DB
	now func() time.Time
}

// New returns a Logger.
func New(db *store.DB) *Logger { return &Logger{db: db, now: time.Now} }

// sensitiveKeys are refused in Context to keep secrets out of the audit log.
var sensitiveKeys = []string{"password", "secret", "token", "passphrase", "totp", "key", "authorization", "cookie"}

func checkContext(c map[string]any) error {
	for k := range c {
		lk := strings.ToLower(k)
		for _, s := range sensitiveKeys {
			if strings.Contains(lk, s) {
				return fmt.Errorf("audit context key %q looks sensitive; refusing", k)
			}
		}
	}
	return nil
}

func canonical(e *Event, ctxJSON string) string {
	// Field order is fixed; JSON-encode each field to avoid delimiter ambiguity.
	parts := []any{e.ID, store.FormatTime(e.At), e.ActorKind, e.ActorID, e.Action, e.TargetKind, e.TargetID, e.Result, e.RequestID, e.JobID, ctxJSON}
	b, _ := json.Marshal(parts)
	return string(b)
}

func chainHash(prev, canon string) string {
	h := sha256.Sum256([]byte(prev + "\n" + canon))
	return hex.EncodeToString(h[:])
}

// Record appends e. It may be called inside an existing transaction via RecordTx.
func (l *Logger) Record(ctx context.Context, e Event) (string, error) {
	var id string
	err := l.db.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = l.RecordTx(ctx, tx, e)
		return err
	})
	return id, err
}

// RecordTx appends e within tx so the audit row commits atomically with the change it describes.
func (l *Logger) RecordTx(ctx context.Context, tx *sql.Tx, e Event) (string, error) {
	if e.Action == "" || e.ActorKind == "" || e.Result == "" {
		return "", errors.New("audit: actor_kind, action and result are required")
	}
	if err := checkContext(e.Context); err != nil {
		return "", err
	}
	if e.ID == "" {
		e.ID = ids.New()
	}
	if e.At.IsZero() {
		e.At = l.now()
	}
	e.At = e.At.UTC()
	ctxJSON := "{}"
	if len(e.Context) > 0 {
		b, err := json.Marshal(e.Context)
		if err != nil {
			return "", err
		}
		ctxJSON = string(b)
	}
	prev := Genesis
	err := tx.QueryRowContext(ctx, "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	h := chainHash(prev, canonical(&e, ctxJSON))
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,at,actor_kind,actor_id,action,target_kind,target_id,result,request_id,job_id,context_json,prev_hash,hash)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, store.FormatTime(e.At), e.ActorKind, e.ActorID, e.Action, e.TargetKind, e.TargetID, e.Result, e.RequestID, e.JobID, ctxJSON, prev, h)
	return e.ID, err
}

// VerifyResult summarises a chain verification.
type VerifyResult struct {
	Events   int    `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at_seq,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Verify recomputes the full chain.
func (l *Logger) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq,id,at,actor_kind,actor_id,action,target_kind,target_id,result,request_id,job_id,context_json,prev_hash,hash
		FROM audit_events ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	res := VerifyResult{OK: true}
	prev := Genesis
	var lastSeq int64
	for rows.Next() {
		var e Event
		var seq int64
		var at, ctxJSON, p, h string
		if err := rows.Scan(&seq, &e.ID, &at, &e.ActorKind, &e.ActorID, &e.Action, &e.TargetKind, &e.TargetID, &e.Result, &e.RequestID, &e.JobID, &ctxJSON, &p, &h); err != nil {
			return res, err
		}
		res.Events++
		e.At, _ = store.ParseTime(at)
		if lastSeq != 0 && seq != lastSeq+1 && res.OK {
			// AUTOINCREMENT never reuses seq, so a gap means deletion.
			res.OK, res.BrokenAt, res.Reason = false, seq, "sequence gap (row deleted)"
		}
		lastSeq = seq
		if p != prev && res.OK {
			res.OK, res.BrokenAt, res.Reason = false, seq, "prev_hash mismatch"
		}
		if chainHash(p, canonical(&e, ctxJSON)) != h && res.OK {
			res.OK, res.BrokenAt, res.Reason = false, seq, "content hash mismatch"
		}
		prev = h
	}
	return res, rows.Err()
}
