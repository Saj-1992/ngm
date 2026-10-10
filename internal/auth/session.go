package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// SessionIssue carries freshly minted session secrets. Token and CSRF are
// returned to the client exactly once (as cookies) and stored only as hashes.
type SessionIssue struct {
	SessionID string
	Token     string
	CSRF      string
	Stage     string
	ExpiresAt time.Time
}

// ClientInfo describes the login request origin.
type ClientInfo struct {
	IP        string
	UserAgent string
	Secure    bool // issued over HTTPS (cookie Secure flag)
}

// ─── throttling ────────────────────────────────────────────────────────────

func (s *Service) throttleCheck(ctx context.Context, keys ...string) error {
	now := s.now()
	for _, k := range keys {
		var until sql.NullString
		err := s.db.QueryRowContext(ctx, "SELECT locked_until FROM login_throttle WHERE key=?", k).Scan(&until)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if until.Valid {
			t, _ := store.ParseTime(until.String)
			if now.Before(t) {
				return &ThrottledError{Until: t}
			}
		}
	}
	return nil
}

func (s *Service) throttleFail(ctx context.Context, tx *sql.Tx, key string, max int) error {
	now := s.now()
	var failures int
	var ws string
	err := tx.QueryRowContext(ctx, "SELECT failures, window_start FROM login_throttle WHERE key=?", key).Scan(&failures, &ws)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		failures, ws = 0, store.FormatTime(now)
	case err != nil:
		return err
	}
	start, _ := store.ParseTime(ws)
	if now.Sub(start) > s.policy.FailureWindow {
		failures, ws = 0, store.FormatTime(now)
	}
	failures++
	var until any
	if failures >= max {
		until = store.FormatTime(now.Add(s.policy.LockDuration))
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO login_throttle(key,failures,window_start,locked_until) VALUES(?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET failures=excluded.failures, window_start=excluded.window_start, locked_until=excluded.locked_until`,
		key, failures, ws, until)
	return err
}

// ─── login ─────────────────────────────────────────────────────────────────

// Login verifies a password and issues a session. The session is fully
// active only after MFA: its stage is pending_mfa (TOTP enrolled) or
// mfa_enroll (no TOTP yet; MFA is mandatory for every user).
func (s *Service) Login(ctx context.Context, username, password string, ci ClientInfo) (*SessionIssue, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	userKey, ipKey := "user:"+username, "ip:"+ci.IP
	if len(username) > 64 || len(password) > 1024 {
		return nil, ErrInvalidCredentials
	}
	if err := s.throttleCheck(ctx, userKey, ipKey); err != nil {
		s.auditLogin(ctx, "", username, ci, "denied", "throttled")
		return nil, err
	}
	var id, hash, status string
	var mfa int
	err := s.db.QueryRowContext(ctx, "SELECT id, password_hash, status, mfa_enabled FROM users WHERE username=?", username).Scan(&id, &hash, &status, &mfa)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = VerifyPassword(password, s.dummy) // equalise timing
		return nil, s.loginFailed(ctx, "", username, ci, userKey, ipKey)
	}
	if err != nil {
		return nil, err
	}
	ok, verr := VerifyPassword(password, hash)
	if verr != nil || !ok || status != "active" {
		return nil, s.loginFailed(ctx, id, username, ci, userKey, ipKey)
	}
	stage := "pending_mfa"
	if mfa == 0 {
		stage = "mfa_enroll"
	}
	var issue *SessionIssue
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM login_throttle WHERE key=?", userKey); err != nil {
			return err
		}
		var err error
		issue, err = s.createSessionTx(ctx, tx, id, stage, ci)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditLogin(ctx, id, username, ci, "success", "password_ok:"+stage)
	return issue, nil
}

func (s *Service) loginFailed(ctx context.Context, id, username string, ci ClientInfo, userKey, ipKey string) error {
	_ = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.throttleFail(ctx, tx, userKey, s.policy.UserMaxFailures); err != nil {
			return err
		}
		return s.throttleFail(ctx, tx, ipKey, s.policy.IPMaxFailures)
	})
	s.auditLogin(ctx, id, username, ci, "failure", "bad_credentials")
	return ErrInvalidCredentials
}

func (s *Service) auditLogin(ctx context.Context, id, username string, ci ClientInfo, result, reason string) {
	_, _ = s.audit.Record(ctx, audit.Event{ActorKind: "user", ActorID: id, Action: "auth.login", TargetKind: "user", TargetID: id, Result: result,
		RequestID: RequestIDFrom(ctx), Context: map[string]any{"username": username, "ip": ci.IP, "reason": reason}})
}

func (s *Service) createSessionTx(ctx context.Context, tx *sql.Tx, userID, stage string, ci ClientInfo) (*SessionIssue, error) {
	now := s.now()
	token, csrf := randomToken(32), randomToken(32)
	abs := now.Add(s.policy.AbsoluteTimeout)
	idle := now.Add(s.policy.IdleTimeout)
	if stage != "active" {
		abs = now.Add(s.policy.PendingTimeout)
		idle = abs
	}
	id := ids.New()
	secure := 0
	if ci.Secure {
		secure = 1
	}
	ua := ci.UserAgent
	if len(ua) > 256 {
		ua = ua[:256]
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,client_ip,user_agent,stage,secure)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, userID, HashToken(token), HashToken(csrf), store.FormatTime(now), store.FormatTime(now),
		store.FormatTime(idle), store.FormatTime(abs), ci.IP, ua, stage, secure)
	if err != nil {
		return nil, err
	}
	return &SessionIssue{SessionID: id, Token: token, CSRF: csrf, Stage: stage, ExpiresAt: abs}, nil
}

// rotateTx replaces a session with a new one at a new stage (session fixation
// defence on every privilege change), preserving its absolute deadline when
// moving between active states.
func (s *Service) rotateTx(ctx context.Context, tx *sql.Tx, old *Principal, stage string, ci ClientInfo, mfaAt *time.Time) (*SessionIssue, error) {
	now := store.FormatTime(s.now())
	if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE id=?", now, old.SessionID); err != nil {
		return nil, err
	}
	issue, err := s.createSessionTx(ctx, tx, old.UserID, stage, ci)
	if err != nil {
		return nil, err
	}
	if mfaAt != nil {
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET mfa_verified_at=? WHERE id=?", store.FormatTime(*mfaAt), issue.SessionID); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET last_login_at=? WHERE id=?", now, old.UserID); err != nil {
		return nil, err
	}
	return issue, nil
}

// ─── session authentication ────────────────────────────────────────────────

// AuthenticateSession resolves a session cookie. It extends the idle deadline
// (sliding, at most once a minute) and loads current permissions so that
// grant changes apply immediately.
func (s *Service) AuthenticateSession(ctx context.Context, token string) (*Principal, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrSessionInvalid
	}
	var (
		id, userID, stage, lastSeen, idleExp, absExp, username, locale, status string
		mfaAt, revoked                                                         sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `SELECT s.id, s.user_id, s.stage, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.mfa_verified_at, s.revoked_at,
		u.username, u.locale, u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, HashToken(token)).
		Scan(&id, &userID, &stage, &lastSeen, &idleExp, &absExp, &mfaAt, &revoked, &username, &locale, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	ie, _ := store.ParseTime(idleExp)
	ae, _ := store.ParseTime(absExp)
	if revoked.Valid || status != "active" || !now.Before(ie) || !now.Before(ae) {
		return nil, ErrSessionInvalid
	}
	ls, _ := store.ParseTime(lastSeen)
	if stage == "active" && now.Sub(ls) > time.Minute {
		nie := now.Add(s.policy.IdleTimeout)
		if nie.After(ae) {
			nie = ae
		}
		_, _ = s.db.ExecContext(ctx, "UPDATE sessions SET last_seen_at=?, idle_expires_at=? WHERE id=?", store.FormatTime(now), store.FormatTime(nie), id)
	}
	p := &Principal{Kind: "user", UserID: userID, Username: username, SessionID: id, Stage: stage, Locale: locale}
	if mfaAt.Valid {
		p.MFAVerifiedAt, _ = store.ParseTime(mfaAt.String)
	}
	p.Global, p.Scoped, err = effectivePerms(ctx, s.db, userID)
	return p, err
}

// CheckCSRF verifies a double-submit CSRF token against the session.
func (s *Service) CheckCSRF(ctx context.Context, sessionID, csrf string) bool {
	if csrf == "" || len(csrf) > 128 {
		return false
	}
	var h string
	if err := s.db.QueryRowContext(ctx, "SELECT csrf_hash FROM sessions WHERE id=?", sessionID).Scan(&h); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), []byte(HashToken(csrf))) == 1
}

// Logout revokes the session.
func (s *Service) Logout(ctx context.Context, p *Principal) error {
	if p == nil || p.SessionID == "" {
		return nil
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", store.FormatTime(s.now()), p.SessionID); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, p, "auth.logout", "session", p.SessionID, "success", nil)
	})
}

// PurgeExpiredSessions deletes sessions past their absolute deadline or revoked over a day ago.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)",
		store.FormatTime(now), store.FormatTime(now.Add(-24*time.Hour)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ─── MFA ───────────────────────────────────────────────────────────────────

func totpRef(userID, name string) vault.Ref {
	return vault.Ref{Type: "totp", Scope: "user:" + userID, Name: name}
}

// Enrollment is returned once when a user begins TOTP enrolment.
type Enrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

// BeginTOTPEnroll creates (or replaces) a pending TOTP secret. Only allowed in
// the mfa_enroll stage, so an attacker with a stolen password alone cannot
// replace an existing enrolment.
func (s *Service) BeginTOTPEnroll(ctx context.Context, p *Principal) (*Enrollment, error) {
	if p == nil || p.Kind != "user" || p.Stage != "mfa_enroll" {
		return nil, ErrWrongStage
	}
	// Idempotent while pending: a re-render, a second tab or a retry must not
	// silently invalidate the QR code the user is already scanning.
	if b, err := s.vault.Get(ctx, totpRef(p.UserID, "seed-pending")); err == nil {
		secret := string(b)
		clear(b)
		return &Enrollment{Secret: secret, URI: OTPAuthURI(s.policy.Issuer, p.Username, secret)}, nil
	} else if !errors.Is(err, vault.ErrNotFound) {
		return nil, err
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	if _, err := s.vault.Put(ctx, totpRef(p.UserID, "seed-pending"), []byte(secret)); err != nil {
		return nil, err
	}
	return &Enrollment{Secret: secret, URI: OTPAuthURI(s.policy.Issuer, p.Username, secret)}, nil
}

// ConfirmTOTPEnroll verifies the first code, activates MFA and upgrades the
// session (rotated) to active.
func (s *Service) ConfirmTOTPEnroll(ctx context.Context, p *Principal, code string, ci ClientInfo) (*SessionIssue, error) {
	if p == nil || p.Kind != "user" || p.Stage != "mfa_enroll" {
		return nil, ErrWrongStage
	}
	sec, err := s.vault.Get(ctx, totpRef(p.UserID, "seed-pending"))
	if errors.Is(err, vault.ErrNotFound) {
		return nil, ErrWrongStage
	}
	if err != nil {
		return nil, err
	}
	step, ok := VerifyTOTP(string(sec), code, s.now(), -1)
	if !ok {
		s.auditMFA(ctx, p, "auth.mfa_enroll", "failure")
		return nil, ErrInvalidCode
	}
	var issue *SessionIssue
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.vault.DeleteTx(ctx, tx, totpRef(p.UserID, "seed-pending")); err != nil {
			return err
		}
		sid, err := s.vault.PutTx(ctx, tx, totpRef(p.UserID, "seed"), sec)
		if err != nil {
			return err
		}
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO totp_secrets(user_id,vault_secret_id,confirmed_at,last_used_step) VALUES(?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET vault_secret_id=excluded.vault_secret_id, confirmed_at=excluded.confirmed_at, last_used_step=excluded.last_used_step`,
			p.UserID, sid, now, step); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE users SET mfa_enabled=1, revision=revision+1, updated_at=? WHERE id=?", now, p.UserID); err != nil {
			return err
		}
		t := s.now()
		issue, err = s.rotateTx(ctx, tx, p, "active", ci, &t)
		if err != nil {
			return err
		}
		return s.auditTx(ctx, tx, p, "auth.mfa_enroll", "user", p.UserID, "success", nil)
	})
	clear(sec)
	return issue, err
}

// verifyUserTOTP checks a code and advances the replay counter atomically.
func (s *Service) verifyUserTOTP(ctx context.Context, tx *sql.Tx, userID, code string) error {
	var last int64
	if err := tx.QueryRowContext(ctx, "SELECT last_used_step FROM totp_secrets WHERE user_id=? AND confirmed_at IS NOT NULL", userID).Scan(&last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWrongStage
		}
		return err
	}
	sec, err := s.vault.Get(ctx, totpRef(userID, "seed"))
	if err != nil {
		return err
	}
	defer clear(sec)
	step, ok := VerifyTOTP(string(sec), code, s.now(), last)
	if !ok {
		return ErrInvalidCode
	}
	res, err := tx.ExecContext(ctx, "UPDATE totp_secrets SET last_used_step=? WHERE user_id=? AND last_used_step=?", step, userID, last)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrInvalidCode // concurrent use of the same code
	}
	return nil
}

// VerifyMFA completes login for a pending_mfa session (rotating it to active).
func (s *Service) VerifyMFA(ctx context.Context, p *Principal, code string, ci ClientInfo) (*SessionIssue, error) {
	if p == nil || p.Kind != "user" || p.Stage != "pending_mfa" {
		return nil, ErrWrongStage
	}
	var issue *SessionIssue
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.verifyUserTOTP(ctx, tx, p.UserID, code); err != nil {
			return err
		}
		t := s.now()
		var err error
		issue, err = s.rotateTx(ctx, tx, p, "active", ci, &t)
		if err != nil {
			return err
		}
		return s.auditTx(ctx, tx, p, "auth.mfa_verify", "user", p.UserID, "success", nil)
	})
	if errors.Is(err, ErrInvalidCode) {
		s.auditMFA(ctx, p, "auth.mfa_verify", "failure")
		// Failed second factors count toward the same per-user lockout.
		_ = s.db.Tx(ctx, func(tx *sql.Tx) error { return s.throttleFail(ctx, tx, "user:"+p.Username, s.policy.UserMaxFailures) })
	}
	return issue, err
}

// StepUp re-verifies a TOTP code for an active session, authorising critical
// actions for StepUpWindow.
func (s *Service) StepUp(ctx context.Context, p *Principal, code string) (time.Time, error) {
	if p == nil || p.Kind != "user" || p.Stage != "active" {
		return time.Time{}, ErrWrongStage
	}
	if err := s.throttleCheck(ctx, "user:"+p.Username); err != nil {
		return time.Time{}, err
	}
	now := s.now()
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.verifyUserTOTP(ctx, tx, p.UserID, code); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET mfa_verified_at=? WHERE id=?", store.FormatTime(now), p.SessionID); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, p, "auth.step_up", "session", p.SessionID, "success", nil)
	})
	if errors.Is(err, ErrInvalidCode) {
		s.auditMFA(ctx, p, "auth.step_up", "failure")
		_ = s.db.Tx(ctx, func(tx *sql.Tx) error { return s.throttleFail(ctx, tx, "user:"+p.Username, s.policy.UserMaxFailures) })
	}
	return now, err
}

func (s *Service) auditMFA(ctx context.Context, p *Principal, action, result string) {
	_, _ = s.audit.Record(ctx, audit.Event{ActorKind: "user", ActorID: p.UserID, Action: action, TargetKind: "user", TargetID: p.UserID, Result: result, RequestID: RequestIDFrom(ctx)})
}
