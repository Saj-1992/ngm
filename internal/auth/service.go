// Package auth implements identity, sessions, MFA, API tokens, login
// throttling and RBAC (MASTER_SPEC §11, SECURITY_MODEL.md).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidCode        = errors.New("invalid or reused verification code")
	ErrNotFound           = errors.New("not found")
	ErrStale              = errors.New("revision changed")
	ErrConflict           = errors.New("conflict")
	ErrLastOwner          = errors.New("at least one active owner must remain")
	ErrEscalation         = errors.New("cannot grant or modify privileges you do not hold")
	ErrBuiltinRole        = errors.New("built-in roles cannot be modified")
	ErrSessionInvalid     = errors.New("session invalid or expired")
	ErrWrongStage         = errors.New("operation not allowed in this session stage")
	ErrAlreadyInitialized = errors.New("setup already completed")
)

// ThrottledError is returned while a login bucket is locked.
type ThrottledError struct{ Until time.Time }

func (e *ThrottledError) Error() string { return "too many failed attempts" }

// Policy holds tunable security parameters.
type Policy struct {
	Argon2          Argon2Params
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	PendingTimeout  time.Duration // pending_mfa / mfa_enroll sessions
	UserMaxFailures int
	IPMaxFailures   int
	FailureWindow   time.Duration
	LockDuration    time.Duration
	Issuer          string
}

// DefaultPolicy returns production defaults.
func DefaultPolicy() Policy {
	return Policy{
		Argon2:          DefaultArgon2,
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		PendingTimeout:  10 * time.Minute,
		UserMaxFailures: 5,
		IPMaxFailures:   20,
		FailureWindow:   15 * time.Minute,
		LockDuration:    15 * time.Minute,
		Issuer:          "NGM",
	}
}

// Service is the identity service.
type Service struct {
	db     *store.DB
	vault  *vault.Vault
	audit  *audit.Logger
	policy Policy
	now    func() time.Time
	dummy  string
}

// NewService constructs the service.
func NewService(db *store.DB, v *vault.Vault, a *audit.Logger, p Policy) *Service {
	s := &Service{db: db, vault: v, audit: a, policy: p, now: time.Now}
	// Hash used for unknown users so that response timing does not reveal
	// whether a username exists.
	s.dummy, _ = HashPassword("ngm-dummy-password-never-valid", p.Argon2)
	return s
}

// SetClock overrides the time source (tests).
func (s *Service) SetClock(f func() time.Time) { s.now = f }

// Policy returns the active policy.
func (s *Service) Policy() Policy { return s.policy }

// ─── built-in roles ─────────────────────────────────────────────────────────

// EnsureBuiltins (re)asserts built-in roles and their permissions.
func (s *Service) EnsureBuiltins(ctx context.Context) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		now := store.FormatTime(s.now())
		for _, b := range Builtins {
			if _, err := tx.ExecContext(ctx, `INSERT INTO roles(id,name,builtin,description,created_at,updated_at) VALUES(?,?,1,?,?,?)
				ON CONFLICT(id) DO UPDATE SET name=excluded.name, builtin=1, description=excluded.description`, b.ID, b.Name, b.Description, now, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id=?", b.ID); err != nil {
				return err
			}
			for _, p := range b.Permissions {
				if _, err := tx.ExecContext(ctx, "INSERT INTO role_permissions(role_id,permission) VALUES(?,?)", b.ID, p); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ─── users ──────────────────────────────────────────────────────────────────

// Grant binds a role to a user, globally or for one resource scope.
type Grant struct {
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name,omitempty"`
	ScopeKind string `json:"scope_kind"`
	ScopeID   string `json:"scope_id"`
}

// User is the client-safe user view (never includes hashes or secrets).
type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	Locale      string     `json:"locale"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	Revision    int64      `json:"revision"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Grants      []Grant    `json:"grants"`
}

var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

// ValidateUsername enforces lowercase ASCII usernames, 3–32 chars.
func ValidateUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return errors.New("username must be 3–32 chars: lowercase letters, digits, '.', '_' or '-', starting with a letter")
	}
	return nil
}

func validLocale(l string) bool { return l == "en" || l == "fa" }

// UserCount returns the number of users.
func (s *Service) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
	return n, err
}

// CreateUserInput describes a new user.
type CreateUserInput struct {
	Username    string
	DisplayName string
	Password    string
	Locale      string
	Grants      []Grant
}

func (s *Service) validateGrants(ctx context.Context, q queryer, gs []Grant) error {
	if len(gs) > 50 {
		return errors.New("too many grants")
	}
	for _, g := range gs {
		if g.ScopeKind == "" {
			g.ScopeKind = "global"
		}
		switch g.ScopeKind {
		case "global":
			if g.ScopeID != "" {
				return errors.New("global grants must not have a scope_id")
			}
		case "website", "route", "domain":
			if !ids.Valid(g.ScopeID) {
				return errors.New("scoped grants need a valid scope_id")
			}
		default:
			return fmt.Errorf("unknown scope_kind %q", g.ScopeKind)
		}
		var n int
		if err := q.QueryRowContext(ctx, "SELECT count(*) FROM roles WHERE id=?", g.RoleID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("unknown role %q", g.RoleID)
		}
	}
	return nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func rolePerms(ctx context.Context, q queryer, roleID string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, "SELECT permission FROM role_permissions WHERE role_id=?", roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		m[p] = true
	}
	return m, rows.Err()
}

// checkGrantable enforces that the actor holds every permission of every
// granted role (prevents privilege escalation). A nil actor means a trusted
// system context (installer/CLI).
func (s *Service) checkGrantable(ctx context.Context, q queryer, actor *Principal, gs []Grant) error {
	if actor == nil {
		return nil
	}
	for _, g := range gs {
		perms, err := rolePerms(ctx, q, g.RoleID)
		if err != nil {
			return err
		}
		for p := range perms {
			if !actor.Global[p] {
				return ErrEscalation
			}
		}
	}
	return nil
}

func insertGrants(ctx context.Context, tx *sql.Tx, userID string, gs []Grant, now string) error {
	for _, g := range gs {
		kind := g.ScopeKind
		if kind == "" {
			kind = "global"
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO permission_grants(id,user_id,role_id,scope_kind,scope_id,created_at) VALUES(?,?,?,?,?,?)",
			ids.New(), userID, g.RoleID, kind, g.ScopeID, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: duplicate grant", ErrConflict)
			}
			return err
		}
	}
	return nil
}

// CreateUser creates a user. actor nil = trusted system context.
func (s *Service) CreateUser(ctx context.Context, actor *Principal, in CreateUserInput) (*User, error) {
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if err := ValidateUsername(in.Username); err != nil {
		return nil, err
	}
	if in.Locale == "" {
		in.Locale = "en"
	}
	if !validLocale(in.Locale) {
		return nil, errors.New("locale must be en or fa")
	}
	if len(in.DisplayName) > 100 {
		return nil, errors.New("display name too long")
	}
	if err := CheckPasswordPolicy(in.Password, in.Username); err != nil {
		return nil, err
	}
	hash, err := HashPassword(in.Password, s.policy.Argon2)
	if err != nil {
		return nil, err
	}
	id := ids.New()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.validateGrants(ctx, tx, in.Grants); err != nil {
			return err
		}
		if err := s.checkGrantable(ctx, tx, actor, in.Grants); err != nil {
			return err
		}
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,locale,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, in.Username, in.DisplayName, hash, in.Locale, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: username already exists", ErrConflict)
			}
			return err
		}
		if err := insertGrants(ctx, tx, id, in.Grants, now); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "user.create", "user", id, "success", map[string]any{"username": in.Username, "grants": len(in.Grants)})
	})
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// BootstrapOwner creates the first user with the Owner role. It fails if any
// user already exists (checked inside the same transaction).
func (s *Service) BootstrapOwner(ctx context.Context, username, displayName, password, locale string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := CheckPasswordPolicy(password, username); err != nil {
		return nil, err
	}
	if locale == "" {
		locale = "en"
	}
	if !validLocale(locale) {
		return nil, errors.New("locale must be en or fa")
	}
	hash, err := HashPassword(password, s.policy.Argon2)
	if err != nil {
		return nil, err
	}
	id := ids.New()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadyInitialized
		}
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,locale,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, username, displayName, hash, locale, now, now); err != nil {
			return err
		}
		if err := insertGrants(ctx, tx, id, []Grant{{RoleID: RoleOwner, ScopeKind: "global"}}, now); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, nil, "setup.owner_create", "user", id, "success", map[string]any{"username": username})
	})
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

const userCols = "id,username,display_name,status,locale,mfa_enabled,last_login_at,revision,created_at,updated_at"

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var mfa int
	var last sql.NullString
	var c, up string
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Status, &u.Locale, &mfa, &last, &u.Revision, &c, &up); err != nil {
		return nil, err
	}
	u.MFAEnabled = mfa == 1
	if last.Valid {
		t, _ := store.ParseTime(last.String)
		u.LastLoginAt = &t
	}
	u.CreatedAt, _ = store.ParseTime(c)
	u.UpdatedAt, _ = store.ParseTime(up)
	return &u, nil
}

func (s *Service) grantsFor(ctx context.Context, q queryer, userID string) ([]Grant, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.role_id, r.name, g.scope_kind, g.scope_id FROM permission_grants g JOIN roles r ON r.id=g.role_id
		WHERE g.user_id=? ORDER BY r.name, g.scope_kind, g.scope_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.RoleID, &g.RoleName, &g.ScopeKind, &g.ScopeID); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetUser loads a user with grants.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Grants, err = s.grantsFor(ctx, s.db, id)
	return u, err
}

// ListUsers returns all users (V1 single gateway: user counts are small).
func (s *Service) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	for _, u := range out {
		if u.Grants, err = s.grantsFor(ctx, s.db, u.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// effectivePerms computes global and scoped permissions for a user.
func effectivePerms(ctx context.Context, q queryer, userID string) (map[string]bool, map[string]map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.scope_kind, g.scope_id, rp.permission FROM permission_grants g
		JOIN role_permissions rp ON rp.role_id=g.role_id WHERE g.user_id=?`, userID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	global := map[string]bool{}
	scoped := map[string]map[string]bool{}
	for rows.Next() {
		var kind, sid, perm string
		if err := rows.Scan(&kind, &sid, &perm); err != nil {
			return nil, nil, err
		}
		if kind == "global" {
			global[perm] = true
			continue
		}
		key := kind + ":" + sid
		if scoped[key] == nil {
			scoped[key] = map[string]bool{}
		}
		scoped[key][perm] = true
	}
	return global, scoped, rows.Err()
}

// targetGuard refuses changes to a user who holds permissions the actor lacks
// (e.g. an Admin editing an Owner).
func (s *Service) targetGuard(ctx context.Context, q queryer, actor *Principal, targetID string) error {
	if actor == nil {
		return nil
	}
	g, _, err := effectivePerms(ctx, q, targetID)
	if err != nil {
		return err
	}
	for p := range g {
		if !actor.Global[p] {
			return ErrEscalation
		}
	}
	return nil
}

// activeOwners counts active users holding a global Owner grant.
func activeOwners(ctx context.Context, q queryer) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(DISTINCT u.id) FROM users u JOIN permission_grants g ON g.user_id=u.id
		WHERE u.status='active' AND g.role_id=? AND g.scope_kind='global'`, RoleOwner).Scan(&n)
	return n, err
}

// UpdateUserInput holds optional changes.
type UpdateUserInput struct {
	DisplayName *string
	Status      *string
	Locale      *string
	Grants      *[]Grant
}

// UpdateUser applies changes with optimistic concurrency.
func (s *Service) UpdateUser(ctx context.Context, actor *Principal, id string, rev int64, in UpdateUserInput) (*User, error) {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM users WHERE id=?", id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if cur != rev {
			return ErrStale
		}
		if err := s.targetGuard(ctx, tx, actor, id); err != nil {
			return err
		}
		sets, args := []string{}, []any{}
		if in.DisplayName != nil {
			if len(*in.DisplayName) > 100 {
				return errors.New("display name too long")
			}
			sets, args = append(sets, "display_name=?"), append(args, *in.DisplayName)
		}
		if in.Locale != nil {
			if !validLocale(*in.Locale) {
				return errors.New("locale must be en or fa")
			}
			sets, args = append(sets, "locale=?"), append(args, *in.Locale)
		}
		if in.Status != nil {
			if *in.Status != "active" && *in.Status != "disabled" {
				return errors.New("status must be active or disabled")
			}
			if actor != nil && actor.UserID == id && *in.Status == "disabled" {
				return fmt.Errorf("%w: cannot disable yourself", ErrConflict)
			}
			sets, args = append(sets, "status=?"), append(args, *in.Status)
		}
		now := store.FormatTime(s.now())
		sets, args = append(sets, "revision=revision+1", "updated_at=?"), append(args, now)
		args = append(args, id)
		if _, err := tx.ExecContext(ctx, "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE id=?", args...); err != nil {
			return err
		}
		if in.Grants != nil {
			if err := s.validateGrants(ctx, tx, *in.Grants); err != nil {
				return err
			}
			if err := s.checkGrantable(ctx, tx, actor, *in.Grants); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM permission_grants WHERE user_id=?", id); err != nil {
				return err
			}
			if err := insertGrants(ctx, tx, id, *in.Grants, now); err != nil {
				return err
			}
		}
		if n, err := activeOwners(ctx, tx); err != nil {
			return err
		} else if n == 0 {
			return ErrLastOwner
		}
		if in.Status != nil && *in.Status == "disabled" {
			if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now, id); err != nil {
				return err
			}
		}
		if in.Grants != nil {
			// Privilege change: force re-authentication of existing sessions.
			if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND id<>?", now, id, sessionOf(actor)); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, actor, "user.update", "user", id, "success", map[string]any{
			"status_changed": in.Status != nil, "grants_changed": in.Grants != nil, "locale_changed": in.Locale != nil})
	})
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

func sessionOf(p *Principal) string {
	if p == nil {
		return ""
	}
	return p.SessionID
}

// DeleteUser removes a user (not yourself, not the last owner).
func (s *Service) DeleteUser(ctx context.Context, actor *Principal, id string, rev int64) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM users WHERE id=?", id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if cur != rev {
			return ErrStale
		}
		if actor != nil && actor.UserID == id {
			return fmt.Errorf("%w: cannot delete yourself", ErrConflict)
		}
		if err := s.targetGuard(ctx, tx, actor, id); err != nil {
			return err
		}
		if err := s.deleteUserSecretsTx(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id=?", id); err != nil {
			return err
		}
		if n, err := activeOwners(ctx, tx); err != nil {
			return err
		} else if n == 0 {
			return ErrLastOwner
		}
		return s.auditTx(ctx, tx, actor, "user.delete", "user", id, "success", nil)
	})
}

func (s *Service) deleteUserSecretsTx(ctx context.Context, tx *sql.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM totp_secrets WHERE user_id=?", userID); err != nil {
		return err
	}
	for _, name := range []string{"seed", "seed-pending"} {
		if err := s.vault.DeleteTx(ctx, tx, vault.Ref{Type: "totp", Scope: "user:" + userID, Name: name}); err != nil {
			return err
		}
	}
	return nil
}

// ChangePassword changes the caller's own password after verifying the current one.
func (s *Service) ChangePassword(ctx context.Context, actor *Principal, current, next string) error {
	if actor == nil || actor.Kind != "user" {
		return ErrWrongStage
	}
	var hash, username string
	if err := s.db.QueryRowContext(ctx, "SELECT password_hash, username FROM users WHERE id=?", actor.UserID).Scan(&hash, &username); err != nil {
		return err
	}
	ok, err := VerifyPassword(current, hash)
	if err != nil || !ok {
		_, _ = s.audit.Record(ctx, audit.Event{ActorKind: "user", ActorID: actor.UserID, Action: "user.password_change", TargetKind: "user", TargetID: actor.UserID, Result: "failure"})
		return ErrInvalidCredentials
	}
	if err := CheckPasswordPolicy(next, username); err != nil {
		return err
	}
	nh, err := HashPassword(next, s.policy.Argon2)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash=?, revision=revision+1, updated_at=? WHERE id=?", nh, now, actor.UserID); err != nil {
			return err
		}
		// Revoke every other session of this user.
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at IS NULL", now, actor.UserID, actor.SessionID); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "user.password_change", "user", actor.UserID, "success", nil)
	})
}

// AdminReset is the host-local recovery path (`ngm admin reset`): it sets a
// new password for username, clears its MFA enrolment (forcing re-enrolment at
// next login), re-enables the account, clears throttling and revokes all of
// its sessions.
func (s *Service) AdminReset(ctx context.Context, username, newPassword string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if err := CheckPasswordPolicy(newPassword, username); err != nil {
		return err
	}
	nh, err := HashPassword(newPassword, s.policy.Argon2)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username=?", username).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash=?, mfa_enabled=0, status='active', failed_logins=0, locked_until=NULL, revision=revision+1, updated_at=? WHERE id=?", nh, now, id); err != nil {
			return err
		}
		if err := s.deleteUserSecretsTx(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM login_throttle WHERE key=?", "user:"+username); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, nil, "admin.reset", "user", id, "success", map[string]any{"via": "cli"})
	})
}

// ResetMFA clears another user's MFA enrolment (they must re-enrol on next login).
func (s *Service) ResetMFA(ctx context.Context, actor *Principal, id string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.targetGuard(ctx, tx, actor, id); err != nil {
			return err
		}
		now := store.FormatTime(s.now())
		res, err := tx.ExecContext(ctx, "UPDATE users SET mfa_enabled=0, revision=revision+1, updated_at=? WHERE id=?", now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if err := s.deleteUserSecretsTx(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now, id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "user.mfa_reset", "user", id, "success", nil)
	})
}

// ─── audit helper ──────────────────────────────────────────────────────────

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor *Principal, action, tk, tid, result string, c map[string]any) error {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: tk, TargetID: tid, Result: result, Context: c, RequestID: RequestIDFrom(ctx)}
	if actor != nil {
		e.ActorKind, e.ActorID = actor.Kind, actor.UserID
		if actor.Kind == "local" {
			e.ActorKind = "cli"
		}
	}
	_, err := s.audit.RecordTx(ctx, tx, e)
	return err
}

type reqIDKey struct{}

// WithRequestID binds a request ID for audit correlation.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, reqIDKey{}, id)
}

// RequestIDFrom returns the bound request ID.
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(reqIDKey{}).(string)
	return s
}

// ─── helpers ───────────────────────────────────────────────────────────────

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the hex SHA-256 of a high-entropy token.
func HashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func marshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
