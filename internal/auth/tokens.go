package auth

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

// TokenPrefix marks NGM API tokens (helps secret scanners).
const TokenPrefix = "ngm_"

// APIToken is the client-safe token view.
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreatedToken includes the plaintext, shown exactly once.
type CreatedToken struct {
	APIToken
	Token string `json:"token"`
}

// CreateToken issues a scoped bearer token for the actor. Scopes must be a
// subset of the actor's current global permissions and may not include
// step-up permissions (a token cannot present a fresh second factor).
func (s *Service) CreateToken(ctx context.Context, actor *Principal, name string, scopes []string, ttl time.Duration) (*CreatedToken, error) {
	if actor == nil || actor.Kind != "user" {
		return nil, ErrWrongStage
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return nil, errors.New("token name is required (max 64 chars)")
	}
	if len(scopes) == 0 || len(scopes) > len(Catalog) {
		return nil, errors.New("at least one scope is required")
	}
	seen := map[string]bool{}
	for _, sc := range scopes {
		if !KnownPermission(sc) {
			return nil, fmt.Errorf("unknown scope %q", sc)
		}
		if StepUp[sc] {
			return nil, fmt.Errorf("scope %q requires interactive MFA and cannot be granted to a token", sc)
		}
		if !actor.Global[sc] {
			return nil, ErrEscalation
		}
		seen[sc] = true
	}
	if ttl < 0 || ttl > 366*24*time.Hour {
		return nil, errors.New("token lifetime must be at most 366 days")
	}
	scopes = sorted(keys(seen))
	secret := randomToken(32)
	plain := TokenPrefix + secret
	t := &CreatedToken{Token: plain}
	t.ID, t.Name, t.Prefix, t.Scopes, t.CreatedAt = ids.New(), name, TokenPrefix+secret[:6], scopes, s.now().UTC()
	var exp any
	if ttl > 0 {
		e := s.now().Add(ttl).UTC()
		t.ExpiresAt, exp = &e, store.FormatTime(e)
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(id,user_id,name,token_hash,prefix,scopes_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			t.ID, actor.UserID, name, HashToken(plain), t.Prefix, marshal(scopes), exp, store.FormatTime(t.CreatedAt)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "token.create", "api_token", t.ID, "success", map[string]any{"name": name, "scopes": scopes})
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ListTokens lists the user's tokens.
func (s *Service) ListTokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,prefix,scopes_json,expires_at,last_used_at,revoked_at,created_at FROM api_tokens WHERE user_id=? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		var sc, c string
		var exp, used, rev sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &sc, &exp, &used, &rev, &c); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sc), &t.Scopes)
		t.ExpiresAt, t.LastUsedAt, t.RevokedAt = optTime(exp), optTime(used), optTime(rev)
		t.CreatedAt, _ = store.ParseTime(c)
		out = append(out, t)
	}
	return out, rows.Err()
}

func optTime(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t, err := store.ParseTime(s.String)
	if err != nil {
		return nil
	}
	return &t
}

// RevokeToken revokes one of the actor's tokens.
func (s *Service) RevokeToken(ctx context.Context, actor *Principal, id string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL", store.FormatTime(s.now()), id, actor.UserID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.auditTx(ctx, tx, actor, "token.revoke", "api_token", id, "success", nil)
	})
}

// AuthenticateToken resolves a bearer token. Effective permissions are the
// intersection of the token scopes and the owner's current global
// permissions, minus step-up permissions.
func (s *Service) AuthenticateToken(ctx context.Context, bearer string) (*Principal, error) {
	if !strings.HasPrefix(bearer, TokenPrefix) || len(bearer) > 128 {
		return nil, ErrSessionInvalid
	}
	var id, userID, sc, username, status, locale string
	var exp, rev sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT t.id, t.user_id, t.scopes_json, t.expires_at, t.revoked_at, u.username, u.status, u.locale
		FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`, HashToken(bearer)).Scan(&id, &userID, &sc, &exp, &rev, &username, &status, &locale)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if rev.Valid || status != "active" {
		return nil, ErrSessionInvalid
	}
	if e := optTime(exp); e != nil && !now.Before(*e) {
		return nil, ErrSessionInvalid
	}
	var scopes []string
	_ = json.Unmarshal([]byte(sc), &scopes)
	g, _, err := effectivePerms(ctx, s.db, userID)
	if err != nil {
		return nil, err
	}
	eff := map[string]bool{}
	for _, p := range scopes {
		if g[p] && !StepUp[p] {
			eff[p] = true
		}
	}
	_, _ = s.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at=? WHERE id=?", store.FormatTime(now), id)
	return &Principal{Kind: "token", UserID: userID, Username: username, TokenID: id, Stage: "active", Global: eff, Scoped: map[string]map[string]bool{}, Locale: locale}, nil
}
