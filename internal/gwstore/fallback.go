package gwstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/store"
)

// FallbackKey is the settings key of the fallback website (ADR-036).
const FallbackKey = "gateway.fallback"

// Fallback is the website served to every request that matches no route.
type Fallback struct {
	WebsiteID     string `json:"website_id"`
	CertificateID string `json:"certificate_id"`
}

// Enabled reports whether both parts are set.
func (f Fallback) Enabled() bool { return f.WebsiteID != "" && f.CertificateID != "" }

// GetFallback returns the stored setting (zero value when unset).
func GetFallback(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) Fallback {
	var v string
	var f Fallback
	if err := q.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", FallbackKey).Scan(&v); err == nil {
		_ = json.Unmarshal([]byte(v), &f)
	}
	return f
}

// ErrFallbackInvalid is returned for an unusable fallback choice.
var ErrFallbackInvalid = errors.New("invalid fallback website")

// SetFallback validates and stores the fallback. An empty value disables it.
// The website must have a published version and the certificate must be
// valid with a key; the change reaches Nginx with the next deployment.
func (s *Service) SetFallback(ctx context.Context, actor *auth.Principal, f Fallback) error {
	if (f.WebsiteID == "") != (f.CertificateID == "") {
		return fmt.Errorf("%w: choose both a website and a certificate, or neither", ErrFallbackInvalid)
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if f.Enabled() {
			var pub int
			_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM website_versions WHERE website_id=? AND published_at IS NOT NULL", f.WebsiteID).Scan(&pub)
			if pub == 0 {
				return fmt.Errorf("%w: the website has no published version", ErrFallbackInvalid)
			}
			var notAfter sql.NullString
			var key sql.NullString
			if err := tx.QueryRowContext(ctx, "SELECT not_after, key_secret_id FROM certificates WHERE id=?", f.CertificateID).Scan(&notAfter, &key); err != nil {
				return fmt.Errorf("%w: unknown certificate", ErrFallbackInvalid)
			}
			if !key.Valid {
				return fmt.Errorf("%w: the certificate has no private key", ErrFallbackInvalid)
			}
			if t, err := store.ParseTime(notAfter.String); err != nil || !t.After(time.Now()) {
				return fmt.Errorf("%w: the certificate is expired", ErrFallbackInvalid)
			}
		}
		b, _ := json.Marshal(f)
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, revision=revision+1, updated_at=excluded.updated_at`, FallbackKey, string(b), store.FormatTime(time.Now())); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "gateway.fallback.update", "settings", FallbackKey, map[string]any{"website_id": f.WebsiteID, "certificate_id": f.CertificateID})
	})
}
