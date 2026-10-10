package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

// BaselineKey is the settings key of the accepted Nginx package/module state.
const BaselineKey = "nginx.baseline"

// NginxBaseline is the Nginx state NGM last verified (installer, coordinated
// upgrade or `ngm nginx reconcile`). A different observation means Nginx was
// changed outside NGM, e.g. by unattended-upgrades: detected, not prevented.
type NginxBaseline struct {
	Version        string    `json:"version"`
	PackageVersion string    `json:"package_version"`
	StreamModule   bool      `json:"stream_module"`
	SSLPreread     bool      `json:"ssl_preread"`
	SetAt          time.Time `json:"set_at"`
	SetBy          string    `json:"set_by"`
}

// BaselineFrom builds a baseline from an observation.
func BaselineFrom(n observe.Nginx, by string) NginxBaseline {
	return NginxBaseline{Version: n.Version, PackageVersion: n.PackageVersion, StreamModule: n.StreamModule, SSLPreread: n.SSLPreread, SetAt: time.Now().UTC(), SetBy: by}
}

// LoadBaseline returns nil when none is recorded.
func LoadBaseline(ctx context.Context, db *store.DB) (*NginxBaseline, error) {
	var v string
	err := db.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", BaselineKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b NginxBaseline
	return &b, json.Unmarshal([]byte(v), &b)
}

// SaveBaseline records b as the accepted state.
func SaveBaseline(ctx context.Context, db *store.DB, b NginxBaseline) error {
	j, _ := json.Marshal(b)
	_, err := db.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, revision=revision+1, updated_at=excluded.updated_at`, BaselineKey, string(j), store.FormatTime(time.Now()))
	return err
}

// Drift describes how n differs from b ("" when equal).
func Drift(b NginxBaseline, n observe.Nginx) (msg string, critical bool) {
	switch {
	case b.StreamModule && !n.StreamModule:
		return "the Nginx stream module is no longer available (TCP/UDP and TLS passthrough routes are affected)", true
	case b.SSLPreread && !n.SSLPreread:
		return "ssl_preread is no longer available (shared-443 passthrough is affected)", true
	case b.PackageVersion != n.PackageVersion || b.Version != n.Version:
		return fmt.Sprintf("Nginx changed outside NGM: %s (%s) → %s (%s); run `ngm nginx reconcile`", b.Version, b.PackageVersion, n.Version, n.PackageVersion), false
	case !b.StreamModule && n.StreamModule:
		return "the Nginx stream module appeared outside NGM; run `ngm nginx reconcile`", false
	}
	return "", false
}

// nginxDrift records a first baseline or reports drift against it.
func nginxDrift(ctx context.Context, db *store.DB, n observe.Nginx, add func(rule, subject, sev, msg string, d map[string]any)) {
	if !n.Installed || n.Version == "" {
		return
	}
	b, err := LoadBaseline(ctx, db)
	if err != nil {
		return
	}
	if b == nil {
		_ = SaveBaseline(ctx, db, BaselineFrom(n, "first-observation"))
		return
	}
	if msg, crit := Drift(*b, n); msg != "" {
		sev := "warning"
		if crit {
			sev = "critical"
		}
		add("nginx_external_change", "nginx", sev, msg, map[string]any{"baseline": b.PackageVersion, "observed": n.PackageVersion})
	}
}
