// Package observe stores and reads runtime observations (MASTER_SPEC §7.2
// "Runtime") and service heartbeats. Observations are evidence with a
// timestamp; consumers must treat missing or stale evidence as Unknown.
package observe

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Nginx is the observed data-plane state, collected by ngm-helper.
type Nginx struct {
	Installed      bool     `json:"installed"`
	Version        string   `json:"version,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
	PackageOrigin  string   `json:"package_origin,omitempty"` // "ubuntu" | "other" | "unknown"
	ServiceState   string   `json:"service_state"`            // systemd ActiveState: active|inactive|failed|activating|...|unknown
	MainPID        int      `json:"main_pid,omitempty"`
	StreamModule   bool     `json:"stream_module"`
	HTTPV2         bool     `json:"http_v2"`
	SSLPreread     bool     `json:"ssl_preread"`
	Listeners      []string `json:"listeners"` // "addr:port" bound by nginx processes
	// OtherListeners are TCP listeners held by other processes ("addr:port proc").
	OtherListeners []string `json:"other_listeners"`
	Errors         []string `json:"errors,omitempty"`
}

// Kinds of observations.
const KindNginx = "nginx"

// KindPointer records the generation the data plane is configured to serve.
const KindPointer = "nginx_pointer"

// Pointer is the live /etc/nginx/ngm/current target.
type Pointer struct {
	Current string `json:"current"`
}

// Record stores an observation, skipping the write when it is identical to the
// latest one of the same kind less than refresh ago (keeps the table small
// while preserving freshness evidence).
func Record(ctx context.Context, db *store.DB, kind string, data any, refresh time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	now := time.Now()
	var lastHash, lastAt string
	err = db.QueryRowContext(ctx, "SELECT hash, observed_at FROM runtime_observations WHERE kind=? ORDER BY observed_at DESC LIMIT 1", kind).Scan(&lastHash, &lastAt)
	if err == nil && lastHash == h {
		t, _ := store.ParseTime(lastAt)
		if now.Sub(t) < refresh {
			return nil
		}
	}
	return db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO runtime_observations(id,kind,observed_at,data_json,hash) VALUES(?,?,?,?,?)",
			ids.New(), kind, store.FormatTime(now), string(b), h); err != nil {
			return err
		}
		// Retain a bounded history per kind.
		_, err := tx.ExecContext(ctx, `DELETE FROM runtime_observations WHERE kind=? AND id NOT IN
			(SELECT id FROM runtime_observations WHERE kind=? ORDER BY observed_at DESC LIMIT 500)`, kind, kind)
		return err
	})
}

// Latest returns the newest observation of kind decoded into out, and its time.
func Latest(ctx context.Context, db *store.DB, kind string, out any) (time.Time, error) {
	var data, at string
	err := db.QueryRowContext(ctx, "SELECT data_json, observed_at FROM runtime_observations WHERE kind=? ORDER BY observed_at DESC LIMIT 1", kind).Scan(&data, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, err
	}
	if err != nil {
		return time.Time{}, err
	}
	t, _ := store.ParseTime(at)
	return t, json.Unmarshal([]byte(data), out)
}

// Heartbeat upserts a liveness record for service.
func Heartbeat(ctx context.Context, db *store.DB, service, status, detail string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO service_heartbeats(service,pid,version,status,detail,observed_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(service) DO UPDATE SET pid=excluded.pid, version=excluded.version, status=excluded.status, detail=excluded.detail, observed_at=excluded.observed_at`,
		service, os.Getpid(), buildinfo.Version, status, detail, store.FormatTime(time.Now()))
	return err
}
