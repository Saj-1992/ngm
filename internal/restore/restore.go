// Package restore implements `ngm restore`: a supervised, root-only restore of
// a portable backup onto this host (MASTER_SPEC §10.2). The data plane (Nginx)
// keeps running; only NGM's own services are briefly stopped while the
// database is swapped. Any failure before the swap leaves the host untouched;
// a failure after it puts the previous database back.
package restore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Options control a restore.
type Options struct {
	File       string
	Passphrase string
	Preview    bool // verify and describe only
	Apply      bool // after restore, queue a deployment of the restored configuration
	Config     config.Config
	Logf       func(string, ...any)
	// Services stopped during the swap (data plane excluded).
	Services []string
}

// Result describes a restore.
type Result struct {
	Manifest     backup.Manifest `json:"manifest"`
	Previous     string          `json:"previous_db"`
	SafetyBackup string          `json:"safety_backup"`
	DeployJob    string          `json:"deploy_job,omitempty"`
}

func run(ctx context.Context, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Run performs the restore.
func Run(ctx context.Context, o Options) (*Result, error) {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(o.Services) == 0 {
		o.Services = []string{"ngm-api.service", "ngm-ops.service", "ngm-monitor.service"}
	}
	p := o.Config.Paths
	work := filepath.Join(p.StateDir, "restore-"+ids.New())
	defer os.RemoveAll(work)

	// 1. Decrypt + verify (authenticity, hashes, DB integrity) — nothing touched yet.
	f, err := os.Open(o.File)
	if err != nil {
		return nil, err
	}
	x, err := backup.Extract(bufio.NewReader(f), o.Passphrase, filepath.Join(work, "x"), 0)
	f.Close()
	if err != nil {
		return nil, err
	}
	res := &Result{Manifest: x.Manifest}
	ms, _ := store.Migrations()
	latest := ms[len(ms)-1].Version
	if x.Manifest.SchemaVersion > latest {
		return res, fmt.Errorf("backup schema v%d is newer than this NGM (v%d); upgrade NGM first", x.Manifest.SchemaVersion, latest)
	}
	{
		db, err := store.Open(x.DBPath(), store.Options{})
		if err != nil {
			return res, err
		}
		err = db.IntegrityCheck(ctx)
		db.Close()
		if err != nil {
			return res, fmt.Errorf("backup database integrity: %w", err)
		}
	}
	logf("archive verified: created %s on %s by NGM %s (schema v%d), %d files", x.Manifest.Created.Format(time.RFC3339), x.Manifest.Hostname,
		x.Manifest.NGMVersion, x.Manifest.SchemaVersion, len(x.Manifest.Files))
	for k, v := range x.Manifest.Counts {
		logf("  %-24s %d", k, v)
	}
	if o.Preview {
		return res, nil
	}

	// 2. Stage: copy, rekey to this host's KEK, migrate, verify.
	live, err := store.Open(o.Config.DBPath(), store.Options{})
	if err != nil {
		return res, err
	}
	dstKR, err := vault.LoadDir(p.KeysDir)
	if err != nil {
		live.Close()
		return res, err
	}
	liveVault := vault.New(live, dstKR)
	if err := liveVault.Verify(ctx); err != nil {
		live.Close()
		return res, fmt.Errorf("this host's vault keys do not verify: %w", err)
	}
	dstVersions, err := liveVault.KeyVersions(ctx)
	if err != nil {
		live.Close()
		return res, err
	}
	// Safety backup of the current state (portable if a passphrase is configured).
	bs := &backup.Service{DB: live, Vault: liveVault, Dir: p.Backups}
	host, _ := os.Hostname()
	if bs.Configured(ctx) {
		a, err := bs.CreateArchive(ctx, p.KeysDir, host, "pre_restore", "")
		if err != nil {
			live.Close()
			return res, fmt.Errorf("safety backup failed (nothing changed): %w", err)
		}
		res.SafetyBackup = filepath.Join(p.Backups, a.FileName)
	} else {
		snap := filepath.Join(p.Backups, "pre-restore-"+time.Now().UTC().Format("20060102T150405Z")+".db")
		if err := live.Snapshot(ctx, snap); err != nil {
			live.Close()
			return res, fmt.Errorf("safety snapshot failed (nothing changed): %w", err)
		}
		_ = os.Chmod(snap, 0o600)
		res.SafetyBackup = snap
	}
	live.Close()
	logf("safety backup: %s", res.SafetyBackup)

	staged := o.Config.DBPath() + ".restore-staged"
	_ = os.Remove(staged)
	if err := copyFile(x.DBPath(), staged); err != nil {
		return res, err
	}
	defer os.Remove(staged)
	srcKR, err := vault.LoadDir(x.KeysDir())
	if err != nil {
		return res, fmt.Errorf("archive keys: %w", err)
	}
	if err := backup.Rekey(ctx, staged, srcKR, dstKR, dstVersions); err != nil {
		return res, fmt.Errorf("rekey: %w", err)
	}
	{
		sdb, err := store.Open(staged, store.Options{})
		if err != nil {
			return res, err
		}
		if _, err := sdb.Migrate(ctx); err != nil {
			sdb.Close()
			return res, fmt.Errorf("migrate restored database: %w", err)
		}
		if err := vault.New(sdb, dstKR).Verify(ctx); err != nil {
			sdb.Close()
			return res, fmt.Errorf("restored vault does not verify: %w", err)
		}
		if r, err := audit.New(sdb).Verify(ctx); err != nil || !r.OK {
			logf("warning: audit chain in the backup does not verify (%+v %v); restored as-is", r, err)
		}
		// Drop sessions: restored sessions must not be reusable.
		_, _ = sdb.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL", store.FormatTime(time.Now()))
		_, _ = audit.New(sdb).Record(ctx, audit.Event{ActorKind: "cli", Action: "backup.restored", Result: "success",
			Context: map[string]any{"source_host": x.Manifest.Hostname, "created": x.Manifest.Created, "schema": x.Manifest.SchemaVersion}})
		if _, err := sdb.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			sdb.Close()
			return res, err
		}
		sdb.Close()
	}
	logf("staged database rekeyed to this host's vault key, migrated and verified")

	// 3. Swap with NGM services stopped (Nginx keeps serving).
	for _, s := range o.Services {
		if err := run(ctx, "systemctl", "stop", s); err != nil {
			startAll(ctx, o.Services)
			return res, err
		}
	}
	prev := o.Config.DBPath() + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
	swap := func() error {
		cur, err := store.Open(o.Config.DBPath(), store.Options{})
		if err != nil {
			return err
		}
		_, _ = cur.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		cur.Close()
		if err := os.Rename(o.Config.DBPath(), prev); err != nil {
			return err
		}
		for _, suf := range []string{"-wal", "-shm"} {
			_ = os.Remove(o.Config.DBPath() + suf)
		}
		if err := os.Rename(staged, o.Config.DBPath()); err != nil {
			_ = os.Rename(prev, o.Config.DBPath())
			return err
		}
		return fixPerms(o.Config.DBPath())
	}
	if err := swap(); err != nil {
		startAll(ctx, o.Services)
		return res, fmt.Errorf("swap failed; previous database kept: %w", err)
	}
	res.Previous = prev
	logf("database swapped; previous kept at %s", prev)
	startAll(ctx, o.Services)
	if err := waitHealthy(ctx, o.Config.API.Listen, 30*time.Second); err != nil {
		// Put the previous database back.
		logf("restored database failed health check (%v); rolling back", err)
		for _, s := range o.Services {
			_ = run(ctx, "systemctl", "stop", s)
		}
		_ = os.Rename(o.Config.DBPath(), o.Config.DBPath()+".failed-restore")
		_ = os.Rename(prev, o.Config.DBPath())
		startAll(ctx, o.Services)
		return res, fmt.Errorf("restore rolled back: %w", err)
	}
	if o.Apply {
		db, err := store.Open(o.Config.DBPath(), store.Options{})
		if err == nil {
			j, _, err := jobs.NewJournal(db).Submit(ctx, jobs.SubmitRequest{Kind: "deploy.gateway", LockSet: []string{"gateway-config", "certificate"},
				Payload: map[string]any{"force": true, "note": "post-restore apply"}})
			if err == nil {
				res.DeployJob = j.ID
			}
			db.Close()
		}
	}
	return res, nil
}

func startAll(ctx context.Context, svcs []string) {
	for i := len(svcs) - 1; i >= 0; i-- {
		_ = run(ctx, "systemctl", "start", svcs[i])
	}
}

func fixPerms(p string) error {
	gid := -1
	if g, err := user.LookupGroup("ngm"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if err := os.Chown(p, 0, gid); err != nil {
		return err
	}
	return os.Chmod(p, 0o660)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func waitHealthy(ctx context.Context, listen string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error = errors.New("timeout")
	for time.Now().Before(deadline) {
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + listen + "/api/v1/system/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 503 {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(time.Second)
	}
	return last
}
