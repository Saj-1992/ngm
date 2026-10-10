// Package lifecycle implements root-only CLI lifecycle operations
// (MASTER_SPEC §16): signed update/rollback, repair, coordinated Nginx
// upgrade and uninstall. It is never reachable from request handlers.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/installer"
	"github.com/ngm-gateway/ngm/internal/release"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Logger receives progress lines.
type Logger func(format string, a ...any)

// ErrNeedsApproval is returned when a plan was printed but --yes was absent.
var ErrNeedsApproval = errors.New("not applied: re-run with --yes to approve")

// UpdateOptions controls Apply.
type UpdateOptions struct {
	From      string // directory with manifest.json, manifest.sig, ngm-linux-<arch>
	Yes       bool   // administrator approval
	Reinstall bool   // allow the same version (development builds)
	Actor     string
}

// Plan is what an update would do, after full verification.
type Plan struct {
	Manifest  *release.Manifest
	Artifact  *release.Artifact
	From      string
	FromDB    int
	Backup    bool
	Snapshot  string
	Supported bool
}

// Check verifies a release directory with the keys pinned in THIS binary and
// returns the plan. Nothing is changed.
func Check(ctx context.Context, cfg config.Config, from string, reinstall bool) (*Plan, error) {
	keys, err := release.Trusted()
	if err != nil {
		return nil, err
	}
	m, _, err := release.LoadDir(from, keys)
	if err != nil {
		return nil, err
	}
	a, err := m.ArtifactFor(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if err := release.CheckFile(filepath.Join(from, a.File), a); err != nil {
		return nil, err
	}
	if m.Channel == "development" && buildinfo.Channel != "development" {
		return nil, errors.New("refusing a development-channel release on a " + buildinfo.Channel + " installation")
	}
	switch c := release.CompareVersions(m.Version, buildinfo.Version); {
	case c < 0:
		return nil, fmt.Errorf("release %s is older than the installed %s; use `ngm update rollback`", m.Version, buildinfo.Version)
	case c == 0 && !(reinstall && strings.Contains(m.Version, "dev")):
		return nil, fmt.Errorf("release %s is already installed", m.Version)
	}
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cur, err := db.SchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	if m.DBSchema < cur {
		return nil, fmt.Errorf("release %s ships schema %d but this database is at %d; it cannot run here", m.Version, m.DBSchema, cur)
	}
	p := &Plan{Manifest: m, Artifact: a, From: buildinfo.Version, FromDB: cur,
		Snapshot: filepath.Join(cfg.Paths.StateDir, "update", "pre-"+m.Version+".db")}
	p.Backup = (&backup.Service{DB: db, Dir: cfg.Paths.Backups}).Configured(ctx)
	p.Supported = supported(m.Supported)
	return p, nil
}

// Apply verifies, stages and installs a signed release, rolling back
// automatically when the new version does not become healthy.
func Apply(ctx context.Context, cfg config.Config, o UpdateOptions, logf Logger) error {
	p, err := Check(ctx, cfg, o.From, o.Reinstall)
	if err != nil {
		return err
	}
	m := p.Manifest
	logf("verified %s %s (%s channel, signed by %s, %s sha256 %s…)", m.Product, m.Version, m.Channel, m.KeyID, p.Artifact.File, p.Artifact.SHA256[:16])
	logf("plan: %s → %s; schema %d → %d; snapshot %s; encrypted backup: %v", p.From, m.Version, p.FromDB, m.DBSchema, p.Snapshot, p.Backup)
	if !p.Supported {
		logf("warning: this OS is not in the release's supported list %v", m.Supported)
	}
	if !o.Yes {
		return ErrNeedsApproval
	}
	st := &release.UpdateState{From: p.From, To: m.Version, FromSchema: p.FromDB, ToSchema: m.DBSchema, Snapshot: p.Snapshot, Phase: "staged", Actor: o.Actor, StartedAt: time.Now().UTC()}

	// 1. Consistent DB snapshot (local rollback point) + encrypted backup.
	if err := snapshot(ctx, cfg, p.Snapshot); err != nil {
		return fmt.Errorf("pre-update snapshot: %w", err)
	}
	logf("database snapshot written")
	if p.Backup {
		name, err := preBackup(ctx, cfg)
		if err != nil {
			return fmt.Errorf("pre-update backup: %w", err)
		}
		st.Backup = name
		logf("encrypted backup %s", name)
	} else {
		logf("no backup passphrase configured: only the local snapshot protects this update")
	}

	// 2. Stage the immutable release directory and re-verify the copy.
	rel := filepath.Join(cfg.Paths.Releases, m.Version)
	if err := stage(o.From, rel, p.Artifact); err != nil {
		return err
	}
	logf("staged %s", rel)
	if err := release.SaveState(cfg.Paths.StateDir, st); err != nil {
		return err
	}
	auditCLI(ctx, cfg, "system.update.start", m.Version, "success", map[string]any{"from": p.From})

	// 3. Install with the NEW binary (migrations, units, restart, health).
	st.Phase = "installing"
	_ = release.SaveState(cfg.Paths.StateDir, st)
	out, err := runLog(ctx, filepath.Join(cfg.Paths.StateDir, "update", "install-"+m.Version+".log"), filepath.Join(rel, "ngm"), installArgs(rel)...)
	if err == nil {
		err = installer.WaitHealthy(ctx, cfg.API.Listen, 60*time.Second)
	}
	if err != nil {
		st.Phase, st.Error = "failed", lastLine(out, err)
		_ = release.SaveState(cfg.Paths.StateDir, st)
		logf("install of %s failed: %s; rolling back", m.Version, st.Error)
		if rerr := Rollback(ctx, cfg, st, logf); rerr != nil {
			st.Phase, st.Error = "rollback_failed", st.Error+"; rollback: "+rerr.Error()
			_ = release.SaveState(cfg.Paths.StateDir, st)
			return fmt.Errorf("update failed and rollback failed: %s (see %s)", st.Error, release.StatePath(cfg.Paths.StateDir))
		}
		return fmt.Errorf("update to %s failed and was rolled back to %s: %s", m.Version, st.From, st.Error)
	}
	st.Phase, st.FinishedAt = "succeeded", time.Now().UTC()
	_ = release.SaveState(cfg.Paths.StateDir, st)
	auditCLI(ctx, cfg, "system.update", m.Version, "success", map[string]any{"from": p.From})
	if gone, err := GCReleases(cfg.Paths.Releases, cfg.Paths.Current, p.From); err != nil {
		logf("warning: release cleanup: %v", err)
	} else if len(gone) > 0 {
		logf("removed old releases: %v", gone)
	}
	logf("NGM %s is running and healthy (previous: %s; `ngm update rollback --yes` returns to it)", m.Version, p.From)
	return nil
}

// Rollback returns to st.From. When migrations ran since, the pre-update
// snapshot replaces the database: changes made after the update are lost.
func Rollback(ctx context.Context, cfg config.Config, st *release.UpdateState, logf Logger) error {
	prev := filepath.Join(cfg.Paths.Releases, st.From, "ngm")
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("previous release %s is not on disk: %w", st.From, err)
	}
	stopServices(ctx)
	cur, err := schemaOf(ctx, cfg.DBPath())
	if err != nil {
		return err
	}
	if cur != st.FromSchema {
		if err := restoreSnapshot(st.Snapshot, cfg.DBPath()); err != nil {
			return fmt.Errorf("restore snapshot: %w", err)
		}
		logf("database restored from %s (schema %d → %d)", st.Snapshot, cur, st.FromSchema)
	}
	if err := installer.AtomicSymlink(filepath.Join(cfg.Paths.Releases, st.From), cfg.Paths.Current); err != nil {
		return err
	}
	if out, err := runLog(ctx, filepath.Join(cfg.Paths.StateDir, "update", "rollback-"+st.From+".log"), prev, installArgs(filepath.Dir(prev))...); err != nil {
		return errors.New(lastLine(out, err))
	}
	if err := installer.WaitHealthy(ctx, cfg.API.Listen, 60*time.Second); err != nil {
		return err
	}
	if st.Phase == "succeeded" {
		st.Phase = "rolled_back"
	} else if st.Phase != "rollback_failed" {
		st.Phase = "rolled_back"
	}
	st.FinishedAt = time.Now().UTC()
	_ = release.SaveState(cfg.Paths.StateDir, st)
	auditCLI(ctx, cfg, "system.update.rollback", st.From, "success", map[string]any{"from": st.To})
	logf("rolled back to %s", st.From)
	return nil
}

func stage(from, rel string, a *release.Artifact) error {
	bin := filepath.Join(rel, "ngm")
	if _, err := os.Stat(bin); err == nil {
		if release.CheckFile(bin, a) == nil {
			return copyManifest(from, rel)
		}
		if !strings.Contains(filepath.Base(rel), "dev") {
			return fmt.Errorf("%s already exists with different content; releases are immutable", rel)
		}
	}
	if err := os.MkdirAll(rel, 0o755); err != nil {
		return err
	}
	if err := installer.CopyFile(filepath.Join(from, a.File), bin, 0o755); err != nil {
		return err
	}
	if err := release.CheckFile(bin, a); err != nil {
		return err
	}
	return copyManifest(from, rel)
}

func copyManifest(from, rel string) error {
	for _, n := range []string{"manifest.json", "manifest.sig"} {
		if err := installer.CopyFile(filepath.Join(from, n), filepath.Join(rel, n), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func snapshot(ctx context.Context, cfg config.Config, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	_ = os.Remove(dst)
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

func restoreSnapshot(snap, dbPath string) error {
	if _, err := os.Stat(snap); err != nil {
		return err
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		return err
	}
	tmp := dbPath + ".rollback"
	if err := installer.CopyFile(snap, tmp, fi.Mode().Perm()); err != nil {
		return err
	}
	chownLike(tmp, fi)
	for _, s := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + s)
	}
	return os.Rename(tmp, dbPath)
}

func schemaOf(ctx context.Context, path string) (int, error) {
	db, err := store.Open(path, store.Options{})
	if err != nil {
		return 0, err
	}
	defer db.Close()
	return db.SchemaVersion(ctx)
}

func preBackup(ctx context.Context, cfg config.Config) (string, error) {
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return "", err
	}
	defer db.Close()
	kr, err := vault.LoadDir(cfg.Paths.KeysDir)
	if err != nil {
		return "", err
	}
	v := vault.New(db, kr)
	host, _ := os.Hostname()
	a, err := (&backup.Service{DB: db, Vault: v, Dir: cfg.Paths.Backups}).CreateArchive(ctx, cfg.Paths.KeysDir, host, "pre_update", "")
	if err != nil {
		return "", err
	}
	fixGroup(filepath.Join(cfg.Paths.Backups, a.FileName))
	return a.FileName, nil
}

func stopServices(ctx context.Context) {
	us := installer.Units()
	for i := len(us) - 1; i >= 0; i-- {
		_ = exec.CommandContext(ctx, "systemctl", "stop", us[i]).Run()
	}
}

func runLog(ctx context.Context, logPath, bin string, args ...string) (string, error) {
	_ = os.MkdirAll(filepath.Dir(logPath), 0o750)
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	_ = os.WriteFile(logPath, out, 0o640)
	return string(out), err
}

func lastLine(out string, err error) string {
	ls := strings.Split(strings.TrimSpace(out), "\n")
	l := strings.TrimSpace(ls[len(ls)-1])
	if l == "" {
		return err.Error()
	}
	return l
}

func supported(list []string) bool {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil || len(list) == 0 {
		return len(list) == 0
	}
	var id, ver string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "ID="); ok {
			id = strings.Trim(v, `"`)
		}
		if v, ok := strings.CutPrefix(l, "VERSION_ID="); ok {
			ver = strings.Trim(v, `"`)
		}
	}
	for _, s := range list {
		if s == id+"-"+ver {
			return true
		}
	}
	return false
}

func auditCLI(ctx context.Context, cfg config.Config, action, target, result string, d map[string]any) {
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = audit.New(db).Record(ctx, audit.Event{ActorKind: "cli", Action: action, TargetKind: "release", TargetID: target, Result: result, Context: d})
}

// installArgs passes the signed manifest when the release has one, so the
// binary re-verifies itself before changing anything.
func installArgs(rel string) []string {
	if _, err := os.Stat(filepath.Join(rel, "manifest.sig")); err == nil {
		return []string{"install", "--release-dir", rel}
	}
	return []string{"install"}
}
