package installer

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
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/deploy"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/release"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Service accounts and groups (SECURITY_MODEL.md).
var (
	groups = []string{"ngm", "ngm-vault", "ngm-helper"}
	users  = []struct{ name, primary string }{
		{"ngm-api", "ngm"}, {"ngm-ops", "ngm"}, {"ngm-monitor", "ngm"}, {"ngm-logs", "ngm"},
	}
	supplementary = map[string][]string{"ngm-api": {"ngm-vault"}, "ngm-ops": {"ngm-helper", "ngm-vault"}}
	units         = []string{"ngm-helper.service", "ngm-ops.service", "ngm-monitor.service", "ngm-log-indexer.service", "ngm-api.service"}
)

// Result summarises an installation.
type Result struct {
	Version        string
	Fresh          bool
	BootstrapToken string // only on fresh installs without users
	NginxInstalled bool
	Preflight      *Report
	Steps          []string
}

// Logger receives progress lines.
type Logger func(format string, a ...any)

// Install performs an idempotent install or upgrade of the running binary.
// It never edits third-party nginx or UFW configuration.
func Install(ctx context.Context, o Options, logf Logger) (*Result, error) {
	res := &Result{Version: buildinfo.Version}
	step := func(f string, a ...any) {
		s := fmt.Sprintf(f, a...)
		res.Steps = append(res.Steps, s)
		logf("• %s", s)
	}
	// 0. Signed release: verify before anything changes.
	var signed *release.Manifest
	if o.ReleaseDir != "" {
		self, err := os.Executable()
		if err != nil {
			return res, err
		}
		self, _ = filepath.EvalSymlinks(self)
		keys, err := release.Trusted()
		if err != nil {
			return res, err
		}
		m, _, err := release.LoadDir(o.ReleaseDir, keys)
		if err != nil {
			return res, fmt.Errorf("release verification failed (nothing installed): %w", err)
		}
		a, err := m.ArtifactFor("")
		if err != nil {
			return res, err
		}
		if err := release.CheckFile(self, a); err != nil {
			return res, fmt.Errorf("this binary does not match the signed manifest (nothing installed): %w", err)
		}
		if m.Version != buildinfo.Version {
			return res, fmt.Errorf("signed manifest is for %s but this binary is %s", m.Version, buildinfo.Version)
		}
		signed = m
		step("release %s verified: signed by pinned key %s, sha256 %s", m.Version, m.KeyID, a.SHA256[:16])
	}
	logf("NGM %s installer (%s channel)", buildinfo.Version, buildinfo.Channel)
	if signed == nil {
		logf("WARNING: no signed manifest given (--release-dir): this binary's integrity is NOT verified. Use the signed bootstrap installer (install.sh) or \"ngm update apply\" for releases.")
	}

	rep := Preflight(ctx, o)
	res.Preflight = rep
	for _, c := range rep.Checks {
		logf("  [%s] %s: %s", strings.ToUpper(c.Status), c.ID, c.Detail)
	}
	if rep.Failed() {
		return res, errors.New("preflight failed; nothing was changed")
	}
	paths := config.DefaultPaths()
	_, statErr := os.Stat("/etc/ngm/ngm.json")
	res.Fresh = errors.Is(statErr, os.ErrNotExist)

	// 1. Nginx from the Ubuntu archive.
	if rep.NginxState == "absent" {
		step("installing nginx and libnginx-mod-stream from the Ubuntu archive")
		if err := aptInstall(ctx, logf, "nginx", "libnginx-mod-stream"); err != nil {
			return res, err
		}
		res.NginxInstalled = true
	} else if out, _ := run(ctx, "dpkg-query", "-W", "-f=${Status}", "libnginx-mod-stream"); !strings.Contains(out, "install ok installed") {
		step("installing libnginx-mod-stream (Ubuntu archive) to match the installed nginx")
		if err := aptInstall(ctx, logf, "libnginx-mod-stream"); err != nil {
			return res, err
		}
	}

	// 2. Accounts.
	for _, g := range groups {
		if _, err := user.LookupGroup(g); err != nil {
			step("creating system group %s", g)
			if out, err := run(ctx, "groupadd", "--system", g); err != nil {
				return res, fmt.Errorf("groupadd %s: %v: %s", g, err, out)
			}
		}
	}
	for _, u := range users {
		if _, err := user.Lookup(u.name); err != nil {
			step("creating system user %s", u.name)
			if out, err := run(ctx, "useradd", "--system", "--gid", u.primary, "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", u.name); err != nil {
				return res, fmt.Errorf("useradd %s: %v: %s", u.name, err, out)
			}
		}
		if extra := supplementary[u.name]; len(extra) > 0 {
			if out, err := run(ctx, "usermod", "-a", "-G", strings.Join(extra, ","), u.name); err != nil {
				return res, fmt.Errorf("usermod %s: %v: %s", u.name, err, out)
			}
		}
	}
	gid := func(name string) int {
		g, err := user.LookupGroup(name)
		if err != nil {
			return -1
		}
		n, _ := strconv.Atoi(g.Gid)
		return n
	}
	ngmGID, vaultGID := gid("ngm"), gid("ngm-vault")

	// 3. Directories with ownership and modes.
	dirs := []struct {
		path string
		gid  int
		mode os.FileMode
	}{
		{"/opt/ngm", 0, 0o755}, {paths.Releases, 0, 0o755},
		{paths.ConfigDir, ngmGID, 0o750}, {paths.KeysDir, vaultGID, 0o750},
		// setgid so files created inside inherit group ngm (Go needs os.ModeSetgid, not 0o2000).
		{paths.StateDir, ngmGID, os.ModeSetgid | 0o770}, {paths.Websites, ngmGID, os.ModeSetgid | 0o770}, {paths.Backups, ngmGID, os.ModeSetgid | 0o770},
		// /var/log/ngm and its nginx/ subdirectory are traversable (o+x, not
		// listable): Nginx workers (www-data) reopen their log files by path
		// after a log rotation.
		{paths.Generation, ngmGID, os.ModeSetgid | 0o770}, {paths.LogDir, ngmGID, os.ModeSetgid | 0o771},
		{filepath.Join(paths.LogDir, "nginx"), ngmGID, os.ModeSetgid | 0o751}, {filepath.Join(paths.LogDir, "app"), ngmGID, os.ModeSetgid | 0o770},
		{filepath.Join(paths.StateDir, "logindex"), ngmGID, os.ModeSetgid | 0o770},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode.Perm()); err != nil {
			return res, err
		}
		if err := os.Chown(d.path, 0, d.gid); err != nil {
			return res, err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return res, err
		}
	}
	step("directories prepared under /opt/ngm, /etc/ngm, /var/lib/ngm, /var/log/ngm")

	// 4. Release bundle + atomic current pointer.
	exe, err := os.Executable()
	if err != nil {
		return res, err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	relDir := filepath.Join(paths.Releases, buildinfo.Version)
	relBin := filepath.Join(relDir, "ngm")
	if exe != relBin {
		if err := os.MkdirAll(relDir, 0o755); err != nil {
			return res, err
		}
		if same, _ := sameFile(exe, relBin); !same {
			if _, err := os.Stat(relBin); err == nil && !strings.Contains(buildinfo.Version, "dev") {
				return res, fmt.Errorf("release %s already installed with different content; releases are immutable", buildinfo.Version)
			}
			if err := copyFile(exe, relBin, 0o755); err != nil {
				return res, err
			}
			step("installed release %s", relDir)
		}
	}
	if signed != nil {
		for _, n := range []string{"manifest.json", "manifest.sig"} {
			if err := copyFile(filepath.Join(o.ReleaseDir, n), filepath.Join(relDir, n), 0o644); err != nil {
				return res, err
			}
		}
	}
	if err := atomicSymlink(relDir, paths.Current); err != nil {
		return res, err
	}
	if err := atomicSymlink(filepath.Join(paths.Current, "ngm"), "/usr/local/bin/ngm"); err != nil {
		return res, err
	}
	step("current release → %s", buildinfo.Version)

	// 5. Configuration (never overwritten).
	cfgPath := filepath.Join(paths.ConfigDir, "ngm.json")
	if res.Fresh {
		c := config.Default()
		b, _ := json.MarshalIndent(c, "", "  ")
		if err := writeFileAtomic(cfgPath, append(b, '\n'), 0o640, 0, ngmGID); err != nil {
			return res, err
		}
		step("wrote %s", cfgPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return res, err
	}

	// 6. Vault key (generated once, never overwritten).
	kr, err := vault.LoadDir(cfg.Paths.KeysDir)
	if err != nil {
		return res, err
	}
	if len(kr.SortedVersions()) == 0 {
		key, err := vault.GenerateKeyFile(cfg.Paths.KeysDir, 1)
		if err != nil {
			return res, err
		}
		kf := filepath.Join(cfg.Paths.KeysDir, vault.KeyFileName(1))
		if err := os.Chown(kf, 0, vaultGID); err != nil {
			return res, err
		}
		_ = kr.Add(1, key)
		clear(key)
		step("generated vault key %s (root:ngm-vault 0440). Back it up only inside encrypted backups", kf)
	}

	// 7. Database: snapshot before migrating an existing DB, then migrate.
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return res, err
	}
	defer db.Close()
	cur, err := db.SchemaVersion(ctx)
	if err != nil {
		return res, err
	}
	ms, _ := store.Migrations()
	if cur > 0 && cur < ms[len(ms)-1].Version {
		snap := filepath.Join(cfg.Paths.Backups, fmt.Sprintf("pre-migrate-v%d-%s.db", cur, time.Now().UTC().Format("20060102T150405Z")))
		if err := db.Snapshot(ctx, snap); err != nil {
			return res, fmt.Errorf("pre-migration snapshot: %w", err)
		}
		_ = os.Chmod(snap, 0o640)
		step("pre-migration snapshot %s", snap)
	}
	applied, err := db.Migrate(ctx)
	if err != nil {
		return res, err
	}
	if len(applied) > 0 {
		step("applied migrations %v", applied)
	}
	v := vault.New(db, kr)
	if err := v.Init(ctx); err != nil {
		return res, err
	}
	if err := v.Verify(ctx); err != nil {
		return res, err
	}
	pre, _ := json.Marshal(rep)
	if err := setSetting(ctx, db, "install.preflight", string(pre)); err != nil {
		return res, err
	}
	var nUsers int
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&nUsers)
	if nUsers == 0 {
		tok, err := NewBootstrapToken(ctx, db)
		if err != nil {
			return res, err
		}
		res.BootstrapToken = tok
	}
	if err := fixDBPerms(cfg.DBPath(), ngmGID); err != nil {
		return res, err
	}

	// 8. systemd units.
	if err := installUnits(); err != nil {
		return res, err
	}
	if out, err := run(ctx, "systemd-tmpfiles", "--create", "/etc/tmpfiles.d/ngm.conf"); err != nil {
		return res, fmt.Errorf("tmpfiles: %v: %s", err, out)
	}
	if out, err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return res, fmt.Errorf("daemon-reload: %v: %s", err, out)
	}
	// 8a. The data plane must run before NGM services take their first
	// observation: a fresh host (or an install that
	// pulled in the nginx package) can leave nginx stopped. It is started only
	// if its configuration tests clean; a running nginx is never restarted.
	if out, _ := run(ctx, "systemctl", "is-active", "nginx.service"); strings.TrimSpace(out) != "active" {
		if tout, err := run(ctx, "nginx", "-t"); err != nil {
			step("WARNING: nginx is not running and `nginx -t` fails; fix it, then run `systemctl enable --now nginx`: %s", strings.TrimSpace(tout))
		} else if sout, err := run(ctx, "systemctl", "enable", "--now", "nginx.service"); err != nil {
			return res, fmt.Errorf("start nginx: %v: %s", err, sout)
		} else {
			step("nginx was not running: configuration tested and nginx started")
		}
	}

	for _, u := range units {
		if out, err := run(ctx, "systemctl", "enable", u); err != nil {
			return res, fmt.Errorf("enable %s: %v: %s", u, err, out)
		}
		// restart picks up a new release on rerun; NGM never restarts nginx here.
		if out, err := run(ctx, "systemctl", "restart", u); err != nil {
			return res, fmt.Errorf("restart %s: %v: %s", u, err, out)
		}
	}
	step("enabled and started %s", strings.Join(units, ", "))

	// 9. Smoke test.
	if err := waitHealthy(ctx, cfg.API.Listen, 30*time.Second); err != nil {
		return res, fmt.Errorf("smoke test: %w (see `journalctl -u ngm-api`)", err)
	}
	step("smoke test: API answered on %s", cfg.API.Listen)
	return res, nil
}

// NewBootstrapToken creates a one-time owner-setup token and stores its hash.
func NewBootstrapToken(ctx context.Context, db *store.DB) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	h, _ := json.Marshal(auth.HashToken(tok))
	return tok, setSetting(ctx, db, "setup.bootstrap_token_hash", string(h))
}

func setSetting(ctx context.Context, db *store.DB, key, valueJSON string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, revision=revision+1, updated_at=excluded.updated_at`,
			key, valueJSON, store.FormatTime(time.Now()))
		return err
	})
}

func aptInstall(ctx context.Context, logf Logger, pkgs ...string) error {
	deadline := time.Now().Add(3 * time.Minute)
	for dpkgBusy() != "" {
		if time.Now().After(deadline) {
			return errors.New("apt/dpkg remained locked for 3 minutes")
		}
		logf("  waiting for apt/dpkg lock…")
		time.Sleep(5 * time.Second)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	args := append([]string{"-y", "-o", "Dpkg::Options::=--force-confold", "--no-install-recommends", "install"}, pkgs...)
	cmd := execCommand(cctx, "apt-get", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := string(out)
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		return fmt.Errorf("apt-get install %v: %v\n%s", pkgs, err, tail)
	}
	return nil
}

func installUnits() error {
	return fs.WalkDir(deploy.Systemd, "systemd", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := deploy.Systemd.ReadFile(p)
		if err != nil {
			return err
		}
		name := filepath.Base(p)
		dst := filepath.Join("/etc/systemd/system", name)
		if name == "ngm.tmpfiles.conf" {
			dst = "/etc/tmpfiles.d/ngm.conf"
		}
		if name == "ngm.logrotate" {
			dst = "/etc/logrotate.d/ngm"
		}
		return writeFileAtomic(dst, b, 0o644, 0, 0)
	})
}

func fixDBPerms(dbPath string, gid int) error {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.Chown(p, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o660); err != nil {
			return err
		}
	}
	return nil
}

func waitHealthy(ctx context.Context, listen string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+listen+"/api/v1/system/health", nil)
		resp, err := http.DefaultClient.Do(req)
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

// ─── filesystem helpers ────────────────────────────────────────────────────

func sameFile(a, b string) (bool, error) {
	ha, err := fileHash(a)
	if err != nil {
		return false, err
	}
	hb, err := fileHash(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	out.Close()
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func writeFileAtomic(dst string, b []byte, mode os.FileMode, uid, gid int) error {
	tmp := dst + ".ngm-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// atomicSymlink points link at target via rename(2) of a temporary symlink.
// It refuses to replace anything that is not a symlink.
func atomicSymlink(target, link string) error {
	if st, err := os.Lstat(link); err == nil && st.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s exists and is not a symlink; refusing to replace it", link)
	}
	tmp := link + ".ngm-tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}
