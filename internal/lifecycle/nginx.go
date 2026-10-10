package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/alerts"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

// PkgUpgrade is one package apt would upgrade.
type PkgUpgrade struct{ Name, From, To string }

var instRe = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+)`)

// ParseSimulation extracts upgrades from `apt-get -s` output.
func ParseSimulation(out string) []PkgUpgrade {
	var r []PkgUpgrade
	for _, l := range strings.Split(out, "\n") {
		if m := instRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			r = append(r, PkgUpgrade{m[1], m[2], m[3]})
		}
	}
	return r
}

// CheckModuleSet refuses a partial upgrade: dynamic modules are built against
// one exact Nginx version, so nginx-common and every installed
// libnginx-mod-* must move together.
func CheckModuleSet(installed []string, up []PkgUpgrade) error {
	moving := map[string]string{}
	for _, u := range up {
		moving[u.Name] = u.To
	}
	core, ok := moving["nginx-common"]
	if !ok {
		if len(up) > 0 {
			return errors.New("apt would upgrade Nginx modules without nginx-common; refusing a mixed module set")
		}
		return nil
	}
	for _, p := range installed {
		if strings.HasPrefix(p, "libnginx-mod-") {
			if _, ok := moving[p]; !ok {
				return fmt.Errorf("%s would stay on its old version while nginx moves to %s (module ABI mismatch); refusing", p, core)
			}
		}
	}
	return nil
}

// NginxPackages lists installed Nginx packages.
func NginxPackages(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package} ${db:Status-Abbrev}\n", "nginx*", "libnginx-mod-*").Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	var ps []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.HasPrefix(f[1], "ii") {
			ps = append(ps, f[0])
		}
	}
	return ps, nil
}

func aptLocked(ctx context.Context) bool {
	for _, l := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"} {
		if err := exec.CommandContext(ctx, "flock", "-n", "-E", "75", l, "true").Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 75 {
				return true
			}
		}
	}
	return false
}

// NginxUpgrade performs the coordinated Nginx APT upgrade.
func NginxUpgrade(ctx context.Context, cfg config.Config, yes bool, logf Logger) error {
	if aptLocked(ctx) {
		return errors.New("another package manager is running (dpkg lock held); try again later")
	}
	pkgs, err := NginxPackages(ctx)
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return errors.New("no Ubuntu Nginx packages are installed")
	}
	logf("installed: %s", strings.Join(pkgs, " "))
	if out, err := exec.CommandContext(ctx, "apt-get", "update", "-q").CombinedOutput(); err != nil {
		return fmt.Errorf("apt-get update: %s", lastLine(string(out), err))
	}
	sim, err := exec.CommandContext(ctx, "apt-get", append([]string{"-s", "install", "--only-upgrade"}, pkgs...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get -s: %s", lastLine(string(sim), err))
	}
	up := ParseSimulation(string(sim))
	if len(up) == 0 {
		logf("Nginx packages are up to date")
		return NginxReconcile(ctx, cfg, "ngm nginx upgrade (no change)", logf)
	}
	for _, u := range up {
		logf("  %s %s → %s", u.Name, u.From, u.To)
	}
	if err := CheckModuleSet(pkgs, up); err != nil {
		return err
	}
	if !yes {
		return ErrNeedsApproval
	}
	// Pre-upgrade copies: NGM backup (if configured) + /etc/nginx tarball.
	if name, err := preBackup(ctx, cfg); err == nil {
		logf("encrypted backup %s", name)
	} else {
		logf("no encrypted backup (%v); continuing with the /etc/nginx copy only", err)
	}
	dir := filepath.Join(cfg.Paths.StateDir, "nginx-upgrade")
	_ = os.MkdirAll(dir, 0o700)
	tarball := filepath.Join(dir, "etc-nginx-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz")
	if out, err := exec.CommandContext(ctx, "tar", "-czf", tarball, "-C", "/etc", "nginx").CombinedOutput(); err != nil {
		return fmt.Errorf("copy /etc/nginx: %s", lastLine(string(out), err))
	}
	logf("saved %s", tarball)
	cmd := exec.CommandContext(ctx, "apt-get", append([]string{"install", "-y", "--only-upgrade",
		"-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"}, pkgs...)...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(dir, "apt-"+time.Now().UTC().Format("20060102T150405Z")+".log"), out, 0o600)
	if err != nil {
		return fmt.Errorf("apt-get install failed: %s (configuration copy: %s; package downgrade is not automatic)", lastLine(string(out), err), tarball)
	}
	if out, err := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -t fails after the upgrade; Nginx keeps running the old process until restarted:\n%s\nconfiguration copy: %s", out, tarball)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", "nginx.service").CombinedOutput(); err != nil {
		return fmt.Errorf("restart nginx: %s", lastLine(string(out), err))
	}
	return NginxReconcile(ctx, cfg, "ngm nginx upgrade", logf)
}

// NginxReconcile verifies the current Nginx against NGM's needs and records
// it as the accepted baseline (clearing nginx_external_change).
func NginxReconcile(ctx context.Context, cfg config.Config, by string, logf Logger) error {
	n := helper.ObserveNginx(ctx, helper.ExecRunner{})
	if !n.Installed {
		return errors.New("nginx is not installed")
	}
	if out, err := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -t: %s", strings.TrimSpace(string(out)))
	}
	if n.ServiceState != "active" {
		return fmt.Errorf("nginx service is %s", n.ServiceState)
	}
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return err
	}
	defer db.Close()
	old, _ := alerts.LoadBaseline(ctx, db)
	if old != nil {
		if msg, crit := alerts.Drift(*old, n); crit && needsStream(ctx, db) {
			return fmt.Errorf("refusing to accept this Nginx: %s", msg)
		}
	}
	if err := alerts.SaveBaseline(ctx, db, alerts.BaselineFrom(n, by)); err != nil {
		return err
	}
	_ = observe.Record(ctx, db, observe.KindNginx, n, time.Minute)
	logf("accepted Nginx %s (%s), stream=%v ssl_preread=%v", n.Version, n.PackageVersion, n.StreamModule, n.SSLPreread)
	return nil
}

// needsStream reports whether any listener requires the stream module.
func needsStream(ctx context.Context, db *store.DB) bool {
	var c int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM listeners WHERE enabled=1 AND kind IN ('stream','stream_tls_front')").Scan(&c)
	return c > 0
}
