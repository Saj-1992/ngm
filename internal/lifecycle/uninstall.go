package lifecycle

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ngm-gateway/ngm/internal/store"
)

// Mode is the uninstall mode.
type Mode string

const (
	KeepData Mode = "keep-data" // remove the program, keep configuration, data, logs and backups
	Purge    Mode = "purge"     // also delete every NGM-owned file, rule and account
)

// hookMarker must match the first line of NGM's Nginx hook files.
const hookMarker = "# NGM hook — owned by NGM"

// Runner executes system commands (faked in tests).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs real commands.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Uninstaller removes NGM. Root is "/" in production and a temp dir in tests.
type Uninstaller struct {
	Root   string
	Run    Runner
	DBPath string
}

// Action is one planned step.
type Action struct {
	Kind   string `json:"kind"` // remove | restore | command | keep | warn
	Target string `json:"target"`
	Why    string `json:"why"`
}

var (
	units    = []string{"ngm-api.service", "ngm-log-indexer.service", "ngm-monitor.service", "ngm-ops.service", "ngm-helper.service"}
	accounts = []string{"ngm-api", "ngm-ops", "ngm-monitor", "ngm-logs"}
	groups   = []string{"ngm-helper", "ngm-vault", "ngm"}
	keepDirs = []string{"/etc/ngm", "/var/lib/ngm", "/var/log/ngm", "/etc/nginx/ngm", "/var/www/ngm"}
	sshRe    = regexp.MustCompile(`\]\s+(22(/tcp)?|OpenSSH)(\s|$)`)
	ufwNGMRe = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*?)\s+# ngm:[a-z0-9-]+\s*$`)
)

func (u *Uninstaller) p(path string) string { return filepath.Join(u.Root, filepath.FromSlash(path)) }

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// ownedHook reports whether path is an NGM hook file (marker on line 1).
func (u *Uninstaller) ownedHook(path string) bool {
	b, err := os.ReadFile(u.p(path))
	return err == nil && strings.HasPrefix(string(b), hookMarker)
}

// Plan lists every change without touching anything.
func (u *Uninstaller) Plan(ctx context.Context, m Mode) []Action {
	var a []Action
	add := func(k, t, w string) { a = append(a, Action{k, t, w}) }
	for _, w := range u.dependencies(ctx) {
		add("warn", "", w)
	}
	for _, un := range units {
		if exists(u.p("/etc/systemd/system/" + un)) {
			add("command", "systemctl disable --now "+un, "stop NGM service")
			add("remove", "/etc/systemd/system/"+un, "NGM unit file")
		}
	}
	for _, h := range []string{"/etc/nginx/conf.d/ngm.conf", "/etc/nginx/modules-enabled/99-ngm-stream.conf"} {
		switch {
		case u.ownedHook(h):
			add("remove", h, "NGM Nginx hook (disconnects NGM routes; nginx -t + reload follow)")
		case exists(u.p(h)):
			add("keep", h, "same name as an NGM hook but without the NGM marker: not touched")
		}
	}
	if b, err := os.ReadFile(u.p("/etc/nginx/ngm/.default-site-disabled")); err == nil && !exists(u.p("/etc/nginx/sites-enabled/default")) {
		add("restore", "/etc/nginx/sites-enabled/default -> "+strings.TrimSpace(string(b)), "re-enable the distribution default site NGM disabled")
	}
	add("command", "nginx -t && systemctl reload nginx", "apply the disconnection (aborts and restores the hooks if the test fails)")
	for _, f := range []string{"/opt/ngm", "/usr/local/bin/ngm", "/etc/logrotate.d/ngm", "/etc/tmpfiles.d/ngm.conf", "/run/ngm"} {
		if exists(u.p(f)) {
			add("remove", f, "NGM program files")
		}
	}
	for _, d := range keepDirs {
		if !exists(u.p(d)) {
			continue
		}
		if m == Purge {
			add("remove", d, "NGM data (purge)")
		} else {
			add("keep", d, "kept (Keep Data)")
		}
	}
	rules := u.ufwRules(ctx)
	if m == Purge {
		for _, r := range rules {
			add("command", "ufw delete "+r, "NGM-tagged firewall rule")
		}
		for _, n := range accounts {
			add("command", "userdel "+n, "NGM service account")
		}
		for _, g := range groups {
			add("command", "groupdel "+g, "NGM group")
		}
	} else if len(rules) > 0 {
		add("keep", fmt.Sprintf("%d NGM-tagged UFW rules", len(rules)), "kept so traffic policy does not change; purge removes them")
	}
	return a
}

// dependencies summarises what stops working.
func (u *Uninstaller) dependencies(ctx context.Context) []string {
	if u.DBPath == "" || !exists(u.DBPath) {
		return nil
	}
	db, err := store.Open(u.DBPath, store.Options{})
	if err != nil {
		return []string{"cannot read the NGM database: " + err.Error()}
	}
	defer db.Close()
	var out []string
	for _, q := range []struct{ sql, msg string }{
		{"SELECT COUNT(*) FROM routes", "%d routes will stop being served by Nginx"},
		{"SELECT COUNT(*) FROM websites", "%d websites will go offline"},
		{"SELECT COUNT(*) FROM certificates", "%d certificates will no longer be renewed"},
		{"SELECT COUNT(*) FROM backup_artifacts", "%d backup archives exist under /var/lib/ngm/backups: copy them off this server first"},
	} {
		var n int
		if db.QueryRowContext(ctx, q.sql).Scan(&n) == nil && n > 0 {
			out = append(out, fmt.Sprintf(q.msg, n))
		}
	}
	return out
}

// ufwRules returns NGM-tagged rule specs (numbered order, highest first).
func (u *Uninstaller) ufwRules(ctx context.Context) []string {
	out, err := u.Run.Run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil
	}
	if strings.Contains(out, "Status: inactive") {
		return u.ufwAddedRules(ctx)
	}
	type r struct {
		n    int
		spec string
	}
	var rs []r
	var ssh []r
	otherSSH := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := sc.Text()
		isSSH := sshRe.MatchString(l)
		if m := ufwNGMRe.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			if isSSH {
				ssh = append(ssh, r{n, m[1]})
				continue
			}
			rs = append(rs, r{n, m[1]})
		} else if isSSH && strings.Contains(l, "ALLOW") {
			otherSSH = true
		}
	}
	// Never remove the only rule that lets SSH in (lock-out protection).
	if otherSSH {
		rs = append(rs, ssh...)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].n > rs[j].n })
	s := make([]string, len(rs))
	for i, x := range rs {
		s[i] = x.spec
	}
	return s
}

// Execute performs the plan for m. Nginx is disconnected first and verified;
// on failure the hooks are put back and nothing else is removed.
func (u *Uninstaller) Execute(ctx context.Context, m Mode, logf Logger) error {
	for _, un := range units {
		if exists(u.p("/etc/systemd/system/" + un)) {
			_, _ = u.Run.Run(ctx, "systemctl", "disable", "--now", un)
		}
	}
	// Disconnect Nginx (owned hooks only), keeping copies for a fail-safe restore.
	saved := map[string][]byte{}
	for _, h := range []string{"/etc/nginx/conf.d/ngm.conf", "/etc/nginx/modules-enabled/99-ngm-stream.conf"} {
		if u.ownedHook(h) {
			b, _ := os.ReadFile(u.p(h))
			saved[h] = b
			if err := os.Remove(u.p(h)); err != nil {
				return err
			}
			logf("removed %s", h)
		}
	}
	restoredDefault := ""
	if b, err := os.ReadFile(u.p("/etc/nginx/ngm/.default-site-disabled")); err == nil && !exists(u.p("/etc/nginx/sites-enabled/default")) {
		t := strings.TrimSpace(string(b))
		if t == "/etc/nginx/sites-available/default" || t == "../sites-available/default" {
			if err := os.Symlink(t, u.p("/etc/nginx/sites-enabled/default")); err == nil {
				restoredDefault = t
				logf("re-enabled sites-enabled/default")
			}
		}
	}
	if exists(u.p("/usr/sbin/nginx")) || u.Root == "/" {
		if out, err := u.Run.Run(ctx, "nginx", "-t"); err != nil {
			for h, b := range saved {
				_ = os.WriteFile(u.p(h), b, 0o644)
			}
			if restoredDefault != "" {
				_ = os.Remove(u.p("/etc/nginx/sites-enabled/default"))
			}
			return fmt.Errorf("nginx -t failed after disconnecting NGM; hooks restored, nothing else removed:\n%s", out)
		}
		if out, err := u.Run.Run(ctx, "systemctl", "reload", "nginx.service"); err != nil {
			logf("warning: nginx reload failed: %s", strings.TrimSpace(out))
		}
	}
	for _, un := range units {
		if p := u.p("/etc/systemd/system/" + un); exists(p) {
			_ = os.Remove(p)
		}
	}
	_, _ = u.Run.Run(ctx, "systemctl", "daemon-reload")
	var errs []error
	for _, f := range []string{"/usr/local/bin/ngm", "/opt/ngm", "/etc/logrotate.d/ngm", "/etc/tmpfiles.d/ngm.conf", "/run/ngm"} {
		if exists(u.p(f)) {
			if err := os.RemoveAll(u.p(f)); err != nil {
				errs = append(errs, err)
			} else {
				logf("removed %s", f)
			}
		}
	}
	if m == Purge {
		for _, n := range u.ufwRules(ctx) {
			if out, err := u.Run.Run(ctx, "ufw", append([]string{"--force", "delete"}, strings.Fields(n)...)...); err != nil {
				errs = append(errs, fmt.Errorf("ufw delete %s: %s", n, strings.TrimSpace(out)))
			}
		}
		for _, d := range keepDirs {
			if exists(u.p(d)) {
				if err := os.RemoveAll(u.p(d)); err != nil {
					errs = append(errs, err)
				} else {
					logf("removed %s", d)
				}
			}
		}
		for _, n := range accounts {
			_, _ = u.Run.Run(ctx, "userdel", n)
		}
		for _, g := range groups {
			_, _ = u.Run.Run(ctx, "groupdel", g)
		}
		logf("NGM purged")
	} else {
		logf("NGM removed; data kept in %s", strings.Join(keepDirs, ", "))
	}
	return errors.Join(errs...)
}

var addedRe = regexp.MustCompile(`^ufw (.+?) comment 'ngm:[a-z0-9-]+'$`)

// ufwAddedRules covers an inactive UFW, whose numbered status lists nothing:
// NGM rules are taken from "ufw show added" and deleted by rule spec. The only
// SSH allow rule is kept, as for an active firewall.
func (u *Uninstaller) ufwAddedRules(ctx context.Context) []string {
	out, err := u.Run.Run(ctx, "ufw", "show", "added")
	if err != nil {
		return nil
	}
	var rs, ssh []string
	otherSSH := false
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		isSSH := strings.Contains(l, " 22/tcp") || strings.HasSuffix(l, " 22") || strings.Contains(l, " 22 ") || strings.Contains(l, "OpenSSH")
		if m := addedRe.FindStringSubmatch(l); m != nil {
			if isSSH {
				ssh = append(ssh, m[1])
			} else {
				rs = append(rs, m[1])
			}
		} else if isSSH && strings.HasPrefix(l, "ufw allow") {
			otherSSH = true
		}
	}
	if otherSSH {
		rs = append(rs, ssh...)
	}
	return rs
}
