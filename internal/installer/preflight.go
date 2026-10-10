// Package installer implements `ngm install` and `ngm doctor` preflight
// (MASTER_SPEC §2, §16). It runs as root on the target host.
package installer

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/helper"
)

// Check is one preflight result.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass | warn | fail | info
	Detail string `json:"detail"`
}

// Report is the full preflight result.
type Report struct {
	At       time.Time `json:"at"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Checks   []Check   `json:"checks"`
	// NginxState summarises pre-existing nginx for the install decision.
	NginxState string   `json:"nginx_state"` // absent | ngm-managed | distro-default | customized | foreign
	SSHPorts   []string `json:"ssh_ports"`
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}

func (r *Report) add(id, status, format string, a ...any) {
	r.Checks = append(r.Checks, Check{ID: id, Status: status, Detail: fmt.Sprintf(format, a...)})
}

// Options control preflight/install decisions.
type Options struct {
	AdoptExistingNginx bool // allow installing alongside a customised Ubuntu nginx (NGM never edits third-party files)
	APIListen          string
	// ReleaseDir, when set, holds manifest.json/.sig of the release being
	// installed: the running binary must match the signed manifest.
	ReleaseDir string
}

func osRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Preflight inspects the host without changing it.
func Preflight(ctx context.Context, o Options) *Report {
	r := &Report{At: time.Now().UTC(), Arch: runtime.GOARCH}
	r.Hostname, _ = os.Hostname()
	osr := osRelease()
	r.OS = osr["PRETTY_NAME"]

	// Root.
	if os.Geteuid() == 0 {
		r.add("root", "pass", "running as root")
	} else {
		r.add("root", "fail", "installer must run as root (sudo)")
	}
	// OS / arch support matrix.
	if osr["ID"] == "ubuntu" && (osr["VERSION_ID"] == "22.04" || osr["VERSION_ID"] == "24.04") {
		r.add("os", "pass", "%s", r.OS)
	} else {
		r.add("os", "fail", "unsupported OS %q; supported: Ubuntu 22.04/24.04 LTS", r.OS)
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		r.add("arch", "pass", "%s", runtime.GOARCH)
	} else {
		r.add("arch", "fail", "unsupported architecture %s", runtime.GOARCH)
	}
	// systemd and cgroup v2.
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		r.add("systemd", "pass", "systemd is PID 1")
	} else {
		r.add("systemd", "fail", "systemd not running (containers without systemd are unsupported)")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		r.add("cgroup", "pass", "cgroup v2 unified hierarchy")
	} else {
		r.add("cgroup", "warn", "cgroup v2 not detected; resource budgets may not apply")
	}
	// Resources (planning targets, not guarantees).
	if free, ok := diskFree("/var"); ok {
		switch {
		case free < 2<<30:
			r.add("disk", "fail", "only %.1f GiB free on /var (need ≥ 2 GiB)", float64(free)/(1<<30))
		case free < 10<<30:
			r.add("disk", "warn", "%.1f GiB free on /var (recommended ≥ 10 GiB)", float64(free)/(1<<30))
		default:
			r.add("disk", "pass", "%.1f GiB free on /var", float64(free)/(1<<30))
		}
	}
	if mem := memTotalKiB(); mem > 0 {
		gib := float64(mem) / (1 << 20)
		if gib < 0.9 {
			r.add("memory", "warn", "%.2f GiB RAM (provisional minimum 1 GiB)", gib)
		} else {
			r.add("memory", "pass", "%.2f GiB RAM", gib)
		}
	}
	// apt/dpkg locks.
	if busy := dpkgBusy(); busy != "" {
		r.add("apt_lock", "fail", "package manager busy: %s held; wait for it to finish", busy)
	} else {
		r.add("apt_lock", "pass", "dpkg/apt locks free")
	}
	// API port.
	listen := o.APIListen
	if listen == "" {
		listen = "127.0.0.1:9999"
	}
	if ln, err := net.Listen("tcp", listen); err == nil {
		ln.Close()
		r.add("api_port", "pass", "%s free", listen)
	} else if ngmRunning(ctx) {
		r.add("api_port", "pass", "%s held by existing ngm-api (rerun/upgrade)", listen)
	} else {
		r.add("api_port", "fail", "%s already in use by another process", listen)
	}
	// Nginx.
	r.NginxState = inspectNginx(ctx, r, o)
	// Public ports (informational for later phases).
	ss, _ := run(ctx, "ss", "-H", "-t", "-l", "-n", "-p")
	for _, port := range []string{":80", ":443"} {
		var owners []string
		for _, l := range strings.Split(ss, "\n") {
			f := strings.Fields(l)
			if len(f) >= 4 && strings.HasSuffix(f[3], port) {
				owners = append(owners, procName(l))
			}
		}
		switch {
		case len(owners) == 0:
			r.add("port"+port, "info", "port %s free", port[1:])
		case allEqual(owners, "nginx"):
			r.add("port"+port, "info", "port %s held by nginx", port[1:])
		default:
			r.add("port"+port, "warn", "port %s held by %s; NGM listeners on it will conflict", port[1:], strings.Join(owners, ","))
		}
	}
	// SSH + firewall (read-only; NGM changes nothing here in this phase).
	if out, err := run(ctx, "sshd", "-T"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if p, ok := strings.CutPrefix(l, "port "); ok {
				r.SSHPorts = append(r.SSHPorts, strings.TrimSpace(p))
			}
		}
		r.add("ssh", "info", "sshd listening on port(s) %s", strings.Join(r.SSHPorts, ","))
	} else {
		r.add("ssh", "warn", "could not read sshd configuration; firewall changes will require manual SSH confirmation")
	}
	if out, err := run(ctx, "ufw", "status"); err == nil {
		first := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
		r.add("ufw", "info", "%s", first)
	} else {
		r.add("ufw", "info", "ufw not available")
	}
	// IP families.
	v4, v6 := ipFamilies()
	r.add("ip_families", "info", "global IPv4: %v, global IPv6: %v", v4, v6)
	return r
}

func allEqual(s []string, v string) bool {
	for _, x := range s {
		if x != v {
			return false
		}
	}
	return true
}

func procName(ssLine string) string {
	i := strings.Index(ssLine, `(("`)
	if i < 0 {
		return "unknown"
	}
	rest := ssLine[i+3:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "unknown"
	}
	return rest[:j]
}

func memTotalKiB() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "MemTotal:"); ok {
			var n uint64
			fmt.Sscanf(strings.TrimSpace(v), "%d", &n)
			return n
		}
	}
	return 0
}

func ipFamilies() (v4, v6 bool) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() {
			continue
		}
		if ipn.IP.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	return
}

func ngmRunning(ctx context.Context) bool {
	out, err := run(ctx, "systemctl", "is-active", "ngm-api.service")
	return err == nil && strings.TrimSpace(out) == "active"
}

// inspectNginx classifies a pre-existing nginx installation.
func inspectNginx(ctx context.Context, r *Report, o Options) string {
	out, _ := run(ctx, "dpkg-query", "-W", helper.DpkgFormat, "nginx", "nginx-common", "nginx-core", "nginx-full", "nginx-light", "nginx-extras", "libnginx-mod-stream")
	pk := helper.ParseDpkg(out)
	installed := false
	for _, name := range []string{"nginx", "nginx-common", "nginx-core", "nginx-full", "nginx-light", "nginx-extras"} {
		if p := pk[name]; p.Installed {
			installed = true
			if helper.Origin(p) != "ubuntu" {
				r.add("nginx_origin", "fail", "package %s %s is not from the Ubuntu archive (maintainer %q); NGM supports only distro Nginx OSS and will not take it over", name, p.Version, p.Maintainer)
				return "foreign"
			}
		}
	}
	_, binErr := os.Stat("/usr/sbin/nginx")
	if !installed {
		if binErr == nil {
			r.add("nginx_origin", "fail", "/usr/sbin/nginx exists but is not owned by an Ubuntu package (source build?); refusing")
			return "foreign"
		}
		if _, err := os.Stat("/etc/nginx"); err == nil {
			r.add("nginx", "warn", "/etc/nginx exists without an installed nginx package (leftover configuration will be preserved)")
		}
		r.add("nginx", "pass", "nginx not installed; NGM will install nginx + libnginx-mod-stream from the Ubuntu archive")
		return "absent"
	}
	r.add("nginx_origin", "pass", "nginx %s from the Ubuntu archive", pk["nginx-common"].Version)
	if b, err := os.ReadFile("/etc/nginx/ngm/.ngm-owned"); err == nil && len(b) > 0 {
		r.add("nginx", "pass", "nginx already managed by NGM")
		return "ngm-managed"
	}
	customized := nginxCustomizations(ctx)
	if len(customized) == 0 {
		r.add("nginx", "pass", "distribution default nginx configuration")
		return "distro-default"
	}
	detail := strings.Join(customized, "; ")
	if o.AdoptExistingNginx {
		r.add("nginx", "warn", "existing nginx configuration will be preserved untouched (%s). NGM manages only its own include tree", detail)
	} else {
		r.add("nginx", "fail", "existing customised nginx configuration found (%s). Re-run with --adopt-existing-nginx to install alongside it; NGM never edits third-party files", detail)
	}
	return "customized"
}

// nginxCustomizations lists signs that the nginx configuration is not the
// pristine distribution default.
func nginxCustomizations(ctx context.Context) []string {
	var out []string
	// Modified conffiles (dpkg records the shipped md5 of each).
	cf, _ := run(ctx, "dpkg-query", "-W", "-f=${Conffiles}\n", "nginx-common")
	for _, l := range strings.Split(cf, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.HasPrefix(f[0], "/etc/nginx/") {
			continue
		}
		sum, err := md5File(f[0])
		if err != nil {
			continue // removed conffile: not a takeover risk
		}
		if sum != f[1] {
			out = append(out, "modified "+f[0])
		}
	}
	// Extra enabled sites / conf.d snippets / streams.
	if es, err := os.ReadDir("/etc/nginx/sites-enabled"); err == nil {
		for _, e := range es {
			if e.Name() != "default" {
				out = append(out, "site "+e.Name())
			}
		}
	}
	for _, d := range []string{"/etc/nginx/conf.d", "/etc/nginx/streams-enabled", "/etc/nginx/stream.d"} {
		if es, err := os.ReadDir(d); err == nil {
			for _, e := range es {
				out = append(out, filepath.Join(d, e.Name()))
			}
		}
	}
	return out
}

func md5File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
