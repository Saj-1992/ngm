// Package helper implements ngm-helper: the small privileged service that
// performs allowlisted, typed operations on behalf of ngm-ops (MASTER_SPEC §3,
// §11). There is no generic exec: each operation runs fixed binaries with
// fixed argument shapes, a scrubbed environment, and bounded output.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/observe"
)

// Runner executes an allowlisted binary. Name is a key of binaries, never a path.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

// binaries maps logical names to the only absolute paths that may be executed.
var binaries = map[string][]string{
	"dpkg-query":  {"/usr/bin/dpkg-query"},
	"nginx":       {"/usr/sbin/nginx"},
	"systemctl":   {"/usr/bin/systemctl", "/bin/systemctl"},
	"ss":          {"/usr/bin/ss", "/bin/ss", "/usr/sbin/ss"},
	"ufw":         {"/usr/sbin/ufw"},
	"systemd-run": {"/usr/bin/systemd-run", "/bin/systemd-run"},
	"sshd":        {"/usr/sbin/sshd"},
}

// ExecRunner runs binaries with a minimal environment and 1 MiB output caps.
type ExecRunner struct{}

type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	paths, ok := binaries[name]
	if !ok {
		return nil, nil, fmt.Errorf("binary %q not allowlisted", name)
	}
	var bin string
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, nil, fmt.Errorf("%w: %s", os.ErrNotExist, name)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	out, errb := &capped{max: 1 << 20}, &capped{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// Policy decides which peers may call which operations.
type Policy struct {
	// Allowed maps a UID to the operations it may invoke ("*" = all).
	Allowed map[uint32][]string
}

func (p Policy) permits(uid uint32, op string) bool {
	for _, o := range p.Allowed[uid] {
		if o == "*" || o == op {
			return true
		}
	}
	return false
}

// Helper dispatches operations.
type Helper struct {
	Policy Policy
	Run    Runner
	Nginx  *NginxOps
	FW     *Firewall
	Log    func(msg string, kv ...any)
}

// Ops lists the allowlisted operations.
var Ops = []string{"ping", "observe.nginx", "nginx.state", "nginx.ensure_layout", "nginx.stage", "nginx.activate", "nginx.gc", "nginx.disable_default_site",
	"fw.state", "fw.apply", "fw.confirm", "fw.revert", "acme.put", "acme.clear",
	"site.publish", "site.activate", "site.state", "site.gc", "site.remove"}

// mutating operations require a valid job lease fence.
var mutating = map[string]bool{"nginx.ensure_layout": true, "nginx.stage": true, "nginx.activate": true, "nginx.gc": true, "nginx.disable_default_site": true,
	"fw.apply": true, "fw.confirm": true, "fw.revert": true, "acme.put": true, "acme.clear": true,
	"site.publish": true, "site.activate": true, "site.gc": true, "site.remove": true}

// noArgs operations must be called without arguments.
var noArgs = map[string]bool{"ping": true, "observe.nginx": true, "nginx.state": true, "nginx.disable_default_site": true, "fw.state": true}

func known(op string) bool {
	for _, o := range Ops {
		if o == op {
			return true
		}
	}
	return false
}

// Handle implements ipc.Handler.
func (h *Helper) Handle(ctx context.Context, peer ipc.Peer, req ipc.Request) (any, error) {
	if !known(req.Op) {
		h.log("helper: unknown op", "op", req.Op, "uid", peer.UID, "pid", peer.PID)
		return nil, &ipc.Error{Code: "unknown_op", Message: "operation not allowlisted"}
	}
	if !h.Policy.permits(peer.UID, req.Op) {
		h.log("helper: denied", "op", req.Op, "uid", peer.UID, "pid", peer.PID)
		return nil, &ipc.Error{Code: "forbidden", Message: "peer not permitted for this operation"}
	}
	if noArgs[req.Op] && len(req.Args) > 0 && string(req.Args) != "null" && string(req.Args) != "{}" {
		// Keep each operation's argument surface explicit.
		return nil, &ipc.Error{Code: "bad_args", Message: "operation takes no arguments"}
	}
	if mutating[req.Op] {
		if h.Nginx == nil {
			return nil, &ipc.Error{Code: "unavailable", Message: "nginx operations not configured"}
		}
		fence := h.Nginx.checkFence
		if strings.HasPrefix(req.Op, "fw.") {
			fence = h.Nginx.checkFenceFor("firewall")
		}
		if strings.HasPrefix(req.Op, "acme.") {
			fence = h.Nginx.checkFenceFor("certificate")
		}
		if strings.HasPrefix(req.Op, "site.") {
			fence = h.Nginx.checkFenceFor("website-publish")
		}
		if err := fence(ctx, req); err != nil {
			h.log("helper: fence rejected", "op", req.Op, "uid", peer.UID, "job", req.JobID)
			return nil, err
		}
		h.log("helper: mutating op", "op", req.Op, "uid", peer.UID, "job", req.JobID, "fence", req.Fence)
	}
	switch req.Op {
	case "ping":
		return map[string]any{"version": buildinfo.Version, "pid": os.Getpid(), "uid": os.Getuid()}, nil
	case "observe.nginx":
		return ObserveNginx(ctx, h.Run), nil
	case "nginx.state":
		if h.Nginx == nil {
			return nil, &ipc.Error{Code: "unavailable", Message: "nginx operations not configured"}
		}
		return h.Nginx.State()
	case "nginx.ensure_layout":
		var a struct {
			Stream bool `json:"stream"`
		}
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		return h.Nginx.EnsureLayout(ctx, a.Stream)
	case "nginx.stage":
		var a StageArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		return h.Nginx.Stage(ctx, a)
	case "nginx.activate":
		var a ActivateArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		return h.Nginx.Activate(ctx, a)
	case "nginx.gc":
		var a GCArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		return h.Nginx.GC(ctx, a)
	case "nginx.disable_default_site":
		return h.Nginx.DisableDefaultSite(ctx)
	case "site.publish", "site.activate", "site.state", "site.gc", "site.remove":
		if h.Nginx == nil {
			return nil, &ipc.Error{Code: "unavailable", Message: "nginx operations not configured"}
		}
		var a SiteArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		switch req.Op {
		case "site.publish":
			return h.Nginx.SitePublish(ctx, a)
		case "site.activate":
			return h.Nginx.SiteActivate(ctx, a)
		case "site.state":
			return h.Nginx.SiteState(a)
		case "site.gc":
			return h.Nginx.SiteGC(ctx, a)
		}
		return h.Nginx.SiteRemove(ctx, a)
	case "acme.put", "acme.clear":
		var a AcmeArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		if req.Op == "acme.put" {
			return h.Nginx.AcmePut(ctx, a)
		}
		return h.Nginx.AcmeClear(ctx, a)
	case "fw.state", "fw.apply", "fw.confirm", "fw.revert":
		if h.FW == nil {
			return nil, &ipc.Error{Code: "unavailable", Message: "firewall operations not configured"}
		}
	}
	switch req.Op {
	case "fw.state":
		return h.FW.State(ctx)
	case "fw.apply":
		var a FWApplyArgs
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		return h.FW.Apply(ctx, a)
	case "fw.confirm", "fw.revert":
		var a struct {
			PlanID string `json:"plan_id"`
		}
		if err := decode(req.Args, &a); err != nil {
			return nil, err
		}
		if req.Op == "fw.confirm" {
			return map[string]bool{"confirmed": true}, h.FW.Confirm(ctx, a.PlanID)
		}
		return h.FW.Revert(ctx, a.PlanID)
	}
	return nil, &ipc.Error{Code: "unknown_op", Message: "operation not allowlisted"}
}

func (h *Helper) log(msg string, kv ...any) {
	if h.Log != nil {
		h.Log(msg, kv...)
	}
}

// ObserveNginx gathers data-plane facts. Every failure becomes an Errors entry
// rather than a guessed value.
func ObserveNginx(ctx context.Context, r Runner) observe.Nginx {
	n := observe.Nginx{ServiceState: "unknown", Listeners: []string{}, PackageOrigin: "unknown"}
	out, _, err := r.Run(ctx, "dpkg-query", "-W", DpkgFormat, "nginx", "nginx-common", "nginx-core", "libnginx-mod-stream")
	if err != nil && len(out) == 0 {
		n.Errors = append(n.Errors, "dpkg-query: "+short(err))
	}
	pk := ParseDpkg(string(out))
	if p, ok := pk["nginx"]; ok && p.Installed {
		n.Installed = true
		n.PackageVersion = p.Version
		n.PackageOrigin = Origin(p)
	} else if p, ok := pk["nginx-common"]; ok && p.Installed {
		// nginx-core flavour or partial install: still report what exists.
		n.PackageVersion = p.Version
		n.PackageOrigin = Origin(p)
	}
	if _, err := os.Stat("/usr/sbin/nginx"); err == nil {
		n.Installed = true
		_, se, err := r.Run(ctx, "nginx", "-V")
		if err != nil {
			n.Errors = append(n.Errors, "nginx -V: "+short(err))
		}
		static, dynamic := ParseNginxV(string(se), &n)
		// A dynamic stream module counts only if its package is installed and
		// a load_module snippet is enabled.
		n.StreamModule = static || (dynamic && pk["libnginx-mod-stream"].Installed && streamModuleEnabled())
	}
	out, _, err = r.Run(ctx, "systemctl", "show", "nginx.service", "--property=ActiveState,MainPID,LoadState")
	if err != nil {
		n.Errors = append(n.Errors, "systemctl: "+short(err))
	} else {
		props := ParseProps(string(out))
		if props["LoadState"] == "not-found" {
			n.ServiceState = "not-found"
		} else if s := props["ActiveState"]; s != "" {
			n.ServiceState = s
		}
		n.MainPID, _ = strconv.Atoi(props["MainPID"])
	}
	out, _, err = r.Run(ctx, "ss", "-H", "-t", "-l", "-n", "-p")
	if err != nil {
		n.Errors = append(n.Errors, "ss: "+short(err))
	} else {
		n.Listeners = ParseSSListeners(string(out), "nginx")
		n.OtherListeners = ParseOtherListeners(string(out), "nginx")
	}
	return n
}

func streamModuleEnabled() bool {
	entries, err := os.ReadDir("/etc/nginx/modules-enabled")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "stream") {
			return true
		}
	}
	return false
}

func short(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Pkg is a dpkg package record.
type Pkg struct {
	Installed  bool
	Version    string
	Maintainer string
}

// DpkgFormat is the dpkg-query output format parsed by ParseDpkg.
const DpkgFormat = "-f=${Package}\t${Status}\t${Version}\t${Maintainer}\n"

// ParseDpkg parses dpkg-query output in DpkgFormat.
func ParseDpkg(out string) map[string]Pkg {
	res := map[string]Pkg{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.SplitN(l, "\t", 4)
		if len(f) < 3 || f[0] == "" {
			continue
		}
		p := Pkg{Installed: f[1] == "install ok installed", Version: f[2]}
		if len(f) == 4 {
			p.Maintainer = f[3]
		}
		res[f[0]] = p
	}
	return res
}

// Origin classifies a package as from the Ubuntu archive or not. Ubuntu
// archive builds carry an "ubuntu" version suffix and an Ubuntu maintainer;
// nginx.org builds (e.g. 1.26.2-1~noble, "NGINX Packaging") do not.
func Origin(p Pkg) string {
	if p.Version == "" {
		return "unknown"
	}
	if strings.Contains(p.Version, "ubuntu") && strings.Contains(strings.ToLower(p.Maintainer), "ubuntu") {
		return "ubuntu"
	}
	return "other"
}

// ParseNginxV extracts the version and compile-time capabilities from
// `nginx -V` (printed on stderr). StreamStatic reports a non-dynamic stream build.
func ParseNginxV(s string, n *observe.Nginx) (streamStatic, streamDynamic bool) {
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "nginx version: nginx/"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				n.Version = f[0]
			}
		}
	}
	n.HTTPV2 = strings.Contains(s, "--with-http_v2_module")
	n.SSLPreread = strings.Contains(s, "--with-stream_ssl_preread_module")
	for _, tok := range strings.Fields(s) {
		switch tok {
		case "--with-stream":
			streamStatic = true
		case "--with-stream=dynamic":
			streamDynamic = true
		}
	}
	return
}

// ParseProps parses `systemctl show` KEY=VALUE output.
func ParseProps(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m
}

// ParseSSListeners extracts "addr:port" of LISTEN sockets owned by proc.
func ParseSSListeners(s, proc string) []string {
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 || !strings.Contains(l, `(("`+proc+`"`) {
			continue
		}
		// State Recv-Q Send-Q Local Peer Process
		seen[f[3]] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseOtherListeners lists "addr:port proc" for LISTEN sockets not owned by proc.
func ParseOtherListeners(s, proc string) []string {
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || strings.Contains(l, `(("`+proc+`"`) {
			continue
		}
		name := "unknown"
		if i := strings.Index(l, `(("`); i >= 0 {
			rest := l[i+3:]
			if j := strings.IndexByte(rest, 34); j > 0 {
				name = rest[:j]
			}
		}
		seen[f[3]+" "+name] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MarshalIndent is a helper for CLI display.
func MarshalIndent(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// ErrNotLinux is returned when the helper is started off Linux.
var ErrNotLinux = errors.New("ngm helper requires Linux")
