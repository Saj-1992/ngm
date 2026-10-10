package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ngm-gateway/ngm/internal/fwspec"
	"github.com/ngm-gateway/ngm/internal/ipc"
)

// FWRule is the typed rule (see package fwspec).
type FWRule = fwspec.Rule

// SSHGuardKey marks the rule NGM adds to keep SSH reachable.
const SSHGuardKey = fwspec.SSHGuardKey

// FWState is the observed UFW state.
type FWState struct {
	Installed bool              `json:"installed"`
	Active    bool              `json:"active"`
	Defaults  string            `json:"defaults"`
	Owned     map[string]string `json:"owned"`   // key → rule text (from `ufw show added`)
	Foreign   []string          `json:"foreign"` // non-NGM rules (never modified)
	SSHPorts  []int             `json:"ssh_ports"`
	SSHPeers  []string          `json:"ssh_peers"` // current SSH client addresses
	SSHOpen   bool              `json:"ssh_open"`  // every SSH port has an allow rule (any source)
}

var commentRe = regexp.MustCompile(`comment '(ngm:[a-z0-9-]+)'`)

// ParseShowAdded parses `ufw show added` output.
func ParseShowAdded(out string) (owned map[string]string, foreign []string) {
	owned = map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "ufw ") {
			continue
		}
		if m := commentRe.FindStringSubmatch(l); m != nil {
			owned[strings.TrimPrefix(m[1], "ngm:")] = l
		} else {
			foreign = append(foreign, l)
		}
	}
	sort.Strings(foreign)
	return
}

// sshAllowed reports whether rule texts allow port from anywhere.
func sshAllowed(rules []string, port int) bool {
	p := strconv.Itoa(port)
	for _, l := range rules {
		f := strings.Fields(strings.Split(l, " comment ")[0])
		if len(f) < 2 || (f[1] != "allow" && f[1] != "limit") {
			continue
		}
		joined := " " + strings.Join(f[2:], " ") + " "
		anySrc := !strings.Contains(joined, " from ") || strings.Contains(joined, " from any ")
		hasPort := strings.Contains(joined, " "+p+"/tcp ") || strings.Contains(joined, " "+p+" ") || strings.Contains(joined, " port "+p+" ")
		if anySrc && hasPort && !strings.Contains(joined, "proto udp") {
			return true
		}
	}
	return false
}

// Firewall implements UFW operations (root, inside ngm-helper or fw-revert).
type Firewall struct {
	Run     Runner
	PlanDir string // /var/lib/ngm/fw (root-only)
	NGMBin  string // /opt/ngm/current/ngm
	Config  string // /etc/ngm/ngm.json
	mu      sync.Mutex
}

func (f *Firewall) ufw(ctx context.Context, args ...string) (string, error) {
	o, e, err := f.Run.Run(ctx, "ufw", args...)
	out := strings.TrimSpace(string(o) + "\n" + string(e))
	if err != nil {
		return out, fmt.Errorf("ufw %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

// State reads UFW and SSH facts (read-only).
func (f *Firewall) State(ctx context.Context) (*FWState, error) {
	st := &FWState{Owned: map[string]string{}}
	out, err := f.ufw(ctx, "status", "verbose")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not exist") {
			return st, nil
		}
		return nil, err
	}
	st.Installed = true
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Status: ") {
			st.Active = strings.TrimSpace(strings.TrimPrefix(l, "Status: ")) == "active"
		}
		if strings.HasPrefix(l, "Default: ") {
			st.Defaults = strings.TrimSpace(strings.TrimPrefix(l, "Default: "))
		}
	}
	added, err := f.ufw(ctx, "show", "added")
	if err != nil {
		return nil, err
	}
	st.Owned, st.Foreign = ParseShowAdded(added)
	if o, _, err := f.Run.Run(ctx, "sshd", "-T"); err == nil {
		for _, l := range strings.Split(string(o), "\n") {
			if p, ok := strings.CutPrefix(l, "port "); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
					st.SSHPorts = append(st.SSHPorts, n)
				}
			}
		}
	}
	if len(st.SSHPorts) == 0 {
		st.SSHPorts = []int{22}
	}
	if o, _, err := f.Run.Run(ctx, "ss", "-H", "-t", "-n", "state", "established"); err == nil {
		for _, l := range strings.Split(string(o), "\n") {
			fl := strings.Fields(l)
			if len(fl) < 4 {
				continue
			}
			for _, p := range st.SSHPorts {
				if strings.HasSuffix(fl[2], ":"+strconv.Itoa(p)) {
					st.SSHPeers = append(st.SSHPeers, fl[3])
				}
			}
		}
	}
	all := append(append([]string{}, st.Foreign...), values(st.Owned)...)
	st.SSHOpen = true
	for _, p := range st.SSHPorts {
		if !sshAllowed(all, p) {
			st.SSHOpen = false
		}
	}
	return st, nil
}

func values(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// FWApplyArgs describes an owned-rule delta.
type FWApplyArgs struct {
	fencedArgs
	PlanID       string   `json:"plan_id"`
	Add          []FWRule `json:"add"`
	Delete       []FWRule `json:"delete"` // owned rules to remove (full definition, for re-adding on revert)
	Enable       bool     `json:"enable"`
	WatchdogSecs int      `json:"watchdog_seconds"` // 0 = no watchdog (safe change)
}

// FWPlan is the persisted inverse of an applied delta.
type FWPlan struct {
	PlanID     string   `json:"plan_id"`
	RemoveKeys []FWRule `json:"remove"`  // rules added by the change
	ReAdd      []FWRule `json:"re_add"`  // rules deleted by the change
	Disable    bool     `json:"disable"` // change enabled UFW
}

// FWApplyResult reports what happened.
type FWApplyResult struct {
	Added    []string `json:"added"`
	Shared   []string `json:"shared"` // identical foreign rule existed; not owned, never deleted
	Deleted  []string `json:"deleted"`
	Enabled  bool     `json:"enabled"`
	Watchdog string   `json:"watchdog,omitempty"`
}

var planRe = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// Apply executes the delta with SSH protection and an optional dead-man
// watchdog (a transient systemd timer that reverts unless confirmed).
func (f *Firewall) Apply(ctx context.Context, a FWApplyArgs) (*FWApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !planRe.MatchString(a.PlanID) {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid plan id"}
	}
	for _, r := range append(append([]FWRule{}, a.Add...), a.Delete...) {
		if err := r.Validate(); err != nil {
			return nil, &ipc.Error{Code: "bad_args", Message: err.Error()}
		}
	}
	st, err := f.State(ctx)
	if err != nil {
		return nil, err
	}
	if !st.Installed {
		return nil, &ipc.Error{Code: "ufw_missing", Message: "ufw is not installed"}
	}
	for _, r := range a.Delete {
		if r.Key == SSHGuardKey {
			return nil, &ipc.Error{Code: "ssh_guard", Message: "the SSH guard rule cannot be removed by NGM"}
		}
	}
	for _, r := range a.Add {
		for _, p := range st.SSHPorts {
			if r.Port == p && r.Action == "deny" {
				return nil, &ipc.Error{Code: "ssh_guard", Message: fmt.Sprintf("refusing a deny rule on SSH port %d", p)}
			}
		}
	}
	add := append([]FWRule{}, a.Add...)
	// Enabling without an SSH allow rule would lock out management: add the guard first.
	if (a.Enable || st.Active) && !st.SSHOpen {
		for _, p := range st.SSHPorts {
			k := SSHGuardKey
			if p != 22 || len(st.SSHPorts) > 1 {
				k = fmt.Sprintf("%s-%d", SSHGuardKey, p)
			}
			add = append([]FWRule{{Key: k, Action: "allow", Proto: "tcp", Port: p, Source: "any"}}, add...)
		}
	}
	plan := FWPlan{PlanID: a.PlanID, Disable: a.Enable && !st.Active}
	res := &FWApplyResult{}
	if a.WatchdogSecs > 0 {
		if a.WatchdogSecs < 30 || a.WatchdogSecs > 1800 {
			return nil, &ipc.Error{Code: "bad_args", Message: "watchdog must be 30–1800 s"}
		}
	}
	// Persist the inverse plan before touching anything, then arm the watchdog.
	for _, r := range add {
		if _, exists := st.Owned[r.Key]; !exists {
			plan.RemoveKeys = append(plan.RemoveKeys, r)
		}
	}
	for _, r := range a.Delete {
		if _, exists := st.Owned[r.Key]; exists {
			plan.ReAdd = append(plan.ReAdd, r)
		}
	}
	if err := f.savePlan(plan); err != nil {
		return nil, err
	}
	if a.WatchdogSecs > 0 {
		unit := "ngm-fw-watchdog-" + strings.ToLower(a.PlanID)
		if _, se, err := f.Run.Run(ctx, "systemd-run", "--unit="+unit, "--on-active="+strconv.Itoa(a.WatchdogSecs), "--timer-property=AccuracySec=1s",
			f.NGMBin, "--config", f.Config, "fw-revert", a.PlanID); err != nil {
			return nil, &ipc.Error{Code: "watchdog_failed", Message: "could not arm watchdog; nothing changed: " + string(se)}
		}
		res.Watchdog = unit
	}
	for _, r := range add {
		if _, exists := st.Owned[r.Key]; exists {
			continue
		}
		out, err := f.ufw(ctx, append(r.Args(), "comment", "ngm:"+r.Key)...)
		if err != nil {
			return res, &ipc.Error{Code: "ufw_failed", Message: err.Error()}
		}
		if strings.Contains(out, "Skipping adding existing rule") {
			res.Shared = append(res.Shared, r.Key)
		} else {
			res.Added = append(res.Added, r.Key)
		}
	}
	for _, r := range a.Delete {
		if _, exists := st.Owned[r.Key]; !exists {
			continue
		}
		if _, err := f.ufw(ctx, append([]string{"--force", "delete"}, r.Args()...)...); err != nil {
			return res, &ipc.Error{Code: "ufw_failed", Message: err.Error()}
		}
		res.Deleted = append(res.Deleted, r.Key)
	}
	if a.Enable && !st.Active {
		after, err := f.State(ctx)
		if err != nil || !after.SSHOpen {
			return res, &ipc.Error{Code: "ssh_guard", Message: "refusing to enable: SSH would not be allowed"}
		}
		if _, err := f.ufw(ctx, "--force", "enable"); err != nil {
			return res, &ipc.Error{Code: "ufw_failed", Message: err.Error()}
		}
		res.Enabled = true
	}
	return res, nil
}

func (f *Firewall) planPath(id string) string { return filepath.Join(f.PlanDir, "revert-"+id+".json") }

func (f *Firewall) savePlan(p FWPlan) error {
	if err := os.MkdirAll(f.PlanDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	return os.WriteFile(f.planPath(p.PlanID), b, 0o600)
}

// Confirm disarms the watchdog and forgets the revert plan.
func (f *Firewall) Confirm(ctx context.Context, planID string) error {
	if !planRe.MatchString(planID) {
		return &ipc.Error{Code: "bad_args", Message: "invalid plan id"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	unit := "ngm-fw-watchdog-" + strings.ToLower(planID)
	_, _, _ = f.Run.Run(ctx, "systemctl", "stop", unit+".timer")
	if _, err := os.Stat(f.planPath(planID)); err != nil {
		return &ipc.Error{Code: "no_plan", Message: "no pending plan (already confirmed or reverted)"}
	}
	return os.Remove(f.planPath(planID))
}

// Revert applies the stored inverse plan (idempotent) and removes it.
func (f *Firewall) Revert(ctx context.Context, planID string) (map[string]any, error) {
	if !planRe.MatchString(planID) {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid plan id"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.planPath(planID))
	if err != nil {
		return map[string]any{"reverted": false, "reason": "no pending plan"}, nil
	}
	var p FWPlan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	st, err := f.State(ctx)
	if err != nil {
		return nil, err
	}
	if p.Disable && st.Active {
		if _, err := f.ufw(ctx, "disable"); err != nil {
			return nil, err
		}
	}
	for _, r := range p.RemoveKeys {
		if _, owned := st.Owned[r.Key]; owned {
			_, _ = f.ufw(ctx, append([]string{"--force", "delete"}, r.Args()...)...)
		}
	}
	for _, r := range p.ReAdd {
		_, _ = f.ufw(ctx, append(r.Args(), "comment", "ngm:"+r.Key)...)
	}
	_, _, _ = f.Run.Run(ctx, "systemctl", "stop", "ngm-fw-watchdog-"+strings.ToLower(planID)+".timer")
	_ = os.Remove(f.planPath(planID))
	return map[string]any{"reverted": true, "disabled": p.Disable, "removed": len(p.RemoveKeys), "re_added": len(p.ReAdd)}, nil
}
