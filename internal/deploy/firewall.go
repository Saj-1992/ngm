package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/fwspec"
	"github.com/ngm-gateway/ngm/internal/fwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/observe"
)

// KindFirewall applies NGM-owned UFW rules.
const KindFirewall = "firewall.apply"

// FirewallPayload is the job payload.
type FirewallPayload struct {
	Enable bool `json:"enable"`
}

// KindFirewallObservation is the runtime observation kind for UFW state.
const KindFirewallObservation = "firewall"

// firewall job tuning (tests shorten these).
var (
	fwWatchdog     = 120 * time.Second
	fwConfirmSlack = 15 * time.Second
	fwPoll         = time.Second
)

// SetFirewallTiming overrides watchdog/confirmation timing (tests).
func SetFirewallTiming(watchdog, slack, poll time.Duration) {
	fwWatchdog, fwConfirmSlack, fwPoll = watchdog, slack, poll
}

func (c *Coordinator) runFirewall(r *runner) {
	ctx := r.ctx
	var p FirewallPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	fw := &fwstore.Service{DB: c.DB, Audit: c.Audit}
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	if c.blockedByIncident(r, KindFirewall) {
		return
	}
	desired, err := fw.List(ctx)
	if err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	removed, _ := fw.Removed(ctx)
	for _, d := range desired {
		if err := d.Typed().Validate(); err != nil {
			r.end(jobs.Blocked, "validation_failed", nil, &failure{Code: "validation_failed", Message: err.Error()})
			return
		}
	}
	var st helper.FWState
	if err := c.call(ctx, r, "fw.state", nil, &st); err != nil {
		c.failSafely(r, &failure{Code: "helper", Message: err.Error()})
		return
	}
	if !st.Installed {
		r.end(jobs.Blocked, "ufw_missing", nil, &failure{Code: "ufw_missing", Message: "ufw is not installed on this host"})
		return
	}
	for _, d := range desired {
		for _, sp := range st.SSHPorts {
			if d.Port == sp && d.Action == "deny" {
				r.end(jobs.Blocked, "ssh_guard", nil, &failure{Code: "ssh_guard", Message: fmt.Sprintf("rule %q denies the SSH port %d", d.Key, sp)})
				return
			}
		}
	}
	var add, del []fwspec.Rule
	want := map[string]bool{}
	for _, d := range desired {
		want[d.Key] = true
		if _, ok := st.Owned[d.Key]; !ok {
			add = append(add, d.Typed())
		}
	}
	for _, rm := range removed {
		if _, ok := st.Owned[rm.Key]; ok && !want[rm.Key] {
			del = append(del, rm.Typed())
		}
	}
	risky := (p.Enable && !st.Active) || (st.Active && len(del) > 0)
	for _, a := range add {
		if a.Action != "allow" && (st.Active || p.Enable) {
			risky = true
		}
	}
	impact := map[string]any{"add": keys(add), "delete": keys(del), "enable": p.Enable && !st.Active, "risky": risky,
		"ssh_ports": st.SSHPorts, "ssh_sessions": st.SSHPeers, "foreign_rules_preserved": len(st.Foreign)}
	if err := r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, impact); err != nil {
		return
	}
	if len(add) == 0 && len(del) == 0 && !(p.Enable && !st.Active) {
		r.end(jobs.Blocked, "no_changes", nil, &failure{Code: "no_changes", Message: "UFW already matches the desired NGM rules"})
		return
	}
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, map[string]any{"ufw_active": st.Active, "ssh_open": st.SSHOpen})
	if err := r.to(jobs.Applying, "apply", jobs.External, impact); err != nil {
		return
	}
	wd := 0
	if risky {
		wd = int(fwWatchdog.Seconds())
	}
	var res helper.FWApplyResult
	err = c.call(ctx, r, "fw.apply", helper.FWApplyArgs{PlanID: r.j.ID, Add: add, Delete: del, Enable: p.Enable, WatchdogSecs: wd}, &res)
	if err != nil {
		// Partial application is possible: revert from the stored plan.
		_ = r.to(jobs.Compensating, "apply_failed", jobs.External, map[string]string{"error": err.Error()})
		var out map[string]any
		if rerr := c.call(context.WithoutCancel(ctx), r, "fw.revert", map[string]string{"plan_id": r.j.ID}, &out); rerr != nil {
			c.recoveryRequired(r, &failure{Code: "firewall_revert_failed", Message: "firewall change failed and revert failed: " + rerr.Error()})
			return
		}
		r.end(jobs.RolledBack, "rolled_back", out, &failure{Code: "firewall_apply_failed", Message: err.Error()})
		return
	}
	// The confirmation window is journaled so the UI can show a real countdown.
	deadline := time.Now().Add(fwWatchdog - fwConfirmSlack)
	vev := map[string]any{"result": res, "confirm_required": risky}
	if risky {
		vev["confirm_deadline"] = deadline.UTC()
	}
	if err := r.to(jobs.Verifying, "verify", jobs.Idempotent, vev); err != nil {
		return
	}
	var after helper.FWState
	if err := c.call(ctx, r, "fw.state", nil, &after); err != nil || !after.SSHOpen && after.Active {
		c.fwRevert(r, &failure{Code: "ssh_not_allowed", Message: "after the change SSH is not allowed; reverting"})
		return
	}
	present := map[string]bool{}
	for k := range after.Owned {
		present[k] = true
	}
	for _, d := range desired {
		if !present[d.Key] && !contains(res.Shared, d.Key) {
			c.fwRevert(r, &failure{Code: "verification_failed", Message: "rule " + d.Key + " is not present after apply"})
			return
		}
	}
	if risky {
		// Dead-man confirmation: an operator must prove access still works.
		if r.c.Broker != nil {
			_, _ = r.c.Broker.Publish(ctx, "firewall.confirm_required", "global", map[string]any{"job_id": r.j.ID, "deadline": deadline.UTC()})
		}
		confirmed := false
		for time.Now().Before(deadline) {
			var v string
			if err := c.DB.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", fwstore.SettingConfirm(r.j.ID)).Scan(&v); err == nil && v == "true" {
				confirmed = true
				break
			}
			select {
			case <-ctx.Done():
				return // lease lost; the watchdog reverts if nobody confirms
			case <-time.After(fwPoll):
			}
		}
		_, _ = c.DB.ExecContext(context.WithoutCancel(ctx), "DELETE FROM settings WHERE key=?", fwstore.SettingConfirm(r.j.ID))
		if !confirmed {
			c.fwRevert(r, &failure{Code: "not_confirmed", Message: "the change was not confirmed in time; reverted to keep management access"})
			return
		}
		if err := c.call(ctx, r, "fw.confirm", map[string]string{"plan_id": r.j.ID}, nil); err != nil {
			c.recoveryRequired(r, &failure{Code: "confirm_failed", Message: err.Error()})
			return
		}
	} else {
		_ = c.call(ctx, r, "fw.confirm", map[string]string{"plan_id": r.j.ID}, nil)
	}
	_ = fw.MarkApplied(ctx, present)
	_ = observe.Record(ctx, c.DB, KindFirewallObservation, after, 0)
	r.end(jobs.Succeeded, "succeeded", map[string]any{"result": res, "ufw_active": after.Active}, nil)
}

func (c *Coordinator) fwRevert(r *runner, f *failure) {
	ctx := context.WithoutCancel(r.ctx)
	_ = r.to(jobs.Compensating, "revert", jobs.External, f)
	var out map[string]any
	if err := c.call(ctx, r, "fw.revert", map[string]string{"plan_id": r.j.ID}, &out); err != nil {
		c.recoveryRequired(r, &failure{Code: "firewall_revert_failed", Message: err.Error() + " (the watchdog timer, if armed, will still revert)"})
		return
	}
	var after helper.FWState
	if err := c.call(ctx, r, "fw.state", nil, &after); err == nil {
		present := map[string]bool{}
		for k := range after.Owned {
			present[k] = true
		}
		_ = (&fwstore.Service{DB: c.DB, Audit: c.Audit}).MarkApplied(ctx, present)
		_ = observe.Record(ctx, c.DB, KindFirewallObservation, after, 0)
	}
	r.end(jobs.RolledBack, "rolled_back", out, f)
}

func keys(rs []fwspec.Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Key)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// firewallLocks is the lock set for firewall jobs.
var firewallLocks = []locks.Resource{locks.Firewall}
