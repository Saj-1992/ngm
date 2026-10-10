package deploy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/recovery"
)

// KindReconcile is the supervised fix for drift between NGM's active record
// and the generation the data plane actually serves (Recovery Center).
const KindReconcile = "deploy.reconcile"

// ReconcilePayload selects the supervised outcome.
type ReconcilePayload struct {
	// Mode "adopt" keeps the generation that is serving (after it verifies);
	// "restore" switches back to the recorded active generation (and verifies it).
	Mode       string `json:"mode"`
	IncidentID string `json:"incident_id,omitempty"`
}

// recordPointer stores the live generation pointer as an observation so the
// API can check drift without calling the helper.
func (c *Coordinator) recordPointer(ctx context.Context, cur string) {
	_ = observe.Record(context.WithoutCancel(ctx), c.DB, observe.KindPointer, observe.Pointer{Current: cur}, 0)
}

func (c *Coordinator) runReconcile(r *runner) {
	ctx := r.ctx
	var p ReconcilePayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	if p.Mode != "adopt" && p.Mode != "restore" {
		r.end(jobs.Blocked, "validation_failed", nil, &failure{Code: "validation_failed", Message: "mode must be adopt or restore"})
		return
	}
	var st map[string]any
	if err := c.call(ctx, r, "nginx.state", nil, &st); err != nil {
		r.end(jobs.Failed, "helper", nil, &failure{Code: "helper", Message: err.Error()})
		return
	}
	cur, _ := st["current"].(string)
	c.recordPointer(ctx, cur)
	prev, _ := c.active(ctx)
	recorded := helper.EmptyGen
	if prev != nil {
		recorded = prev.ID
	}
	impact := map[string]any{"serving": cur, "recorded": recorded, "mode": p.Mode}
	if err := r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, impact); err != nil {
		return
	}
	resolve := func(outcome, note string) {
		if p.IncidentID == "" {
			return
		}
		rs := &recovery.Service{DB: c.DB, Audit: c.Audit}
		if _, err := rs.ResolveVerified(context.WithoutCancel(ctx), p.IncidentID, r.j.ActorID, outcome, note); err != nil {
			c.Log.Warn("reconcile: incident not resolved", "incident", p.IncidentID, "err", err)
		}
	}
	if cur == recorded {
		// Nothing to change; still prove it serves before closing the incident.
		if prev != nil {
			if ev, ok := c.verify(ctx, recorded, prev.ProbeToken, prev.Summary); !ok {
				r.end(jobs.Blocked, "unverified", nil, &failure{Code: "recorded_unverified", Message: "the recorded generation is selected but does not verify", Details: ev})
				return
			}
		}
		_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
		_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
		_ = r.to(jobs.Applying, "apply", jobs.External, map[string]string{"action": "none"})
		_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, impact)
		resolve("failed", "reconcile job "+r.j.ID+": data plane already serves the recorded generation (verified)")
		r.end(jobs.Succeeded, "succeeded", map[string]any{"consistent": true, "serving": cur}, nil)
		return
	}
	switch p.Mode {
	case "adopt":
		g, err := c.loadGen(ctx, cur)
		if err != nil {
			r.end(jobs.Blocked, "unknown_generation", nil, &failure{Code: "unknown_generation", Message: fmt.Sprintf("the serving generation %q is not an NGM generation; use restore", cur)})
			return
		}
		_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
		_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
		_ = r.to(jobs.Applying, "apply", jobs.External, map[string]string{"action": "adopt", "generation": cur})
		_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, impact)
		ev, ok := c.verify(ctx, cur, g.ProbeToken, g.Summary)
		if !ok {
			// Nothing was changed: the operator can choose restore instead.
			_ = r.to(jobs.Compensating, "adopt_unverified", jobs.Idempotent, ev)
			r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "adopt_unverified", Message: "the serving generation does not verify; nothing was changed. Use restore.", Details: ev})
			return
		}
		if err := c.promote(ctx, r, cur, recorded, ev); err != nil {
			c.recoveryRequired(r, &failure{Code: "promote_failed", Message: err.Error()})
			return
		}
		resolve("succeeded", "reconcile job "+r.j.ID+": adopted serving generation "+cur+" after verification")
	case "restore":
		if prev == nil {
			r.end(jobs.Blocked, "nothing_recorded", nil, &failure{Code: "nothing_recorded", Message: "NGM has no recorded active generation to restore; use adopt"})
			return
		}
		if err := r.to(jobs.Staging, "stage", jobs.Idempotent, nil); err != nil {
			return
		}
		if _, ok := c.ensureOnDisk(r, prev, st); !ok {
			return
		}
		_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
		if err := r.to(jobs.Applying, "apply", jobs.External, map[string]string{"action": "restore", "generation": recorded}); err != nil {
			return
		}
		var act helper.ActivateResult
		if err := c.call(ctx, r, "nginx.activate", helper.ActivateArgs{GenID: recorded, Expected: cur}, &act); err != nil {
			c.resolveUncertain(r, recorded, cur, prev.Summary, err)
			return
		}
		if !act.Activated {
			_ = r.to(jobs.Compensating, "activate_failed", jobs.Idempotent, act)
			r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "nginx_test_failed", Message: "nginx -t rejected the recorded generation; the serving one stays", Details: act.TestOutput})
			return
		}
		_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, act)
		ev, ok := c.verify(ctx, recorded, prev.ProbeToken, prev.Summary)
		if !ok {
			c.compensate(r, recorded, cur, prev.Summary, &failure{Code: "verification_failed", Message: "restored generation did not verify; switched back", Details: ev})
			return
		}
		c.recordPointer(ctx, recorded)
		if cur != helper.EmptyGen {
			c.markGen(ctx, cur, "rolled_back")
		}
		resolve("rolled_back", "reconcile job "+r.j.ID+": restored recorded generation "+recorded+" (verified)")
		r.end(jobs.Succeeded, "succeeded", map[string]any{"restored": recorded, "replaced": cur, "verification": ev}, nil)
	}
}
