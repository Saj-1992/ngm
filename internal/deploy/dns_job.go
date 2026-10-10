package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/cloudflare"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Cloudflare DNS jobs (the API never calls Cloudflare itself).
const (
	KindDNSPreview = "dns.cloudflare.preview"
	KindDNSApply   = "dns.cloudflare.apply"
)

// CloudflareTokenRef is where the scoped API token lives.
var CloudflareTokenRef = vault.Ref{Type: "cloudflare_token", Scope: "global", Name: "token"}

// DNSPayload drives both jobs.
type DNSPayload struct {
	DomainID string   `json:"domain_id"`
	PlanHash string   `json:"plan_hash,omitempty"` // apply only: must equal a fresh preview
	Adopt    []string `json:"adopt,omitempty"`     // apply only: external record ids to take over
}

var dnsLocks = []locks.Resource{locks.DNSProvider}

// CloudflareBase overrides the API base (tests).
var CloudflareBase = ""

func (c *Coordinator) cloudflareClient(ctx context.Context) (*cloudflare.Client, error) {
	if c.Vault == nil {
		return nil, fmt.Errorf("vault unavailable")
	}
	tok, err := c.Vault.Get(ctx, CloudflareTokenRef)
	if err != nil {
		return nil, fmt.Errorf("no Cloudflare API token configured")
	}
	return &cloudflare.Client{Token: string(tok), Base: CloudflareBase}, nil
}

func desiredFrom(d *domains.Domain) []cloudflare.Desired {
	var out []cloudflare.Desired
	for _, e := range d.Expected {
		if e.Type == "NS" {
			continue // delegation is managed at the registrar, not in the zone
		}
		ttl := 1
		if e.TTL != nil {
			ttl = *e.TTL
		}
		out = append(out, cloudflare.Desired{Name: e.Name, Type: e.Type, Value: e.Value, TTL: ttl})
	}
	return out
}

// dnsPlan builds a fresh plan (shared by preview and apply).
func (c *Coordinator) dnsPlan(ctx context.Context, p DNSPayload) (*cloudflare.Client, *domains.Domain, *cloudflare.Plan, []string, error) {
	reg := &domains.Service{DB: c.DB, Audit: c.Audit}
	d, err := reg.Get(ctx, p.DomainID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cl, err := c.cloudflareClient(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := cl.Verify(ctx); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("token check: %w", err)
	}
	z, err := cl.FindZone(ctx, d.FQDN)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cur, err := cl.Records(ctx, z.ID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	want := desiredFrom(d)
	plan, err := cloudflare.MakePlan(z, cur, want)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, _ = c.DB.ExecContext(ctx, "UPDATE domains SET dns_provider='cloudflare', provider_zone_id=? WHERE id=?", z.ID, d.ID)
	return cl, d, plan, cloudflare.Drift(cur, want), nil
}

func (c *Coordinator) runDNS(r *runner) {
	ctx := r.ctx
	var p DNSPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	cl, d, plan, drift, err := c.dnsPlan(ctx, p)
	if err != nil {
		r.end(jobs.Blocked, "cloudflare", nil, &failure{Code: "cloudflare", Message: err.Error()})
		return
	}
	if err := r.to(jobs.ImpactAnalyzed, "plan", jobs.Idempotent, map[string]any{"plan": plan, "drift": drift}); err != nil {
		return
	}
	if r.j.Kind == KindDNSPreview {
		// Read-only: walk the state machine with no external effect.
		ro := map[string]string{"note": "preview only; nothing is changed at the provider"}
		_ = r.to(jobs.Staging, "stage", jobs.Idempotent, ro)
		_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, ro)
		_ = r.to(jobs.Applying, "no_change", jobs.Idempotent, ro)
		_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, ro)
		r.end(jobs.Succeeded, "succeeded", map[string]any{"plan": plan, "drift": drift, "domain": d.FQDN}, nil)
		return
	}
	// Apply: only exactly what the operator previewed and confirmed.
	if p.PlanHash == "" || p.PlanHash != plan.Hash {
		r.end(jobs.Blocked, "plan_changed", nil, &failure{Code: "plan_changed", Message: "the zone or the expectations changed since the preview; preview again and confirm the new plan"})
		return
	}
	adopt := map[string]bool{}
	for _, id := range p.Adopt {
		adopt[id] = true
	}
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	if err := r.to(jobs.Applying, "apply", jobs.External, map[string]any{"changes": len(plan.Changes)}); err != nil {
		return
	}
	res, err := cl.Apply(ctx, plan, adopt)
	ev := map[string]any{"results": res, "note": "DNS caches honour TTLs; resolvers may serve old data until then"}
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, ev)
	_ = (&domains.Service{DB: c.DB}).RequestCheck(ctx, d.ID) // fresh DNS evidence
	actions := []string{}
	for _, a := range res {
		actions = append(actions, a.Action+" "+a.Name+" "+a.Type)
	}
	_ = c.auditDNS(ctx, r, d.ID, actions, err)
	if err != nil {
		// DNS is not transactional: partial changes stay and are reported.
		r.end(jobs.Failed, "partial", ev, &failure{Code: "dns_partial", Message: err.Error()})
		return
	}
	r.end(jobs.Succeeded, "succeeded", ev, nil)
}

func (c *Coordinator) auditDNS(ctx context.Context, r *runner, domainID string, actions []string, err error) error {
	res := "success"
	if err != nil {
		res = "failure"
	}
	_, e := c.Audit.Record(ctx, auditEventDNS(r.j.ActorID, r.j.ID, domainID, strings.Join(actions, "; "), res))
	return e
}

func auditEventDNS(actor, job, domainID, actions, result string) audit.Event {
	return audit.Event{ActorKind: "user", ActorID: actor, Action: "dns.cloudflare_apply", TargetKind: "domain", TargetID: domainID, JobID: job, Result: result,
		Context: map[string]any{"changes": actions}}
}

// KindDNSDiscover is a read-only job: list the token's zones (and, with a
// zone_id, that zone's DNS records). The API never calls Cloudflare directly
// (ADR-031), so discovery for the panel runs here in ngm-ops.
const KindDNSDiscover = "dns.cloudflare.discover"

// DiscoverPayload optionally narrows discovery to one zone's records.
type DiscoverPayload struct {
	ZoneID string `json:"zone_id,omitempty"`
}

func (c *Coordinator) runDNSDiscover(r *runner) {
	ctx := r.ctx
	var p DiscoverPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	cl, err := c.cloudflareClient(ctx)
	if err != nil {
		r.end(jobs.Blocked, "cloudflare", nil, &failure{Code: "cloudflare", Message: err.Error()})
		return
	}
	zones, err := cl.Zones(ctx)
	if err != nil {
		r.end(jobs.Blocked, "cloudflare", nil, &failure{Code: "cloudflare", Message: err.Error()})
		return
	}
	result := map[string]any{"zones": zones}
	if p.ZoneID != "" {
		recs, err := cl.Records(ctx, p.ZoneID)
		if err != nil {
			r.end(jobs.Blocked, "cloudflare", nil, &failure{Code: "cloudflare", Message: err.Error()})
			return
		}
		result["records"] = recs
		result["zone_id"] = p.ZoneID
	}
	if err := r.to(jobs.ImpactAnalyzed, "discovered", jobs.Idempotent, map[string]any{"zones": len(zones)}); err != nil {
		return
	}
	ro := map[string]string{"note": "read-only discovery; nothing is changed at the provider"}
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, ro)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, ro)
	_ = r.to(jobs.Applying, "no_change", jobs.Idempotent, ro)
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, ro)
	r.end(jobs.Succeeded, "succeeded", result, nil)
}
