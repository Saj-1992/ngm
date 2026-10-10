package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/certauto"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/jobs"
)

// KindACME issues (or renews) a certificate through ACME HTTP-01.
const KindACME = "certificate.acme"

// ACMEPayload describes an order. CertificateID set = renewal.
type ACMEPayload struct {
	CertificateID string   `json:"certificate_id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Identifiers   []string `json:"identifiers,omitempty"`
	Directory     string   `json:"directory"` // letsencrypt-staging | letsencrypt
	Email         string   `json:"email,omitempty"`
	Challenge     string   `json:"challenge,omitempty"` // http-01 (default) | dns-01 (Cloudflare; required for wildcards)
	Trigger       string   `json:"trigger,omitempty"`   // manual | scheduled
}

// ACMEState is stored in certificates.acme_json.
type ACMEState struct {
	Directory   string    `json:"directory"`
	Email       string    `json:"email,omitempty"`
	Identifiers []string  `json:"identifiers"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastJob     string    `json:"last_job,omitempty"`
	Renewals    int       `json:"renewals"`
}

// RenewBefore is how long before expiry renewal starts.
const RenewBefore = 30 * 24 * time.Hour

// helperChallenges publishes HTTP-01 responses through the fenced helper.
type helperChallenges struct {
	c *Coordinator
	r *runner
}

func (h helperChallenges) Put(ctx context.Context, token, ka string) error {
	return h.c.call(ctx, h.r, "acme.put", helper.AcmeArgs{Token: token, KeyAuth: ka}, nil)
}
func (h helperChallenges) Clear(ctx context.Context, token string) error {
	return h.c.call(ctx, h.r, "acme.clear", helper.AcmeArgs{Token: token}, nil)
}

func (c *Coordinator) acmeState(ctx context.Context, certID string) (ACMEState, error) {
	var st ACMEState
	var raw string
	if err := c.DB.QueryRowContext(ctx, "SELECT acme_json FROM certificates WHERE id=? AND source='acme'", certID).Scan(&raw); err != nil {
		return st, err
	}
	err := json.Unmarshal([]byte(raw), &st)
	return st, err
}

func (c *Coordinator) saveACMEState(ctx context.Context, certID string, st ACMEState) {
	b, _ := json.Marshal(st)
	_, _ = c.DB.ExecContext(context.WithoutCancel(ctx), "UPDATE certificates SET acme_json=? WHERE id=?", string(b), certID)
}

func (c *Coordinator) runACME(r *runner) {
	ctx := r.ctx
	var p ACMEPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	block := func(code, msg string) { r.end(jobs.Blocked, code, nil, &failure{Code: code, Message: msg}) }
	if c.ACME == nil {
		block("acme_unavailable", "ACME is not configured in this worker")
		return
	}
	renewal := p.CertificateID != ""
	var st ACMEState
	if renewal {
		var err error
		if st, err = c.acmeState(ctx, p.CertificateID); err != nil {
			block("not_acme", "certificate not found or not issued through ACME")
			return
		}
		p.Directory, p.Email, p.Identifiers = st.Directory, st.Email, st.Identifiers
	}
	dir, ok := certauto.Directories[p.Directory]
	if !ok {
		block("validation_failed", "unknown ACME directory "+p.Directory)
		return
	}
	names, err := certauto.ValidateIdentifiers(p.Identifiers)
	if err != nil {
		block("validation_failed", err.Error())
		return
	}
	if !renewal {
		if err := gwstoreName(p.Name); err != nil {
			block("validation_failed", err.Error())
			return
		}
	}
	// Challenge selection: HTTP-01 (default) or DNS-01 via Cloudflare.
	var solver certauto.DNSSolver
	dns01 := p.Challenge == "dns-01"
	for _, n := range names {
		if strings.HasPrefix(n, "*.") && !dns01 {
			block("validation_failed", "wildcard certificates require the dns-01 challenge")
			return
		}
	}
	// Prerequisites from evidence.
	pre := map[string]any{"directory": p.Directory, "names": names, "renewal": renewal, "challenge": chalName(dns01)}
	if dns01 {
		cl, err := c.cloudflareClient(ctx)
		if err != nil {
			block("dns01_unavailable", "dns-01 needs the Cloudflare integration: "+err.Error())
			return
		}
		solver = newCFDNSSolver(cl)
	} else if why := c.acmeHTTPReady(ctx); why != "" {
		block("http01_unavailable", why)
		return
	}
	reg := &domains.Service{DB: c.DB, Audit: c.Audit}
	caa := map[string]any{}
	for _, n := range names {
		allowed, evidence := caaDecision(ctx, reg, n)
		caa[n] = evidence
		if !allowed {
			block("caa_forbids", fmt.Sprintf("the CAA records of %s do not allow %s to issue (%s)", n, certauto.CADomain, evidence))
			return
		}
	}
	pre["caa"] = caa
	if err := r.to(jobs.ImpactAnalyzed, "prerequisites", jobs.Idempotent, pre); err != nil {
		return
	}
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	if err := r.to(jobs.Applying, "order", jobs.External, map[string]any{"directory": dir}); err != nil {
		return
	}
	is := c.ACME.WithChallenges(helperChallenges{c: c, r: r})
	step := func(name string, ev any) {
		id, err := c.Jobs.BeginStep(ctx, r.j.ID, "acme."+name, jobs.External, &r.lease.Token)
		if err == nil {
			_ = c.Jobs.FinishStep(ctx, id, "completed", ev)
		}
	}
	octx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	res, err := is.Issue(octx, dir, p.Email, names, solver, step)
	cancel()
	recordErr := func(msg string) {
		if renewal {
			st.LastAttempt, st.LastError, st.LastJob = time.Now().UTC(), msg, r.j.ID
			c.saveACMEState(ctx, p.CertificateID, st)
		}
	}
	if err != nil {
		recordErr(err.Error())
		// Nothing was stored; the previous certificate (if any) stays in use.
		_ = r.to(jobs.Compensating, "order_failed", jobs.Idempotent, map[string]string{"error": err.Error()})
		r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "acme_failed", Message: err.Error()})
		return
	}
	defer clear(res.KeyPEM)
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, map[string]any{"not_after": res.NotAfter})
	var cert *gwstore.Cert
	if renewal {
		cert, err = c.GW.ReplaceCertificate(ctx, nil, p.CertificateID, res.ChainPEM, string(res.KeyPEM))
	} else {
		cert, err = c.GW.ImportCertificate(ctx, nil, p.Name, res.ChainPEM, string(res.KeyPEM), "acme")
	}
	if err != nil {
		recordErr(err.Error())
		r.end(jobs.Failed, "store_failed", nil, &failure{Code: "store_failed", Message: err.Error()})
		return
	}
	st = ACMEState{Directory: p.Directory, Email: p.Email, Identifiers: names, LastAttempt: time.Now().UTC(), LastJob: r.j.ID, Renewals: st.Renewals}
	if renewal {
		st.Renewals++
	}
	c.saveACMEState(ctx, cert.ID, st)
	result := map[string]any{"certificate_id": cert.ID, "not_after": cert.NotAfter, "fingerprint": cert.Fingerprint}
	// A renewed certificate in use must reach Nginx: queue a Safe Apply.
	if renewal && c.certInUse(ctx, cert.ID) {
		j, _, err := c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindApply, ActorID: r.j.ActorID, IdempotencyKey: "acme-deploy-" + r.j.ID,
			LockSet: []string{"gateway-config", "certificate"}, Payload: ApplyPayload{Note: "certificate renewal " + cert.Name}})
		if err == nil {
			result["deploy_job"] = j.ID
		}
	}
	r.end(jobs.Succeeded, "succeeded", result, nil)
}

func gwstoreName(n string) error {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > 64 {
		return fmt.Errorf("certificate name must be 1–64 characters")
	}
	return nil
}

func (c *Coordinator) certInUse(ctx context.Context, id string) bool {
	var n int
	_ = c.DB.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE certificate_id=?", id).Scan(&n)
	return n > 0
}

// acmeHTTPReady checks that the active generation serves HTTP-01 on port 80.
func (c *Coordinator) acmeHTTPReady(ctx context.Context) string {
	g, err := c.active(ctx)
	if err != nil || g == nil {
		return "nothing is deployed yet: create an HTTP listener on port 80 and apply it first"
	}
	if !strings.Contains(g.Files[gateway.FileHTTP], "location ^~ "+gateway.AcmePrefix) {
		return "the active configuration has no HTTP listener on port 80 (needed for the HTTP-01 challenge); add one and apply"
	}
	return ""
}

// caaDecision uses the Domain Registry's authoritative CAA evidence. Without
// evidence the CA itself still enforces CAA; that is reported, not hidden.
func caaDecision(ctx context.Context, reg *domains.Service, name string) (bool, string) {
	ds, err := reg.List(ctx)
	if err != nil {
		return true, "registry unavailable"
	}
	for _, d0 := range ds {
		if name != d0.FQDN && !strings.HasSuffix(name, "."+d0.FQDN) {
			continue
		}
		d, err := reg.Get(ctx, d0.ID)
		if err != nil {
			break
		}
		for _, o := range d.Observed {
			if o.Name == d.FQDN && o.Type == "CAA" && o.Source == "authoritative" && o.Error == "" && time.Since(o.ObservedAt) < 24*time.Hour {
				if domains.CAAAllows(o.Values, certauto.CADomain, false) {
					return true, fmt.Sprintf("allowed by CAA of %s (%d record(s), observed %s)", d.FQDN, len(o.Values), o.ObservedAt.Format(time.RFC3339))
				}
				return false, fmt.Sprintf("CAA of %s: %s", d.FQDN, strings.Join(o.Values, "; "))
			}
		}
		return true, "no recent CAA evidence for " + d.FQDN + " (the CA checks CAA itself)"
	}
	return true, name + " is not in the Domain Registry (no CAA evidence; the CA checks CAA itself)"
}

// ScheduleRenewals queues renewals for ACME certificates expiring within
// RenewBefore (at most one attempt per certificate per day).
func (c *Coordinator) ScheduleRenewals(ctx context.Context) (int, error) {
	rows, err := c.DB.QueryContext(ctx, "SELECT id, COALESCE(not_after,'') FROM certificates WHERE source='acme'")
	if err != nil {
		return 0, err
	}
	type due struct{ id string }
	var list []due
	for rows.Next() {
		var id, na string
		if err := rows.Scan(&id, &na); err != nil {
			rows.Close()
			return 0, err
		}
		t, err := time.Parse(time.RFC3339Nano, na)
		if err != nil || time.Until(t) < RenewBefore {
			list = append(list, due{id})
		}
	}
	rows.Close()
	n := 0
	for _, d := range list {
		_, created, err := c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindACME, IdempotencyKey: "acme-renew-" + d.id + "-" + time.Now().UTC().Format("20060102"),
			LockSet: []string{"certificate"}, Payload: ACMEPayload{CertificateID: d.id, Trigger: "scheduled"}})
		if err == nil && created {
			n++
		}
	}
	return n, nil
}
