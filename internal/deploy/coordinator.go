// Package deploy is the Deployment Coordinator: it runs Safe Apply jobs
// (MASTER_SPEC §8, DEPLOYMENT_CONTRACT.md) inside ngm-ops. It is the only
// component that promotes a configuration generation to Active.
package deploy

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
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/certauto"
	"github.com/ngm-gateway/ngm/internal/deployspec"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/perf"
	"github.com/ngm-gateway/ngm/internal/recovery"
	"github.com/ngm-gateway/ngm/internal/sse"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Re-exported job contract (see package deployspec).
const (
	KindApply    = deployspec.KindApply
	KindRollback = deployspec.KindRollback
)

type (
	ApplyPayload    = deployspec.ApplyPayload
	RollbackPayload = deployspec.RollbackPayload
)

// Helper is the helper RPC surface used by the coordinator.
type Helper interface {
	Call(ctx context.Context, req ipc.Request, out any) error
}

// SocketHelper calls the helper over its Unix socket.
type SocketHelper struct{ Path string }

func (h SocketHelper) Call(ctx context.Context, req ipc.Request, out any) error {
	return ipc.Call(ctx, h.Path, req, out)
}

// Coordinator runs deployment jobs.
type Coordinator struct {
	DB        *store.DB
	Jobs      *jobs.Journal
	Locks     *locks.Manager
	GW        *gwstore.Service
	Audit     *audit.Logger
	Broker    *sse.Broker
	Helper    Helper
	Prober    Prober
	Log       *slog.Logger
	Worker    string
	APIListen string
	// PublicOrigin is the configured management origin (see gateway.BuildOptions.ManagementHost).
	PublicOrigin string
	// PublicPath is the Control Center base path (config api.public_path).
	PublicPath string
	// Backups, KeysDir and Hostname serve backup jobs.
	Backups  *backup.Service
	KeysDir  string
	Hostname string
	// VerifyTimeout bounds post-reload verification.
	VerifyTimeout time.Duration
	KeepGens      int
	// ACME issues and renews certificates (nil disables certificate.acme jobs).
	ACME *certauto.Issuer
	// Vault reads integration secrets (Cloudflare token).
	Vault *vault.Vault
	// WebsitesRoot is /var/lib/ngm/websites (website builds).
	WebsitesRoot string

	claimMu sync.Mutex
	claimed map[string]bool // jobs being run by a worker of this process
}

// claim marks a job as taken by this process (several workers may call
// RunOnce concurrently; lease acquisition is re-entrant per job, so the
// claim is what prevents two workers from running the same job).
func (c *Coordinator) claim(id string) bool {
	c.claimMu.Lock()
	defer c.claimMu.Unlock()
	if c.claimed == nil {
		c.claimed = map[string]bool{}
	}
	if c.claimed[id] {
		return false
	}
	c.claimed[id] = true
	return true
}

func (c *Coordinator) unclaim(id string) {
	c.claimMu.Lock()
	delete(c.claimed, id)
	c.claimMu.Unlock()
}

const leaseTTL = 30 * time.Second

// lockSetFor returns the lock set of each job kind this coordinator runs
// (acquired in the total order defined by the locks package).
func lockSetFor(kind string) ([]locks.Resource, bool) {
	switch kind {
	case KindApply, KindRollback, KindReconcile:
		return []locks.Resource{locks.GatewayConfig, locks.Certificate}, true
	case KindFirewall:
		return firewallLocks, true
	case KindBackup:
		return backupLocks, true
	case KindACME:
		return []locks.Resource{locks.Certificate}, true
	case KindDNSPreview, KindDNSApply, KindDNSDiscover:
		return dnsLocks, true
	case KindSiteBuild, KindSitePublish, KindSiteDelete:
		return siteLocks, true
	}
	return nil, false
}

// Summary is stored with each generation.
type Summary struct {
	ModelHash string            `json:"model_hash"`
	Listens   []string          `json:"listens"`
	Probes    []gateway.Probe   `json:"probes"`
	Warnings  []gateway.Issue   `json:"warnings"`
	CertFPs   map[string]string `json:"cert_fingerprints"`
	// CertKeys records the exact key version (key file id) per certificate,
	// so re-staging this generation later uses the matching key.
	CertKeys map[string]string `json:"cert_keys,omitempty"`
	Diff     []FileDiff        `json:"diff"`
}

// FileDiff summarises changes of one file versus the active generation.
type FileDiff struct {
	File    string `json:"file"`
	Change  string `json:"change"` // added | removed | modified
	Added   int    `json:"lines_added"`
	Removed int    `json:"lines_removed"`
}

// failure carries a client-safe error for the job record.
type failure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func (c *Coordinator) publish(ctx context.Context, j *jobs.Job) {
	if c.Broker != nil && j != nil {
		_, _ = c.Broker.Publish(ctx, "job.updated", "global", map[string]any{"id": j.ID, "kind": j.Kind, "state": j.State})
	}
}

// RunOnce processes at most one queued deployment job. It returns true if a
// job was handled.
func (c *Coordinator) RunOnce(ctx context.Context) (bool, error) {
	list, err := c.Jobs.List(ctx, jobs.ListFilter{State: jobs.Queued, Limit: 50})
	if err != nil {
		return false, err
	}
	// Oldest first.
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	for _, j := range list {
		set, ok := lockSetFor(j.Kind)
		if !ok || !c.claim(j.ID) {
			continue
		}
		lease, err := c.Locks.Acquire(ctx, j.ID, c.Worker, set, leaseTTL)
		if errors.Is(err, locks.ErrHeld) {
			c.unclaim(j.ID)
			continue // that resource is busy; a job of another family may run
		}
		if err != nil {
			c.unclaim(j.ID)
			return false, err
		}
		// The job may have been taken and finished between listing and claiming.
		if cur, err := c.Jobs.Get(ctx, j.ID); err != nil || cur.State != jobs.Queued {
			_ = c.Locks.Release(ctx, lease)
			c.unclaim(j.ID)
			continue
		}
		c.run(ctx, j, lease)
		c.unclaim(j.ID)
		return true, nil
	}
	return false, nil
}

// heartbeat keeps a lease alive until stop is closed; lost leases cancel work.
func (c *Coordinator) heartbeat(ctx context.Context, l *locks.Lease, cancel context.CancelFunc, stop <-chan struct{}) {
	t := time.NewTicker(leaseTTL / 3)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := c.Locks.Heartbeat(ctx, l, leaseTTL); err != nil {
				c.Log.Error("deploy: lease lost; stopping job at next checkpoint", "job", l.JobID, "err", err)
				cancel()
				return
			}
		}
	}
}

type runner struct {
	c     *Coordinator
	j     *jobs.Job
	lease *locks.Lease
	ctx   context.Context
	state jobs.State
}

func (r *runner) to(next jobs.State, step string, class jobs.StepClass, evidence any) error {
	o := jobs.TransitionOpts{StepName: step, Class: class, Evidence: evidence, FencingToken: &r.lease.Token, Fence: r.c.Locks.FenceFunc(r.lease)}
	j, err := r.c.Jobs.Transition(r.ctx, r.j.ID, r.state, next, o)
	if err != nil {
		return err
	}
	r.j, r.state = j, next
	r.c.publish(r.ctx, j)
	return nil
}

func (r *runner) end(next jobs.State, step string, result any, fail *failure) {
	o := jobs.TransitionOpts{StepName: step, Result: result, FencingToken: &r.lease.Token, Fence: r.c.Locks.FenceFunc(r.lease)}
	if fail != nil {
		o.Error = fail
		o.Evidence = fail
	}
	j, err := r.c.Jobs.Transition(context.WithoutCancel(r.ctx), r.j.ID, r.state, next, o)
	if err != nil {
		r.c.Log.Error("deploy: final transition failed", "job", r.j.ID, "to", next, "err", err)
		return
	}
	r.j, r.state = j, next
	r.c.publish(r.ctx, j)
	if next != jobs.Succeeded {
		// A generation staged by a job that did not succeed must never look
		// deployable; previously active generations are untouched.
		_, _ = r.c.DB.ExecContext(context.WithoutCancel(r.ctx), "UPDATE config_generations SET status='failed' WHERE job_id=? AND status='staged'", r.j.ID)
	}
	res := "success"
	if next != jobs.Succeeded {
		res = "failure"
	}
	_, _ = r.c.Audit.Record(context.WithoutCancel(r.ctx), audit.Event{ActorKind: "system", ActorID: r.j.ActorID, Action: "deploy." + strings.ToLower(string(next)),
		TargetKind: "job", TargetID: r.j.ID, JobID: r.j.ID, Result: res, Context: map[string]any{"kind": r.j.Kind}})
}

func (c *Coordinator) run(parent context.Context, j *jobs.Job, lease *locks.Lease) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := make(chan struct{})
	go c.heartbeat(parent, lease, cancel, stop)
	defer func() {
		close(stop)
		_ = c.Locks.Release(context.WithoutCancel(parent), lease)
	}()
	r := &runner{c: c, j: j, lease: lease, ctx: ctx, state: j.State}
	defer func() {
		if p := recover(); p != nil {
			c.Log.Error("deploy: panic", "job", j.ID, "panic", p)
			c.failSafely(r, &failure{Code: "internal", Message: fmt.Sprint(p)})
		}
	}()
	switch j.Kind {
	case KindRollback:
		c.runRollback(r)
	case KindFirewall:
		c.runFirewall(r)
	case KindBackup:
		c.runBackup(r)
	case KindReconcile:
		c.runReconcile(r)
	case KindACME:
		c.runACME(r)
	case KindDNSPreview, KindDNSApply:
		c.runDNS(r)
	case KindDNSDiscover:
		c.runDNSDiscover(r)
	case KindSiteBuild:
		c.runSiteBuild(r)
	case KindSitePublish:
		c.runSitePublish(r)
	case KindSiteDelete:
		c.runSiteDelete(r)
	default:
		c.runApply(r)
	}
}

// blockedByIncident ends the job Blocked while a recovery incident for the
// same resource family is open (supervised recovery comes first).
func (c *Coordinator) blockedByIncident(r *runner, kinds ...string) bool {
	in, err := recovery.OpenFor(r.ctx, c.DB, kinds...)
	if err != nil || in == nil {
		return false
	}
	r.end(jobs.Blocked, "recovery_required", nil, &failure{Code: "open_recovery_incident", Message: "resolve recovery incident " + in.ID + " in the Recovery Center first"})
	return true
}

// failSafely ends a job from whatever state it is in.
func (c *Coordinator) failSafely(r *runner, f *failure) {
	switch {
	case r.state.Cancellable():
		r.end(jobs.Failed, "failed", nil, f)
	case r.state == jobs.Applying || r.state == jobs.Verifying || r.state == jobs.Compensating:
		c.recoveryRequired(r, f)
	}
}

func (c *Coordinator) recoveryRequired(r *runner, f *failure) {
	ev, _ := json.Marshal(f)
	_, _ = c.DB.ExecContext(context.WithoutCancel(r.ctx), `INSERT INTO recovery_incidents(id,job_id,status,summary,evidence_json,opened_at) VALUES(?,?,'open',?,?,?)`,
		ids.New(), r.j.ID, f.Message, string(ev), store.FormatTime(time.Now()))
	if r.state != jobs.Compensating && jobs.ValidTransition(r.state, jobs.RecoveryRequired) {
		r.end(jobs.RecoveryRequired, "recovery_required", nil, f)
		return
	}
	r.end(jobs.RecoveryRequired, "recovery_required", nil, f)
}

// ─── shared helpers ────────────────────────────────────────────────────────

// capsAndReserved derives Nginx capabilities and protected ports from evidence.
func (c *Coordinator) capsAndReserved(ctx context.Context) (gateway.Caps, observe.Nginx, []int, error) {
	var n observe.Nginx
	at, err := observe.Latest(ctx, c.DB, observe.KindNginx, &n)
	if err != nil || time.Since(at) > 5*time.Minute {
		return gateway.Caps{}, n, nil, errors.New("no fresh Nginx observation (is ngm-ops observing via the helper?)")
	}
	if !n.Installed {
		return gateway.Caps{}, n, nil, errors.New("nginx is not installed")
	}
	reserved := []int{22}
	var pre struct {
		SSHPorts []string `json:"ssh_ports"`
	}
	var raw string
	if err := c.DB.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='install.preflight'").Scan(&raw); err == nil {
		_ = json.Unmarshal([]byte(raw), &pre)
		reserved = nil
		for _, p := range pre.SSHPorts {
			if v, err := strconv.Atoi(p); err == nil {
				reserved = append(reserved, v)
			}
		}
		if len(reserved) == 0 {
			reserved = []int{22}
		}
	}
	return gateway.CapsFromVersion(n.Version, n.StreamModule, n.SSLPreread, n.HTTPV2), n, reserved, nil
}

type activeGen struct {
	ID         string
	Files      map[string]string
	Summary    Summary
	ProbeToken string
}

func (c *Coordinator) active(ctx context.Context) (*activeGen, error) {
	var gid sql.NullString
	if err := c.DB.QueryRowContext(ctx, "SELECT generation_id FROM active_state WHERE id=1").Scan(&gid); err != nil || !gid.Valid {
		return nil, err
	}
	return c.loadGen(ctx, gid.String)
}

func (c *Coordinator) loadGen(ctx context.Context, id string) (*activeGen, error) {
	g := &activeGen{ID: id}
	var files, sum string
	if err := c.DB.QueryRowContext(ctx, "SELECT files_json, summary_json, probe_token FROM config_generations WHERE id=?", id).Scan(&files, &sum, &g.ProbeToken); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(files), &g.Files)
	_ = json.Unmarshal([]byte(sum), &g.Summary)
	return g, nil
}

func lineDiff(a, b string) (added, removed int) {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	ma, mb := count(a), count(b)
	for l, n := range mb {
		if d := n - ma[l]; d > 0 {
			added += d
		}
	}
	for l, n := range ma {
		if d := n - mb[l]; d > 0 {
			removed += d
		}
	}
	return
}

func diffFiles(old, new map[string]string) []FileDiff {
	var out []FileDiff
	names := map[string]bool{}
	for n := range old {
		names[n] = true
	}
	for n := range new {
		names[n] = true
	}
	keys := make([]string, 0, len(names))
	for n := range names {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, n := range keys {
		o, oki := old[n]
		nw, okn := new[n]
		switch {
		case !oki:
			a, _ := lineDiff("", nw)
			out = append(out, FileDiff{n, "added", a, 0})
		case !okn:
			_, r := lineDiff(o, "")
			out = append(out, FileDiff{n, "removed", 0, r})
		default:
			a, r := lineDiff(o, nw)
			if a+r > 2 { // generation header + probe map always differ
				out = append(out, FileDiff{n, "modified", a, r})
			}
		}
	}
	return out
}

func modelHash(m *gateway.Model) string {
	b, _ := json.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newToken() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// overlapsOther reports whether bind conflicts with a non-Nginx listener.
func overlapsOther(bind string, others []string) string {
	ba, bp, err := splitAddrPort(bind)
	if err != nil {
		return ""
	}
	for _, o := range others {
		addr, proc, _ := strings.Cut(o, " ")
		oa, op, err := splitAddrPort(addr)
		if err != nil || op != bp || oa.Is4() != ba.Is4() && !(oa.IsUnspecified() || ba.IsUnspecified()) {
			continue
		}
		if oa == ba || oa.IsUnspecified() || ba.IsUnspecified() {
			return o + " (" + proc + ")"
		}
	}
	return ""
}

func splitAddrPort(s string) (netip.Addr, int, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), int(ap.Port()), nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0, errors.New("bad addr")
	}
	h := strings.Trim(s[:i], "[]")
	if h == "*" {
		h = "0.0.0.0"
	}
	a, err := netip.ParseAddr(strings.Split(h, "%")[0])
	if err != nil {
		return netip.Addr{}, 0, err
	}
	p, err := strconv.Atoi(s[i+1:])
	return a, p, err
}

// ─── apply ─────────────────────────────────────────────────────────────────

func (c *Coordinator) runApply(r *runner) {
	ctx := r.ctx
	var payload ApplyPayload
	_ = json.Unmarshal(r.j.Payload, &payload)

	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, nil); err != nil {
		c.Log.Error("deploy: start", "job", r.j.ID, "err", err)
		return
	}
	if c.blockedByIncident(r, KindApply, KindRollback, KindReconcile) {
		return
	}
	caps, obs, reserved, err := c.capsAndReserved(ctx)
	if err != nil {
		r.end(jobs.Blocked, "capabilities", nil, &failure{Code: "nginx_unknown", Message: err.Error()})
		return
	}
	model, err := c.GW.LoadModel(ctx)
	if err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: "load model: " + err.Error()})
		return
	}
	plan, issues := gateway.Build(model, caps, gateway.BuildOptions{ReservedPorts: reserved, APIListen: c.APIListen, ManagementHost: gateway.OriginHost(c.PublicOrigin), ManagementPath: c.PublicPath})
	if gateway.HasErrors(issues) {
		r.end(jobs.Blocked, "validation_failed", nil, &failure{Code: "validation_failed", Message: "the desired configuration has errors", Details: issues})
		return
	}
	pv := c.perfView(ctx)
	pr := pv.Render()
	fb := gwstore.GetFallback(ctx, c.DB)
	mh := modelHash(model) + "+perf:" + pr.Hash
	if fb.Enabled() {
		mh += "+fallback:" + fb.WebsiteID + ":" + fb.CertificateID
	}
	prev, _ := c.active(ctx)
	if prev != nil && prev.Summary.ModelHash == mh && !payload.Force {
		_ = r.to(jobs.ImpactAnalyzed, "no_changes", jobs.Idempotent, map[string]any{"active": prev.ID})
		r.state = jobs.ImpactAnalyzed
		r.end(jobs.Blocked, "no_changes", nil, &failure{Code: "no_changes", Message: "the desired configuration equals the active generation; nothing to apply (use force to re-apply)"})
		return
	}

	// Compile.
	genID := ids.New()
	token := newToken()
	certIDs := gateway.UsedCertIDs(plan)
	defaultCert := ""
	if !caps.RejectHandshake {
		defaultCert, err = c.ensureDefaultCert(ctx)
		if err != nil {
			c.failSafely(r, &failure{Code: "default_cert", Message: err.Error()})
			return
		}
		certIDs = append(certIDs, defaultCert)
	}
	if fb.Enabled() {
		certIDs = append(certIDs, fb.CertificateID)
	}
	mat, err := c.GW.CertMaterial(ctx, certIDs)
	defer mat.Clear()
	if err != nil {
		c.failSafely(r, &failure{Code: "certificate_material", Message: err.Error()})
		return
	}
	keys := mat.Keys
	out, err := gateway.Compile(plan, issues, caps, gateway.CompileInput{GenID: genID, ProbeToken: token, CertPEM: mat.Chains, DefaultCertID: defaultCert, KeyFile: mat.KeyFile,
		PerfHTTP: pr.HTTP, PerfServer: pr.HTTPServer, StreamTimeoutMS: perfSec(pv, "stream_proxy_timeout"), StreamConnectMS: perfSec(pv, "stream_proxy_connect_timeout"),
		FallbackSite: fb.WebsiteID, FallbackCertID: fb.CertificateID})
	if err != nil {
		c.failSafely(r, &failure{Code: "compile_failed", Message: err.Error()})
		return
	}
	files := map[string]string{}
	for n, b := range out.Files {
		files[n] = string(b)
	}
	var prevFiles map[string]string
	prevID := helper.EmptyGen
	if prev != nil {
		prevFiles, prevID = prev.Files, prev.ID
	}
	fps := map[string]string{}
	for _, id := range certIDs {
		if cert, err := c.GW.GetCertificate(ctx, id); err == nil {
			fps[id] = cert.Fingerprint
		}
	}
	var warnings []gateway.Issue
	for _, i := range issues {
		if i.Severity == "warning" {
			warnings = append(warnings, i)
		}
	}
	sum := Summary{ModelHash: mh, Listens: out.Listens, Probes: out.Probes, Warnings: warnings, CertFPs: fps, CertKeys: mat.KeyFile, Diff: diffFiles(prevFiles, files)}
	if err := r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, map[string]any{"generation": genID, "diff": sum.Diff, "warnings": len(warnings), "previous": prevID}); err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}

	// Stage: DB records + helper writes the immutable generation.
	if err := c.recordGeneration(ctx, r, genID, model, mh, files, token, sum); err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: "record generation: " + err.Error()})
		return
	}
	if err := r.to(jobs.Staging, "stage", jobs.Idempotent, map[string]any{"generation": genID, "hash": out.Hash}); err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	keyStr := map[string]string{}
	for id, k := range keys {
		keyStr[id] = string(k)
	}
	if err := c.call(ctx, r, "nginx.ensure_layout", map[string]any{"stream": caps.StreamModule}, nil); err != nil {
		r.end(jobs.Failed, "layout", nil, &failure{Code: "layout_failed", Message: err.Error()})
		return
	}
	var staged map[string]any
	if err := c.call(ctx, r, "nginx.stage", helper.StageArgs{GenID: genID, Files: files, Keys: keyStr}, &staged); err != nil {
		r.end(jobs.Failed, "stage_failed", nil, &failure{Code: "stage_failed", Message: err.Error()})
		return
	}
	for k := range keyStr {
		keyStr[k] = ""
	}

	// Preflight: port ownership, distro default site, management access.
	if err := r.to(jobs.Preflight, "preflight", jobs.Idempotent, map[string]any{"manifest": staged["manifest"]}); err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	var conflicts []string
	for _, b := range out.Listens {
		if o := overlapsOther(b, obs.OtherListeners); o != "" {
			conflicts = append(conflicts, b+" ↔ "+o)
		}
	}
	if len(conflicts) > 0 {
		r.end(jobs.Blocked, "port_conflict", nil, &failure{Code: "port_conflict", Message: "ports are held by other processes", Details: conflicts})
		return
	}
	var st map[string]any
	if err := c.call(ctx, r, "nginx.state", nil, &st); err != nil {
		c.failSafely(r, &failure{Code: "helper", Message: err.Error()})
		return
	}
	if enabled, _ := st["distro_default_site_enabled"].(bool); enabled && usesPort(model, 80) {
		if !payload.DisableDistroDefaultSite {
			r.end(jobs.Blocked, "distro_default_site", nil, &failure{Code: "distro_default_site",
				Message: "Ubuntu's default site (sites-enabled/default) binds :80 as default_server and conflicts with an NGM :80 listener. Re-submit with disable_distro_default_site=true to let NGM disable it (recorded for restore on uninstall)."})
			return
		}
		if err := c.call(ctx, r, "nginx.disable_default_site", nil, nil); err != nil {
			r.end(jobs.Failed, "distro_default_site", nil, &failure{Code: "distro_default_site", Message: err.Error()})
			return
		}
	}
	cur, _ := st["current"].(string)
	if cur != prevID {
		r.end(jobs.Blocked, "drift", nil, &failure{Code: "active_drift", Message: fmt.Sprintf("the data plane serves generation %q but NGM's active record is %q; reconcile before applying", cur, prevID)})
		return
	}

	// Apply (external effect).
	if err := r.to(jobs.Applying, "apply", jobs.External, map[string]any{"generation": genID, "previous": prevID}); err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	stepID, _ := c.Jobs.BeginStep(ctx, r.j.ID, "nginx.activate", jobs.External, &r.lease.Token)
	var act helper.ActivateResult
	err = c.call(ctx, r, "nginx.activate", helper.ActivateArgs{GenID: genID, Expected: prevID}, &act)
	if err != nil {
		_ = c.Jobs.FinishStep(context.WithoutCancel(ctx), stepID, "failed", map[string]any{"error": err.Error()})
		var ie *ipc.Error
		if errors.As(err, &ie) && ie.Code == "reload_failed" {
			// Helper restored the previous pointer and reloaded it.
			c.compensate(r, genID, prevID, sum, &failure{Code: "reload_failed", Message: ie.Message})
			return
		}
		// The helper may have died mid-activation: decide from evidence, not hope.
		c.resolveUncertain(r, genID, prevID, sum, err)
		return
	}
	if !act.Activated {
		_ = c.Jobs.FinishStep(context.WithoutCancel(ctx), stepID, "failed", act)
		_ = r.to(jobs.Compensating, "nginx_test_failed", jobs.Idempotent, act)
		c.markGen(ctx, genID, "failed")
		r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "nginx_test_failed", Message: "nginx -t rejected the generation; the previous configuration was never unloaded", Details: act.TestOutput})
		return
	}
	_ = c.Jobs.FinishStep(ctx, stepID, "completed", act)

	// Verify.
	if err := r.to(jobs.Verifying, "verify", jobs.Idempotent, act); err != nil {
		c.recoveryRequired(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	ev, ok := c.verify(ctx, genID, token, sum)
	if !ok {
		c.compensate(r, genID, prevID, sum, &failure{Code: "verification_failed", Message: "post-reload verification failed", Details: ev})
		return
	}
	if err := c.promote(ctx, r, genID, prevID, ev); err != nil {
		c.recoveryRequired(r, &failure{Code: "promote_failed", Message: err.Error()})
		return
	}
	c.gc(ctx, r)
}

func usesPort(m *gateway.Model, port int) bool {
	for _, l := range m.Listeners {
		if l.Enabled && l.Port == port {
			return true
		}
	}
	return false
}

func (c *Coordinator) call(ctx context.Context, r *runner, op string, args any, out any) error {
	req := ipc.Request{Op: op, JobID: r.j.ID, Fence: r.lease.Token}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		req.Args = b
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return c.Helper.Call(cctx, req, out)
}

func (c *Coordinator) recordGeneration(ctx context.Context, r *runner, genID string, m *gateway.Model, mh string, files map[string]string, token string, sum Summary) error {
	mj, _ := json.Marshal(m)
	fj, _ := json.Marshal(files)
	sj, _ := json.Marshal(sum)
	return c.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := c.Locks.FenceFunc(r.lease)(ctx, tx); err != nil {
			return err
		}
		now := store.FormatTime(time.Now())
		var n int64
		_ = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(number),0)+1 FROM desired_revisions").Scan(&n)
		did := ids.New()
		if _, err := tx.ExecContext(ctx, `INSERT INTO desired_revisions(id,number,model_hash,model_json,state,created_by,created_at) VALUES(?,?,?,?,'approved',?,?)`,
			did, n, mh, string(mj), r.j.ActorID, now); err != nil {
			return err
		}
		var gn int64
		_ = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(number),0)+1 FROM config_generations").Scan(&gn)
		_, err := tx.ExecContext(ctx, `INSERT INTO config_generations(id,number,desired_revision_id,stage_path,manifest_hash,status,created_at,files_json,probe_token,job_id,summary_json)
			VALUES(?,?,?,?,?,'staged',?,?,?,?,?)`, genID, gn, did, gateway.GenDir+"/"+genID, mh, now, string(fj), token, r.j.ID, string(sj))
		return err
	})
}

// resolveUncertain settles an activation whose outcome is unknown (helper
// crashed or the connection broke). It waits for the helper to come back,
// reads the live pointer and proves the outcome with verification probes:
// the new generation serving and verified → promote; otherwise the previous
// generation is restored/verified; anything else → RecoveryRequired.
func (c *Coordinator) resolveUncertain(r *runner, genID, prevID string, sum Summary, cause error) {
	ctx := context.WithoutCancel(r.ctx)
	var st map[string]any
	var err error
	deadline := time.Now().Add(uncertainWait)
	for {
		if err = c.call(ctx, r, "nginx.state", nil, &st); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		c.recoveryRequired(r, &failure{Code: "activate_uncertain", Message: "activation outcome unknown (" + cause.Error() + ") and the helper did not come back: " + err.Error()})
		return
	}
	cur, _ := st["current"].(string)
	ev := map[string]any{"cause": cause.Error(), "current": cur}
	switch cur {
	case genID:
		if r.state == jobs.Applying {
			_ = r.to(jobs.Verifying, "uncertain_verify", jobs.Idempotent, ev)
		}
		if vev, ok := c.verify(ctx, genID, r.c.genToken(ctx, genID), sum); ok {
			if err := c.promote(ctx, r, genID, prevID, vev); err != nil {
				c.recoveryRequired(r, &failure{Code: "promote_failed", Message: err.Error()})
			}
			return
		}
		c.compensate(r, genID, prevID, sum, &failure{Code: "activate_interrupted", Message: "activation was interrupted and the new generation did not verify; restored the previous one"})
	case prevID:
		_ = r.to(jobs.Compensating, "uncertain_previous", jobs.Idempotent, ev)
		if prevID != helper.EmptyGen {
			if prev, err := c.loadGen(ctx, prevID); err == nil {
				if pev, ok := c.verify(ctx, prevID, prev.ProbeToken, prev.Summary); !ok {
					c.recoveryRequired(r, &failure{Code: "previous_unverified", Message: "activation interrupted; the previous generation is selected but did not verify", Details: pev})
					return
				}
			}
		}
		c.markGen(ctx, genID, "failed")
		r.end(jobs.RolledBack, "rolled_back", map[string]any{"serving": prevID}, &failure{Code: "activate_interrupted", Message: "activation was interrupted (" + cause.Error() + "); verified that the previous generation still serves"})
	default:
		c.recoveryRequired(r, &failure{Code: "ambiguous_state", Message: fmt.Sprintf("activation interrupted; the data plane serves %q, expected %q or %q", cur, genID, prevID)})
	}
}

// uncertainWait bounds how long an uncertain activation waits for the helper.
var uncertainWait = 30 * time.Second

func (c *Coordinator) genToken(ctx context.Context, id string) string {
	var t string
	_ = c.DB.QueryRowContext(ctx, "SELECT probe_token FROM config_generations WHERE id=?", id).Scan(&t)
	return t
}

func (c *Coordinator) markGen(ctx context.Context, id, status string) {
	_, _ = c.DB.ExecContext(context.WithoutCancel(ctx), "UPDATE config_generations SET status=? WHERE id=?", status, id)
}

// verify waits for every bind and probe of the generation to pass.
func (c *Coordinator) verify(ctx context.Context, genID, token string, sum Summary) (map[string]any, bool) {
	timeout := c.VerifyTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var missing []string
	var probes []ProbeResult
	for {
		missing = missing[:0]
		for _, b := range sum.Listens {
			addr := b
			if a, p, err := splitAddrPort(b); err == nil && a.IsUnspecified() {
				if a.Is4() {
					addr = "127.0.0.1:" + strconv.Itoa(p)
				} else {
					addr = "[::1]:" + strconv.Itoa(p)
				}
			}
			if !c.Prober.Listening(ctx, addr) {
				missing = append(missing, b)
			}
		}
		probes = probes[:0]
		allOK := len(missing) == 0
		for _, p := range sum.Probes {
			pr := c.Prober.Probe(ctx, p, token, genID, sum.CertFPs[p.CertID])
			probes = append(probes, pr)
			allOK = allOK && pr.OK
		}
		if allOK {
			return map[string]any{"listens": sum.Listens, "probes": probes}, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return map[string]any{"missing_listens": missing, "probes": probes}, false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// compensate restores the previous generation after a failed apply.
func (c *Coordinator) compensate(r *runner, genID, prevID string, _ Summary, f *failure) {
	ctx := context.WithoutCancel(r.ctx)
	if r.state != jobs.Compensating {
		if err := r.to(jobs.Compensating, "compensate", jobs.External, f); err != nil {
			c.recoveryRequired(r, f)
			return
		}
	}
	var st map[string]any
	_ = c.call(ctx, r, "nginx.state", nil, &st)
	cur, _ := st["current"].(string)
	if cur != prevID {
		var act helper.ActivateResult
		if err := c.call(ctx, r, "nginx.activate", helper.ActivateArgs{GenID: prevID, Expected: genID}, &act); err != nil || !act.Activated {
			c.recoveryRequired(r, &failure{Code: "compensation_failed", Message: fmt.Sprintf("could not restore generation %s after: %s", prevID, f.Message), Details: map[string]any{"error": fmt.Sprint(err), "activate": act}})
			return
		}
	}
	// Verify the restored generation if we know it.
	if prevID != helper.EmptyGen {
		if prev, err := c.loadGen(ctx, prevID); err == nil {
			if ev, ok := c.verify(ctx, prevID, prev.ProbeToken, prev.Summary); !ok {
				c.recoveryRequired(r, &failure{Code: "compensation_unverified", Message: "previous generation restored but did not verify", Details: ev})
				return
			}
		}
	}
	c.markGen(ctx, genID, "rolled_back")
	r.end(jobs.RolledBack, "rolled_back", map[string]any{"restored": prevID}, f)
}

// promote records the verified generation as Active (fenced, atomic).
func (c *Coordinator) promote(ctx context.Context, r *runner, genID, prevID string, evidence map[string]any) error {
	err := c.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := c.Locks.FenceFunc(r.lease)(ctx, tx); err != nil {
			return err
		}
		now := store.FormatTime(time.Now())
		if _, err := tx.ExecContext(ctx, "UPDATE config_generations SET status='superseded' WHERE status='active'"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE config_generations SET status='active', activated_at=? WHERE id=?", now, genID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE active_state SET generation_id=?, last_known_good_id=?, revision=revision+1, updated_at=? WHERE id=1", genID, genID, now)
		return err
	})
	if err != nil {
		return err
	}
	r.end(jobs.Succeeded, "succeeded", map[string]any{"generation": genID, "previous": prevID, "verification": evidence}, nil)
	if c.Broker != nil {
		_, _ = c.Broker.Publish(ctx, "gateway.active", "global", map[string]any{"generation": genID})
	}
	return nil
}

func (c *Coordinator) gc(ctx context.Context, r *runner) {
	keep := c.KeepGens
	if keep <= 0 {
		keep = 5
	}
	rows, err := c.DB.QueryContext(ctx, "SELECT id FROM config_generations WHERE status IN ('active','superseded') ORDER BY number DESC LIMIT ?", keep)
	if err != nil {
		return
	}
	var gens []string
	keepKeys := map[string]bool{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		gens = append(gens, id)
	}
	rows.Close()
	for _, g := range gens {
		ag, err := c.loadGen(ctx, g)
		if err != nil {
			return // never delete keys without knowing what retained generations use
		}
		for cid := range ag.Summary.CertFPs {
			f := cid
			if v, ok := ag.Summary.CertKeys[cid]; ok {
				f = v
			}
			keepKeys[f] = true
		}
	}
	cur, err := c.GW.CurrentKeyFiles(ctx)
	if err != nil {
		return
	}
	for _, f := range cur {
		keepKeys[f] = true
	}
	var keys []string
	for f := range keepKeys {
		keys = append(keys, f)
	}
	if err := c.call(ctx, r, "nginx.gc", helper.GCArgs{KeepGens: gens, KeepKeys: keys}, nil); err == nil {
		_, _ = c.GW.PruneKeyVersions(ctx, keepKeys)
	}
}

func (c *Coordinator) ensureDefaultCert(ctx context.Context) (string, error) {
	cs, err := c.GW.ListCertificates(ctx)
	if err != nil {
		return "", err
	}
	for _, ct := range cs {
		if ct.Name == "ngm-default-tls" && ct.Status != "expired" {
			return ct.ID, nil
		}
	}
	ct, err := c.GW.GenerateSelfSigned(ctx, nil, "ngm-default-tls", []string{"ngm-default.invalid"}, 825)
	if err != nil {
		return "", err
	}
	return ct.ID, nil
}

// ─── rollback ──────────────────────────────────────────────────────────────

func (c *Coordinator) runRollback(r *runner) {
	ctx := r.ctx
	var p RollbackPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	target, err := c.loadGen(ctx, p.GenerationID)
	if err != nil {
		r.end(jobs.Blocked, "unknown_generation", nil, &failure{Code: "unknown_generation", Message: "generation not found"})
		return
	}
	var status string
	_ = c.DB.QueryRowContext(ctx, "SELECT status FROM config_generations WHERE id=?", p.GenerationID).Scan(&status)
	if status == "active" {
		r.end(jobs.Blocked, "already_active", nil, &failure{Code: "already_active", Message: "this generation is already active"})
		return
	}
	if status != "superseded" {
		r.end(jobs.Blocked, "not_known_good", nil, &failure{Code: "not_known_good", Message: "only previously verified (superseded) generations can be restored"})
		return
	}
	prev, _ := c.active(ctx)
	prevID := helper.EmptyGen
	if prev != nil {
		prevID = prev.ID
	}
	_ = r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, map[string]any{"from": prevID, "to": target.ID, "diff": diffFiles(prev.filesOrNil(), target.Files)})
	if err := r.to(jobs.Staging, "stage", jobs.Idempotent, nil); err != nil {
		return
	}
	// Re-stage if the generation was garbage-collected from disk.
	var st map[string]any
	if err := c.call(ctx, r, "nginx.state", nil, &st); err != nil {
		c.failSafely(r, &failure{Code: "helper", Message: err.Error()})
		return
	}
	onDisk, ok := c.ensureOnDisk(r, target, st)
	if !ok {
		return
	}
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, map[string]any{"restaged": !onDisk})
	if cur, _ := st["current"].(string); cur != prevID {
		r.end(jobs.Blocked, "drift", nil, &failure{Code: "active_drift", Message: fmt.Sprintf("data plane serves %q, NGM active record is %q", cur, prevID)})
		return
	}
	if err := r.to(jobs.Applying, "apply", jobs.External, map[string]any{"generation": target.ID}); err != nil {
		return
	}
	var act helper.ActivateResult
	if err := c.call(ctx, r, "nginx.activate", helper.ActivateArgs{GenID: target.ID, Expected: prevID}, &act); err != nil {
		// Never claim the old generation stays active without evidence.
		c.resolveUncertain(r, target.ID, prevID, target.Summary, err)
		return
	}
	if !act.Activated {
		_ = r.to(jobs.Compensating, "activate_failed", jobs.Idempotent, map[string]any{"result": act})
		r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "activate_failed", Message: "nginx -t rejected the target generation; the current one stays active"})
		return
	}
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, act)
	ev, ok := c.verify(ctx, target.ID, target.ProbeToken, target.Summary)
	if !ok {
		c.compensate(r, target.ID, prevID, target.Summary, &failure{Code: "verification_failed", Message: "restored generation did not verify", Details: ev})
		return
	}
	if err := c.promote(ctx, r, target.ID, prevID, ev); err != nil {
		c.recoveryRequired(r, &failure{Code: "promote_failed", Message: err.Error()})
	}
}

// ensureOnDisk re-stages a generation (files + TLS keys from the vault) if it
// was garbage-collected from disk. On failure it ends the job and returns ok=false.
func (c *Coordinator) ensureOnDisk(r *runner, target *activeGen, st map[string]any) (wasOnDisk, ok bool) {
	ctx := r.ctx
	if gs, ok := st["generations"].([]any); ok {
		for _, g := range gs {
			if g == target.ID {
				return true, true
			}
		}
	}
	want := map[string]string{}
	for id := range target.Summary.CertFPs {
		want[id] = id // generations before key versioning used the legacy key
		if f, ok := target.Summary.CertKeys[id]; ok {
			want[id] = f
		}
	}
	keys, err := c.GW.KeyVersions(ctx, want)
	if err != nil {
		r.end(jobs.Blocked, "certificate_material", nil, &failure{Code: "certificate_material", Message: "a key used by that generation no longer exists: " + err.Error()})
		return false, false
	}
	keyStr := map[string]string{}
	for id, k := range keys {
		keyStr[id] = string(k)
		clear(k)
	}
	if err := c.call(ctx, r, "nginx.stage", helper.StageArgs{GenID: target.ID, Files: target.Files, Keys: keyStr}, nil); err != nil {
		r.end(jobs.Failed, "stage_failed", nil, &failure{Code: "stage_failed", Message: err.Error()})
		return false, false
	}
	return false, true
}

func (g *activeGen) filesOrNil() map[string]string {
	if g == nil {
		return nil
	}
	return g.Files
}

// ─── crash reconciliation ──────────────────────────────────────────────────

// Reconcile resolves deployment jobs left unfinished by a crash or restart.
// Steps before Applying have no data-plane effect and are failed (resubmit).
// Jobs in Applying/Verifying/Compensating are resolved from runtime evidence
// (the helper's current pointer); ambiguity becomes RecoveryRequired.
func (c *Coordinator) Reconcile(ctx context.Context) error {
	// Generations staged by jobs that ended without success are not deployable.
	if _, err := c.DB.ExecContext(ctx, `UPDATE config_generations SET status='failed' WHERE status='staged'
		AND job_id IN (SELECT id FROM jobs WHERE state IN ('Blocked','Failed','RolledBack','Cancelled'))`); err != nil {
		return err
	}
	un, err := c.Jobs.Unfinished(ctx)
	if err != nil {
		return err
	}
	for _, j := range un {
		set, ok := lockSetFor(j.Kind)
		if !ok || j.State == jobs.Queued || j.State == jobs.RecoveryRequired {
			continue
		}
		lease, err := c.Locks.Acquire(ctx, j.ID, c.Worker, set, leaseTTL)
		if err != nil {
			c.Log.Warn("reconcile: cannot lock", "job", j.ID, "err", err)
			continue
		}
		r := &runner{c: c, j: j, lease: lease, ctx: ctx, state: j.State}
		c.reconcileOne(r)
		_ = c.Locks.Release(ctx, lease)
	}
	return nil
}

func (c *Coordinator) reconcileOne(r *runner) {
	ctx := r.ctx
	if r.j.Kind == KindBackup {
		// Archive writes publish atomically; an interrupted one left nothing.
		if r.state == jobs.Applying || r.state == jobs.Verifying {
			_ = r.to(jobs.Compensating, "interrupted", jobs.Idempotent, nil)
			r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "interrupted", Message: "ngm-ops restarted while writing the backup; no archive was published"})
			return
		}
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "interrupted before writing; resubmit"})
		return
	}
	if r.j.Kind == KindSiteBuild {
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "build interrupted; nothing was published. Build again."})
		return
	}
	if r.j.Kind == KindSitePublish || r.j.Kind == KindSiteDelete {
		if r.state.Cancellable() {
			r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "interrupted before any change; run it again"})
		} else {
			c.recoveryRequired(r, &failure{Code: "interrupted", Message: "interrupted while changing published website files; check the website and publish again"})
		}
		return
	}
	if r.j.Kind == KindDNSPreview || r.j.Kind == KindDNSDiscover || (r.j.Kind == KindDNSApply && r.state.Cancellable()) {
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "interrupted before any DNS change; run it again"})
		return
	}
	if r.j.Kind == KindDNSApply {
		// Cloudflare calls may or may not have happened: preview again to see the zone.
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted_uncertain", Message: "interrupted while applying DNS changes; some may have been applied. Run a new preview to see the zone state."})
		return
	}
	if r.j.Kind == KindACME {
		// An order interrupted before the certificate was stored changed
		// nothing NGM relies on (challenge files are harmless and replaced).
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "ngm-ops restarted during the ACME order; nothing was stored. Run it again."})
		return
	}
	if r.j.Kind == KindReconcile {
		if r.state.Cancellable() {
			r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "reconcile interrupted before any change; run it again"})
		} else {
			c.recoveryRequired(r, &failure{Code: "interrupted", Message: "reconcile interrupted while changing the data plane; run reconcile again from the Recovery Center"})
		}
		return
	}
	if r.j.Kind == KindFirewall && !r.state.Cancellable() {
		// An unconfirmed firewall change interrupted by a restart is reverted:
		// management access must not depend on a confirmation that can no longer arrive.
		c.fwRevert(r, &failure{Code: "interrupted", Message: "ngm-ops restarted during a firewall change; the change was reverted"})
		return
	}
	if r.state.Cancellable() {
		r.end(jobs.Failed, "interrupted", nil, &failure{Code: "interrupted", Message: "ngm-ops restarted before the configuration was applied; no data-plane change was made. Resubmit the deployment."})
		return
	}
	var genID string
	_ = c.DB.QueryRowContext(ctx, "SELECT id FROM config_generations WHERE job_id=? ORDER BY number DESC LIMIT 1", r.j.ID).Scan(&genID)
	if r.j.Kind == KindRollback {
		var p RollbackPayload
		_ = json.Unmarshal(r.j.Payload, &p)
		genID = p.GenerationID
	}
	prev, _ := c.active(ctx)
	prevID := helper.EmptyGen
	if prev != nil {
		prevID = prev.ID
	}
	var st map[string]any
	if err := c.call(ctx, r, "nginx.state", nil, &st); err != nil {
		c.recoveryRequired(r, &failure{Code: "reconcile_helper", Message: "cannot read data-plane state after restart: " + err.Error()})
		return
	}
	cur, _ := st["current"].(string)
	switch {
	case cur == genID && genID != "":
		g, err := c.loadGen(ctx, genID)
		if err != nil {
			c.recoveryRequired(r, &failure{Code: "reconcile", Message: err.Error()})
			return
		}
		if r.state == jobs.Applying {
			_ = r.to(jobs.Verifying, "reconcile_verify", jobs.Idempotent, map[string]any{"current": cur})
		}
		if r.state == jobs.Compensating {
			c.compensate(r, genID, prevID, g.Summary, &failure{Code: "interrupted", Message: "restart during compensation; compensation resumed"})
			return
		}
		if ev, ok := c.verify(ctx, genID, g.ProbeToken, g.Summary); ok {
			if err := c.promote(ctx, r, genID, prevID, ev); err != nil {
				c.recoveryRequired(r, &failure{Code: "promote_failed", Message: err.Error()})
			}
			return
		}
		c.compensate(r, genID, prevID, g.Summary, &failure{Code: "verification_failed", Message: "generation found active after restart but failed verification"})
	case cur == prevID:
		if r.state != jobs.Compensating {
			_ = r.to(jobs.Compensating, "reconcile", jobs.Idempotent, map[string]any{"current": cur})
		}
		c.markGen(ctx, genID, "rolled_back")
		r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "interrupted", Message: "restart during apply; the data plane still serves the previous generation"})
	default:
		c.recoveryRequired(r, &failure{Code: "ambiguous_state", Message: fmt.Sprintf("after restart the data plane serves %q; expected %q or %q", cur, genID, prevID)})
	}
}

// perfView resolves performance settings with the latest memory evidence.
func (c *Coordinator) perfView(ctx context.Context) perf.View { return perf.Current(ctx, c.DB) }

func perfSec(v perf.View, name string) int {
	for _, x := range v.Values {
		if x.Name == name {
			return x.Effective * 1000
		}
	}
	return 0
}
