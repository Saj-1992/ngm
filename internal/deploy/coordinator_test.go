package deploy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// fakeHelper simulates the helper's data-plane state.
type fakeHelper struct {
	mu              sync.Mutex
	current         string
	staged          map[string]bool
	defaultSite     bool
	failTest        bool
	failReload      bool
	failActivateTo  map[string]bool
	crashAfterSwap  bool                         // activate swaps the pointer, then the connection drops
	crashNoSwap     bool                         // activate dies before swapping
	downStates      int                          // nginx.state fails this many times (helper restarting)
	downAfterCrash  int                          // if set, downStates after a simulated crash
	stagedKeys      map[string]map[string]string // generation → key file id → PEM
	acme            map[string]string            // published HTTP-01 responses
	sites           map[string]string            // site → current version
	siteIndex       map[string]string            // version → index sha (what the copy contains)
	siteIndexSum    string                       // forced index sha (simulates a bad copy)
	sitePublishFail bool
	calls           []string
}

func (f *fakeHelper) Call(_ context.Context, req ipc.Request, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req.Op)
	if req.Op != "nginx.state" && (req.JobID == "" || req.Fence == 0) {
		return &ipc.Error{Code: "fence_required", Message: "x"}
	}
	set := func(v any) error {
		if out == nil {
			return nil
		}
		b, _ := json.Marshal(v)
		return json.Unmarshal(b, out)
	}
	switch req.Op {
	case "nginx.ensure_layout":
		if f.current == "" {
			f.current = helper.EmptyGen
		}
		return set(map[string]any{})
	case "nginx.stage":
		var a helper.StageArgs
		json.Unmarshal(req.Args, &a)
		f.staged[a.GenID] = true
		if f.stagedKeys == nil {
			f.stagedKeys = map[string]map[string]string{}
		}
		f.stagedKeys[a.GenID] = a.Keys
		return set(map[string]any{"manifest": map[string]string{}})
	case "nginx.state":
		if f.downStates > 0 {
			f.downStates--
			return errors.New("dial unix /run/ngm/helper.sock: connect: no such file or directory")
		}
		gens := []any{}
		for g := range f.staged {
			gens = append(gens, g)
		}
		return set(map[string]any{"current": f.current, "generations": gens, "distro_default_site_enabled": f.defaultSite})
	case "nginx.disable_default_site":
		f.defaultSite = false
		return set(map[string]any{"changed": true})
	case "nginx.activate":
		var a helper.ActivateArgs
		json.Unmarshal(req.Args, &a)
		if a.Expected != "" && a.Expected != f.current {
			return &ipc.Error{Code: "current_changed", Message: "x"}
		}
		if f.crashNoSwap {
			f.crashNoSwap = false
			f.downStates = 2
			return errors.New("helper response: EOF")
		}
		if f.crashAfterSwap {
			f.crashAfterSwap = false
			f.current = a.GenID
			f.downStates = 2
			if f.downAfterCrash != 0 {
				f.downStates = f.downAfterCrash
			}
			return errors.New("helper response: EOF")
		}
		if f.failActivateTo[a.GenID] {
			return errors.New("boom")
		}
		if f.failTest {
			return set(helper.ActivateResult{Previous: f.current, Current: f.current, TestOutput: "emerg"})
		}
		if f.failReload {
			return &ipc.Error{Code: "reload_failed", Message: "reload failed"}
		}
		prev := f.current
		f.current = a.GenID
		return set(helper.ActivateResult{Activated: true, Previous: prev, Current: a.GenID, Reloaded: "reload"})
	case "site.state", "site.publish", "site.activate", "site.gc", "site.remove":
		var a helper.SiteArgs
		json.Unmarshal(req.Args, &a)
		if f.sites == nil {
			f.sites = map[string]string{}
		}
		switch req.Op {
		case "site.state":
			return set(map[string]any{"current": f.sites[a.SiteID]})
		case "site.publish":
			if f.sitePublishFail {
				return &ipc.Error{Code: "copy_failed", Message: "disk full"}
			}
			prev := f.sites[a.SiteID]
			f.sites[a.SiteID] = a.VersionID
			sum := f.siteIndexSum
			if sum == "" {
				sum = f.siteIndex[a.VersionID]
			}
			return set(map[string]any{"previous": prev, "current": a.VersionID, "index_sha256": sum})
		case "site.activate":
			if f.sites[a.SiteID] != a.Expected {
				return &ipc.Error{Code: "current_changed", Message: "x"}
			}
			f.sites[a.SiteID] = a.VersionID
		case "site.remove":
			delete(f.sites, a.SiteID)
		}
		return set(map[string]any{})
	case "acme.put", "acme.clear":
		var a helper.AcmeArgs
		json.Unmarshal(req.Args, &a)
		if f.acme == nil {
			f.acme = map[string]string{}
		}
		if req.Op == "acme.put" {
			f.acme[a.Token] = a.KeyAuth
		} else {
			delete(f.acme, a.Token)
		}
		return set(map[string]any{})
	case "nginx.gc":
		return set(map[string]any{})
	}
	return &ipc.Error{Code: "unknown_op", Message: req.Op}
}

// fakeProber answers like Nginx serving whatever generation is current.
type fakeProber struct {
	h        *fakeHelper
	failGens map[string]bool
}

func (p *fakeProber) Probe(_ context.Context, pr gateway.Probe, _, wantGen, _ string) ProbeResult {
	p.h.mu.Lock()
	cur := p.h.current
	p.h.mu.Unlock()
	if cur != wantGen || p.failGens[wantGen] {
		return ProbeResult{Probe: pr, Error: "wrong generation"}
	}
	return ProbeResult{Probe: pr, OK: true, Generation: wantGen}
}
func (p *fakeProber) Listening(context.Context, string) bool { return true }

type env struct {
	c  *Coordinator
	h  *fakeHelper
	p  *fakeProber
	db *store.DB
	gw *gwstore.Service
}

func newEnv(t *testing.T) *env {
	db := storetest.New(t)
	kr := vault.NewKeyring()
	k := make([]byte, 32)
	rand.Read(k)
	kr.Add(1, k)
	v := vault.New(db, kr)
	v.Init(context.Background())
	gw := gwstore.New(db, v, audit.New(db))
	h := &fakeHelper{staged: map[string]bool{}, failActivateTo: map[string]bool{}}
	p := &fakeProber{h: h, failGens: map[string]bool{}}
	c := &Coordinator{DB: db, Jobs: jobs.NewJournal(db), Locks: locks.NewManager(db), GW: gw, Audit: audit.New(db), Helper: h, Prober: p,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Worker: "test", APIListen: "127.0.0.1:9999", VerifyTimeout: 300 * time.Millisecond}
	observe.Record(context.Background(), db, observe.KindNginx, observe.Nginx{Installed: true, Version: "1.24.0", ServiceState: "active", StreamModule: true, SSLPreread: true, HTTPV2: true}, 0)
	return &env{c, h, p, db, gw}
}

func (e *env) seed(t *testing.T, port int) {
	ctx := context.Background()
	l, err := e.gw.SaveListener(ctx, nil, &gateway.Listener{Name: "web", Kind: gateway.KindHTTP, Address: "0.0.0.0", Port: port, Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := e.gw.SaveEndpoint(ctx, nil, &gateway.Endpoint{Name: "app", Host: "127.0.0.1", Port: 8081, Transport: "http"}, 0)
	if _, err := e.gw.SaveRoute(ctx, nil, &gateway.Route{Name: "site", ListenerID: l.ID, Protocol: gateway.ProtoHTTP, DestKind: gateway.DestEndpoint, DestID: ep.ID, Enabled: true,
		Matches: []gateway.Match{{Field: "host", Operator: "exact", Value: "a.example.com"}}}, 0); err != nil {
		t.Fatal(err)
	}
}

func (e *env) submit(t *testing.T, kind string, payload any) *jobs.Job {
	j, _, err := e.c.Jobs.Submit(context.Background(), jobs.SubmitRequest{Kind: kind, ActorID: "U1", LockSet: []string{"gateway-config"}, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.c.RunOnce(context.Background()); !ok || err != nil {
		t.Fatalf("RunOnce ok=%v err=%v", ok, err)
	}
	j, _ = e.c.Jobs.Get(context.Background(), j.ID)
	return j
}

func (e *env) active(t *testing.T) string {
	var g *string
	e.db.QueryRowContext(context.Background(), "SELECT generation_id FROM active_state WHERE id=1").Scan(&g)
	if g == nil {
		return ""
	}
	return *g
}

func TestApplyHappyPathAndNoChanges(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 8080)
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.Succeeded {
		t.Fatalf("state %s err %s", j.State, j.Error)
	}
	gen := e.active(t)
	if gen == "" || e.h.current != gen || !e.h.staged[gen] {
		t.Fatalf("active=%s current=%s", gen, e.h.current)
	}
	steps, _ := e.c.Jobs.Steps(context.Background(), j.ID)
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	want := "validate impact stage preflight apply nginx.activate verify succeeded"
	if strings.Join(names, " ") != want {
		t.Fatalf("steps %v", names)
	}
	// Unchanged model → Blocked(no_changes).
	j2 := e.submit(t, KindApply, ApplyPayload{})
	if j2.State != jobs.Blocked || !strings.Contains(string(j2.Error), "no_changes") {
		t.Fatalf("%s %s", j2.State, j2.Error)
	}
	// Lock released.
	hs, _ := e.c.Locks.List(context.Background())
	if len(hs) != 0 {
		t.Fatalf("leases left: %+v", hs)
	}
}

func TestValidationBlocks(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 22) // SSH port → management lockout risk
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "listener_reserved_port") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	if len(e.h.calls) != 0 {
		t.Fatalf("helper called for invalid model: %v", e.h.calls)
	}
}

func TestVerificationFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 8080)
	first := e.submit(t, KindApply, ApplyPayload{})
	good := e.active(t)
	_ = first
	// Change the model and make the new generation fail verification.
	ep, _ := e.gw.ListEndpoints(context.Background())
	ep[0].Port = 8082
	e.gw.SaveEndpoint(context.Background(), nil, ep[0], ep[0].Revision)
	e.p.failGens = map[string]bool{}
	orig := e.p
	e.c.Prober = &failNew{orig: orig, good: good}
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.RolledBack {
		t.Fatalf("state %s err %s", j.State, j.Error)
	}
	if e.h.current != good || e.active(t) != good {
		t.Fatalf("not restored: current=%s active=%s good=%s", e.h.current, e.active(t), good)
	}
}

// failNew fails probes for any generation except good.
type failNew struct {
	orig *fakeProber
	good string
}

func (f *failNew) Probe(ctx context.Context, p gateway.Probe, tok, want, fp string) ProbeResult {
	if want != f.good {
		return ProbeResult{Probe: p, Error: "502"}
	}
	return f.orig.Probe(ctx, p, tok, want, fp)
}
func (f *failNew) Listening(context.Context, string) bool { return true }

func TestNginxTestAndReloadFailures(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 8080)
	e.h.failTest = true
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.RolledBack || !strings.Contains(string(j.Error), "nginx_test_failed") || e.h.current != helper.EmptyGen {
		t.Fatalf("test failure: %s %s current=%s", j.State, j.Error, e.h.current)
	}
	e.h.failTest, e.h.failReload = false, true
	j = e.submit(t, KindApply, ApplyPayload{Force: true})
	if j.State != jobs.RolledBack || !strings.Contains(string(j.Error), "reload_failed") {
		t.Fatalf("reload failure: %s %s", j.State, j.Error)
	}
}

func TestCompensationFailureNeedsRecovery(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 8080)
	e.submit(t, KindApply, ApplyPayload{})
	good := e.active(t)
	e.c.Prober = &failNew{orig: e.p, good: good}
	e.h.failActivateTo[good] = true // cannot restore
	j := e.submit(t, KindApply, ApplyPayload{Force: true})
	if j.State != jobs.RecoveryRequired {
		t.Fatalf("state %s", j.State)
	}
	var n int
	e.db.QueryRowContext(context.Background(), "SELECT count(*) FROM recovery_incidents WHERE job_id=? AND status='open'", j.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("incidents %d", n)
	}
}

func TestPreflightPortConflictAndDefaultSite(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 80)
	observe.Record(context.Background(), e.db, observe.KindNginx, observe.Nginx{Installed: true, Version: "1.24.0", ServiceState: "active", StreamModule: true, SSLPreread: true,
		OtherListeners: []string{"0.0.0.0:80 apache2"}}, 0)
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "apache2") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	observe.Record(context.Background(), e.db, observe.KindNginx, observe.Nginx{Installed: true, Version: "1.24.0", ServiceState: "active", StreamModule: true, SSLPreread: true, HTTPV2: true}, 0)
	e.h.defaultSite = true
	j = e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "distro_default_site") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	var staged int
	e.db.QueryRowContext(context.Background(), "SELECT count(*) FROM config_generations WHERE status='staged'").Scan(&staged)
	if staged != 0 {
		t.Fatalf("%d generation(s) left in staged state by blocked jobs", staged)
	}
	j = e.submit(t, KindApply, ApplyPayload{DisableDistroDefaultSite: true})
	if j.State != jobs.Succeeded || e.h.defaultSite {
		t.Fatalf("%s %s", j.State, j.Error)
	}
}

func TestReconcileAfterCrash(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		pointerAtNew bool
		pointerElse  bool
		want         jobs.State
	}{
		"applied before crash": {pointerAtNew: true, want: jobs.Succeeded},
		"not applied":          {want: jobs.RolledBack},
		"ambiguous":            {pointerElse: true, want: jobs.RecoveryRequired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.seed(t, 8080)
			crashed := make(chan struct{})
			e.c.Helper = &crashingHelper{fakeHelper: e.h, crashed: crashed}
			j, _, _ := e.c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindApply, ActorID: "U1"})
			go e.c.RunOnce(ctx) // the worker "dies" inside activate, leaving the job in Applying
			<-crashed
			time.Sleep(100 * time.Millisecond)
			got, _ := e.c.Jobs.Get(ctx, j.ID)
			if got.State != jobs.Applying {
				t.Fatalf("setup: state %s", got.State)
			}
			var gen string
			e.db.QueryRowContext(ctx, "SELECT id FROM config_generations WHERE job_id=?", j.ID).Scan(&gen)
			switch {
			case tc.pointerAtNew:
				e.h.current = gen
			case tc.pointerElse:
				e.h.current = "01J9ZZZZZZZZZZZZZZZZZZZZZZ"
			}
			e.c.Helper = e.h
			// Simulated restart: the old lease expired.
			e.db.ExecContext(ctx, "UPDATE lock_leases SET expires_at=?", store.FormatTime(time.Now().Add(-time.Minute)))
			if err := e.c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			got, _ = e.c.Jobs.Get(ctx, j.ID)
			if got.State != tc.want {
				t.Fatalf("state %s, want %s (%s)", got.State, tc.want, got.Error)
			}
		})
	}
}

// crashingHelper simulates the worker dying during activation: the goroutine
// exits without any further journal writes (runtime.Goexit skips recover).
type crashingHelper struct {
	*fakeHelper
	crashed chan struct{}
}

func (c *crashingHelper) Call(ctx context.Context, req ipc.Request, out any) error {
	if req.Op == "nginx.activate" {
		close(c.crashed)
		runtime.Goexit()
	}
	return c.fakeHelper.Call(ctx, req, out)
}

func TestRollbackToPreviousGeneration(t *testing.T) {
	e := newEnv(t)
	e.seed(t, 8080)
	e.submit(t, KindApply, ApplyPayload{})
	g1 := e.active(t)
	e.submit(t, KindApply, ApplyPayload{Force: true})
	g2 := e.active(t)
	if g1 == g2 {
		t.Fatal("expected a new generation")
	}
	delete(e.h.staged, g1) // garbage-collected from disk → must be re-staged
	j := e.submit(t, KindRollback, RollbackPayload{GenerationID: g1})
	if j.State != jobs.Succeeded || e.active(t) != g1 || e.h.current != g1 || !e.h.staged[g1] {
		t.Fatalf("rollback: %s %s active=%s", j.State, j.Error, e.active(t))
	}
	j = e.submit(t, KindRollback, RollbackPayload{GenerationID: g1})
	if j.State != jobs.Blocked {
		t.Fatalf("rollback to active: %s", j.State)
	}
}

func TestHelperCrashDuringActivationIsResolvedFromEvidence(t *testing.T) {
	uncertainWait = 5 * time.Second
	t.Cleanup(func() { uncertainWait = 30 * time.Second })
	// 1. Crash after the swap: the new generation serves and verifies → Succeeded.
	e := newEnv(t)
	e.seed(t, 8080)
	e.h.crashAfterSwap = true
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.Succeeded || e.active(t) != e.h.current {
		t.Fatalf("after-swap crash: %s %s active=%s cur=%s", j.State, j.Error, e.active(t), e.h.current)
	}
	g1 := e.active(t)
	// 2. Crash before the swap: previous generation verified still serving → RolledBack.
	e.bump(t, 8081)
	e.h.crashNoSwap = true
	j = e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.RolledBack || !strings.Contains(string(j.Error), "activate_interrupted") || e.active(t) != g1 || e.h.current != g1 {
		t.Fatalf("no-swap crash: %s %s", j.State, j.Error)
	}
	// 3. Crash after the swap but the new generation does not verify (e.g. not reloaded) → compensated.
	e.bump(t, 8083)
	e.h.crashAfterSwap = true
	e.p.failGens = map[string]bool{}
	var next string
	e.c.Prober = proberHook{e.p, func(gen string) bool { next = gen; return gen != g1 }}
	j = e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.RolledBack || e.h.current != g1 || e.active(t) != g1 || next == "" {
		t.Fatalf("unverified after-swap crash: %s %s cur=%s", j.State, j.Error, e.h.current)
	}
	// 4. Helper never returns → RecoveryRequired (no guess).
	e.c.Prober = e.p
	e.h.downStates = 1 << 30
	uncertainWait = 1500 * time.Millisecond
	rq := e.submitNoState(t)
	if rq.State != jobs.RecoveryRequired {
		t.Fatalf("helper gone: %s %s", rq.State, rq.Error)
	}
}

// proberHook fails probes for generations where fail(gen) is true.
type proberHook struct {
	p    *fakeProber
	fail func(gen string) bool
}

func (h proberHook) Probe(ctx context.Context, pr gateway.Probe, tok, wantGen, fp string) ProbeResult {
	if h.fail(wantGen) {
		return ProbeResult{Probe: pr, Error: "generation header missing"}
	}
	return h.p.Probe(ctx, pr, tok, wantGen, fp)
}
func (h proberHook) Listening(ctx context.Context, a string) bool { return true }

// submitNoState submits an apply while nginx.state is failing: preflight must
// see the state, so let the first call succeed by toggling downStates around it.
func (e *env) submitNoState(t *testing.T) *jobs.Job {
	down := e.h.downStates
	e.h.downStates = 0
	e.h.mu.Lock()
	e.h.crashAfterSwap = true
	e.h.mu.Unlock()
	// Change the model so the apply is not a no-op.
	e.bump(t, 8082)
	j, _, _ := e.c.Jobs.Submit(context.Background(), jobs.SubmitRequest{Kind: KindApply, ActorID: "U1", LockSet: []string{"gateway-config"}, Payload: ApplyPayload{}})
	// After activation crashes, the helper stays down.
	e.h.mu.Lock()
	e.h.downAfterCrash = down
	e.h.mu.Unlock()
	e.c.RunOnce(context.Background())
	j, _ = e.c.Jobs.Get(context.Background(), j.ID)
	return j
}

// bump changes the desired model (one more listener) so an apply is not a no-op.
func (e *env) bump(t *testing.T, port int) {
	if _, err := e.gw.SaveListener(context.Background(), nil, &gateway.Listener{Name: fmt.Sprintf("extra-%d", port), Kind: gateway.KindHTTP, Address: "0.0.0.0", Port: port, Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
}

// driftEnv leaves the data plane on gen2 while NGM records gen1, with an open
// incident (helper crashed after the swap and never came back during the job).
func driftEnv(t *testing.T) (e *env, gen1, gen2, incident string) {
	uncertainWait = 300 * time.Millisecond
	t.Cleanup(func() { uncertainWait = 30 * time.Second })
	e = newEnv(t)
	e.seed(t, 8080)
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatal(j.State)
	}
	gen1 = e.active(t)
	e.bump(t, 8090)
	e.h.crashAfterSwap = true
	e.h.downAfterCrash = 1 << 30
	j := e.submit(t, KindApply, ApplyPayload{})
	if j.State != jobs.RecoveryRequired {
		t.Fatalf("setup: %s %s", j.State, j.Error)
	}
	e.h.downStates, e.h.downAfterCrash = 0, 0 // helper is back
	gen2 = e.h.current
	e.db.QueryRowContext(context.Background(), "SELECT id FROM recovery_incidents WHERE job_id=?", j.ID).Scan(&incident)
	if gen2 == gen1 || incident == "" {
		t.Fatalf("setup drift gen1=%s gen2=%s inc=%s", gen1, gen2, incident)
	}
	// New applies are blocked while the incident is open.
	e.bump(t, 8091)
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Blocked {
		t.Fatalf("apply during incident: %s", j.State)
	}
	return
}

func incidentStatus(e *env, id string) string {
	var s string
	e.db.QueryRowContext(context.Background(), "SELECT status FROM recovery_incidents WHERE id=?", id).Scan(&s)
	return s
}

func TestReconcileAdoptServingGeneration(t *testing.T) {
	e, _, gen2, inc := driftEnv(t)
	j := e.submit(t, KindReconcile, ReconcilePayload{Mode: "adopt", IncidentID: inc})
	if j.State != jobs.Succeeded || e.active(t) != gen2 || incidentStatus(e, inc) != "resolved" {
		t.Fatalf("adopt: %s %s active=%s inc=%s", j.State, j.Error, e.active(t), incidentStatus(e, inc))
	}
	// Applies work again.
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatalf("apply after adopt: %s %s", j.State, j.Error)
	}
}

func TestReconcileRestoreRecordedGeneration(t *testing.T) {
	e, gen1, _, inc := driftEnv(t)
	j := e.submit(t, KindReconcile, ReconcilePayload{Mode: "restore", IncidentID: inc})
	if j.State != jobs.Succeeded || e.h.current != gen1 || e.active(t) != gen1 || incidentStatus(e, inc) != "resolved" {
		t.Fatalf("restore: %s %s cur=%s", j.State, j.Error, e.h.current)
	}
}

func TestReconcileAdoptRefusesUnverified(t *testing.T) {
	e, gen1, gen2, inc := driftEnv(t)
	e.p.failGens[gen2] = true
	j := e.submit(t, KindReconcile, ReconcilePayload{Mode: "adopt", IncidentID: inc})
	if j.State != jobs.RolledBack || e.active(t) != gen1 || e.h.current != gen2 || incidentStatus(e, inc) == "resolved" {
		t.Fatalf("unverified adopt must change nothing: %s %s", j.State, j.Error)
	}
}

func TestRollbackAfterRenewalUsesTheOldKeyVersion(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	cert, err := e.gw.GenerateSelfSigned(ctx, nil, "tls", []string{"a.example.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := e.gw.SaveListener(ctx, nil, &gateway.Listener{Name: "tls", Kind: gateway.KindHTTPS, Address: "0.0.0.0", Port: 8443, Enabled: true}, 0)
	ep, _ := e.gw.SaveEndpoint(ctx, nil, &gateway.Endpoint{Name: "app", Host: "127.0.0.1", Port: 8081, Transport: "http"}, 0)
	if _, err := e.gw.SaveRoute(ctx, nil, &gateway.Route{Name: "site", ListenerID: l.ID, Protocol: gateway.ProtoHTTP, DestKind: gateway.DestEndpoint, DestID: ep.ID, CertificateID: cert.ID, Enabled: true,
		Matches: []gateway.Match{{Field: "host", Operator: "exact", Value: "a.example.com"}}}, 0); err != nil {
		t.Fatal(err)
	}
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	g1 := e.active(t)
	var k1 string
	var v1 string
	for f, k := range e.h.stagedKeys[g1] {
		v1, k1 = f, k
	}
	g1row, _ := e.c.loadGen(ctx, g1)
	if !strings.Contains(g1row.Files["http/ngm.conf"], "keys/"+v1+".key") || v1 == cert.ID {
		t.Fatalf("generation 1 must reference its key version %s", v1)
	}
	// Renew: new key version; generation 2 uses it.
	cp, kp, _ := gwstore.SelfSigned([]string{"a.example.com"}, 60*24*time.Hour, time.Now())
	if _, err := e.gw.ReplaceCertificate(ctx, nil, cert.ID, cp, string(kp)); err != nil {
		t.Fatal(err)
	}
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatalf("after renewal: %s %s", j.State, j.Error)
	}
	g2 := e.active(t)
	for f := range e.h.stagedKeys[g2] {
		if f == v1 {
			t.Fatal("generation 2 reused the old key version")
		}
	}
	// Roll back to generation 1 after it was garbage-collected from disk.
	delete(e.h.staged, g1)
	j := e.submit(t, KindRollback, RollbackPayload{GenerationID: g1})
	if j.State != jobs.Succeeded {
		t.Fatalf("rollback: %s %s", j.State, j.Error)
	}
	if got := e.h.stagedKeys[g1][v1]; got != k1 {
		t.Fatal("rollback re-staged generation 1 without its original key version")
	}
}
