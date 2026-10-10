package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/fwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/jobs"
)

// ufwSim is a minimal ufw model for coordinator tests.
type ufwSim struct {
	active bool
	rules  []string
}

func (u *ufwSim) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	c := strings.Join(args, " ")
	switch name {
	case "sshd":
		return []byte("port 22\n"), nil, nil
	case "ss", "systemd-run", "systemctl":
		return nil, nil, nil
	}
	switch {
	case c == "status verbose":
		if u.active {
			return []byte("Status: active\n"), nil, nil
		}
		return []byte("Status: inactive\n"), nil, nil
	case c == "show added":
		return []byte("Added user rules:\n" + strings.Join(u.rules, "\n") + "\n"), nil, nil
	case c == "--force enable":
		u.active = true
	case c == "disable":
		u.active = false
	case strings.HasPrefix(c, "--force delete "):
		spec := strings.TrimPrefix(c, "--force delete ")
		for i, r := range u.rules {
			if strings.HasPrefix(r, "ufw "+spec) {
				u.rules = append(u.rules[:i], u.rules[i+1:]...)
				break
			}
		}
	case strings.Contains(c, " comment "):
		spec, cm, _ := strings.Cut(c, " comment ")
		u.rules = append(u.rules, "ufw "+spec+" comment '"+cm+"'")
	default:
		return nil, nil, errors.New("unexpected " + c)
	}
	return nil, nil, nil
}

// fwHelper routes fw.* to a real helper.Firewall on the simulator.
type fwHelper struct {
	*fakeHelper
	fw *helper.Firewall
}

func (h *fwHelper) Call(ctx context.Context, req ipc.Request, out any) error {
	if !strings.HasPrefix(req.Op, "fw.") {
		return h.fakeHelper.Call(ctx, req, out)
	}
	if req.Op != "fw.state" && (req.JobID == "" || req.Fence == 0) {
		return &ipc.Error{Code: "fence_required", Message: "x"}
	}
	var res any
	var err error
	switch req.Op {
	case "fw.state":
		res, err = h.fw.State(ctx)
	case "fw.apply":
		var a helper.FWApplyArgs
		json.Unmarshal(req.Args, &a)
		res, err = h.fw.Apply(ctx, a)
	case "fw.confirm":
		var a struct {
			PlanID string `json:"plan_id"`
		}
		json.Unmarshal(req.Args, &a)
		err = h.fw.Confirm(ctx, a.PlanID)
	case "fw.revert":
		var a struct {
			PlanID string `json:"plan_id"`
		}
		json.Unmarshal(req.Args, &a)
		res, err = h.fw.Revert(ctx, a.PlanID)
	}
	if err != nil {
		return err
	}
	if out != nil {
		b, _ := json.Marshal(res)
		return json.Unmarshal(b, out)
	}
	return nil
}

func fwEnv(t *testing.T) (*env, *ufwSim, *fwstore.Service) {
	e := newEnv(t)
	u := &ufwSim{}
	e.c.Helper = &fwHelper{fakeHelper: e.h, fw: &helper.Firewall{Run: u, PlanDir: t.TempDir(), NGMBin: "/x/ngm", Config: "/x.json"}}
	SetFirewallTiming(30*time.Second, 29*time.Second, 20*time.Millisecond) // 1 s confirmation window
	t.Cleanup(func() { SetFirewallTiming(120*time.Second, 15*time.Second, time.Second) })
	return e, u, &fwstore.Service{DB: e.db, Audit: e.c.Audit}
}

func submitFW(t *testing.T, e *env, enable bool, confirm *fwstore.Service) *jobs.Job {
	ctx := context.Background()
	j, _, _ := e.c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindFirewall, ActorID: "U1", Payload: FirewallPayload{Enable: enable}})
	if confirm != nil {
		go func() {
			for i := 0; i < 100; i++ {
				if err := confirm.Confirm(ctx, nil, j.ID); err == nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	e.c.RunOnce(ctx)
	j, _ = e.c.Jobs.Get(ctx, j.ID)
	return j
}

func TestFirewallEnableConfirmed(t *testing.T) {
	e, u, fw := fwEnv(t)
	u.rules = []string{"ufw allow 8443/tcp"} // foreign
	if _, err := fw.Create(context.Background(), nil, fwstore.Rule{Key: "web", Action: "allow", Proto: "tcp", Port: 80}); err != nil {
		t.Fatal(err)
	}
	j := submitFW(t, e, true, fw)
	if j.State != jobs.Succeeded || !u.active {
		t.Fatalf("%s %s active=%v", j.State, j.Error, u.active)
	}
	all := strings.Join(u.rules, "\n")
	if !strings.Contains(all, "ngm:ssh-guard") || !strings.Contains(all, "ngm:web") || !strings.Contains(all, "ufw allow 8443/tcp") {
		t.Fatalf("rules %v", u.rules)
	}
	rs, _ := fw.List(context.Background())
	if rs[0].ActiveState != "present" {
		t.Fatalf("active state %+v", rs[0])
	}
}

func TestFirewallUnconfirmedReverts(t *testing.T) {
	e, u, fw := fwEnv(t)
	if _, err := fw.Create(context.Background(), nil, fwstore.Rule{Key: "web", Action: "allow", Proto: "tcp", Port: 80}); err != nil {
		t.Fatal(err)
	}
	j := submitFW(t, e, true, nil)
	if j.State != jobs.RolledBack || !strings.Contains(string(j.Error), "not_confirmed") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	if u.active || len(u.rules) != 0 {
		t.Fatalf("not reverted: active=%v rules=%v", u.active, u.rules)
	}
}

func TestFirewallSafeChangeNeedsNoConfirmation(t *testing.T) {
	e, u, fw := fwEnv(t)
	if _, err := fw.Create(context.Background(), nil, fwstore.Rule{Key: "web", Action: "allow", Proto: "tcp", Port: 80}); err != nil {
		t.Fatal(err)
	}
	j := submitFW(t, e, false, nil) // ufw inactive, only allow rules
	if j.State != jobs.Succeeded || u.active {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	// Removing a desired rule deletes only that owned rule.
	rs, _ := fw.List(context.Background())
	fw.Delete(context.Background(), nil, rs[0].ID, rs[0].Revision)
	u.rules = append(u.rules, "ufw allow 9000/tcp")
	j = submitFW(t, e, false, nil)
	if j.State != jobs.Succeeded || strings.Contains(strings.Join(u.rules, " "), "ngm:web") || !strings.Contains(strings.Join(u.rules, " "), "9000") {
		t.Fatalf("%s rules=%v", j.State, u.rules)
	}
}

func TestFirewallBlocksSSHDeny(t *testing.T) {
	e, _, fw := fwEnv(t)
	fw.Create(context.Background(), nil, fwstore.Rule{Key: "nossh", Action: "deny", Proto: "tcp", Port: 22})
	j := submitFW(t, e, true, nil)
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "ssh_guard") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
}

func TestOpenIncidentBlocksSameFamilyOnly(t *testing.T) {
	e, u, fw := fwEnv(t)
	ctx := context.Background()
	fw.Create(ctx, nil, fwstore.Rule{Key: "web", Action: "allow", Proto: "tcp", Port: 80})
	// An earlier firewall job left an open incident.
	old, _, _ := e.c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindFirewall, IdempotencyKey: "old-fw-job", Payload: FirewallPayload{}})
	e.db.ExecContext(ctx, `INSERT INTO recovery_incidents(id,job_id,status,summary,opened_at) VALUES('INC1',?,'open','x',?)`, old.ID, time.Now().UTC().Format(time.RFC3339Nano))
	e.c.Jobs.Cancel(ctx, old.ID, "")
	j := submitFW(t, e, false, nil)
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "open_recovery_incident") || len(u.rules) != 0 {
		t.Fatalf("%s %s rules=%v", j.State, j.Error, u.rules)
	}
	// Resolved → firewall jobs run again.
	e.db.ExecContext(ctx, `UPDATE recovery_incidents SET status='resolved' WHERE id='INC1'`)
	if j := submitFW(t, e, false, nil); j.State != jobs.Succeeded {
		t.Fatalf("after resolve: %s %s", j.State, j.Error)
	}
}
