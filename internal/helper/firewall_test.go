package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/ipc"
)

// fakeUFW models ufw's rule list and enablement.
type fakeUFW struct {
	active  bool
	rules   []string // "ufw allow ... comment 'ngm:x'" lines
	timers  map[string]bool
	sshPort int
	calls   []string
}

func (u *fakeUFW) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	c := strings.Join(args, " ")
	u.calls = append(u.calls, name+" "+c)
	switch name {
	case "sshd":
		return []byte(fmt.Sprintf("port %d\n", u.sshPort)), nil, nil
	case "ss":
		return []byte("ESTAB 0 0 10.0.0.2:22 198.51.100.7:51234\n"), nil, nil
	case "systemd-run":
		u.timers[strings.TrimPrefix(args[0], "--unit=")] = true
		return nil, nil, nil
	case "systemctl":
		delete(u.timers, strings.TrimSuffix(args[len(args)-1], ".timer"))
		return nil, nil, nil
	case "ufw":
	default:
		return nil, nil, errors.New("unexpected binary " + name)
	}
	switch {
	case c == "status verbose":
		if u.active {
			return []byte("Status: active\nDefault: deny (incoming), allow (outgoing)\n"), nil, nil
		}
		return []byte("Status: inactive\n"), nil, nil
	case c == "show added":
		return []byte("Added user rules (see 'ufw status' for running firewall):\n" + strings.Join(u.rules, "\n") + "\n"), nil, nil
	case c == "--force enable":
		u.active = true
		return []byte("Firewall is active"), nil, nil
	case c == "disable":
		u.active = false
		return nil, nil, nil
	case strings.HasPrefix(c, "--force delete "):
		spec := strings.TrimPrefix(c, "--force delete ")
		for i, r := range u.rules {
			if strings.HasPrefix(r, "ufw "+spec) {
				u.rules = append(u.rules[:i], u.rules[i+1:]...)
				return nil, nil, nil
			}
		}
		return nil, nil, errors.New("rule not found")
	case strings.Contains(c, " comment "):
		spec, comment, _ := strings.Cut(c, " comment ")
		for _, r := range u.rules {
			if strings.HasPrefix(r, "ufw "+spec) {
				return []byte("Skipping adding existing rule"), nil, nil
			}
		}
		u.rules = append(u.rules, "ufw "+spec+" comment '"+comment+"'")
		return []byte("Rule added"), nil, nil
	}
	return nil, nil, errors.New("unexpected ufw " + c)
}

func newFW(t *testing.T) (*Firewall, *fakeUFW) {
	u := &fakeUFW{timers: map[string]bool{}, sshPort: 22}
	return &Firewall{Run: u, PlanDir: t.TempDir(), NGMBin: "/opt/ngm/current/ngm", Config: "/etc/ngm/ngm.json"}, u
}

const plan1 = "01J9PPPPPPPPPPPPPPPPPPPPPP"
const plan2 = "01J9QQQQQQQQQQQQQQQQQQQQQQ"

var web = FWRule{Key: "listener-web", Action: "allow", Proto: "tcp", Port: 80, Source: "any"}

func TestEnableAddsSSHGuardAndWatchdog(t *testing.T) {
	f, u := newFW(t)
	u.rules = []string{"ufw allow 8080/tcp"} // foreign rule, never touched
	res, err := f.Apply(context.Background(), FWApplyArgs{PlanID: plan1, Add: []FWRule{web}, Enable: true, WatchdogSecs: 120})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Enabled || res.Watchdog == "" || !u.timers[res.Watchdog] {
		t.Fatalf("%+v timers=%v", res, u.timers)
	}
	if !strings.Contains(strings.Join(u.rules, "\n"), "allow proto tcp from any to any port 22 comment 'ngm:ssh-guard'") {
		t.Fatalf("ssh guard missing: %v", u.rules)
	}
	// SSH guard was added before enable.
	gi, ei := -1, -1
	for i, c := range u.calls {
		if strings.Contains(c, "ngm:ssh-guard") && gi < 0 {
			gi = i
		}
		if c == "ufw --force enable" {
			ei = i
		}
	}
	if gi < 0 || ei < gi {
		t.Fatalf("guard must precede enable: %v", u.calls)
	}
	for _, c := range u.calls {
		if strings.Contains(c, "reset") || strings.Contains(c, "8080") && strings.Contains(c, "delete") {
			t.Fatalf("forbidden call %q", c)
		}
	}
	// Watchdog fires (no confirmation): everything NGM did is undone, foreign rule kept.
	out, err := f.Revert(context.Background(), plan1)
	if err != nil || out["reverted"] != true {
		t.Fatalf("%v %v", out, err)
	}
	if u.active || len(u.rules) != 1 || u.rules[0] != "ufw allow 8080/tcp" {
		t.Fatalf("after revert active=%v rules=%v", u.active, u.rules)
	}
	if _, err := os.Stat(f.planPath(plan1)); err == nil {
		t.Fatal("plan not removed")
	}
}

func TestConfirmDisarms(t *testing.T) {
	f, u := newFW(t)
	res, _ := f.Apply(context.Background(), FWApplyArgs{PlanID: plan1, Add: []FWRule{web}, Enable: true, WatchdogSecs: 60})
	if err := f.Confirm(context.Background(), plan1); err != nil {
		t.Fatal(err)
	}
	if u.timers[res.Watchdog] {
		t.Fatal("timer still armed")
	}
	// A late watchdog firing finds no plan and changes nothing.
	out, _ := f.Revert(context.Background(), plan1)
	if out["reverted"] != false || !u.active {
		t.Fatalf("late revert changed state: %v active=%v", out, u.active)
	}
}

func TestSafetyRules(t *testing.T) {
	f, u := newFW(t)
	var e *ipc.Error
	if _, err := f.Apply(context.Background(), FWApplyArgs{PlanID: plan1, Add: []FWRule{{Key: "x", Action: "deny", Proto: "tcp", Port: 22, Source: "any"}}}); !errors.As(err, &e) || e.Code != "ssh_guard" {
		t.Fatalf("deny on SSH port: %v", err)
	}
	if _, err := f.Apply(context.Background(), FWApplyArgs{PlanID: plan1, Delete: []FWRule{{Key: SSHGuardKey, Action: "allow", Proto: "tcp", Port: 22, Source: "any"}}}); !errors.As(err, &e) || e.Code != "ssh_guard" {
		t.Fatalf("delete guard: %v", err)
	}
	for _, bad := range []FWRule{{Key: "a;b", Action: "allow", Proto: "tcp", Port: 1, Source: "any"}, {Key: "a", Action: "reset", Proto: "tcp", Port: 1, Source: "any"},
		{Key: "a", Action: "allow", Proto: "tcp", Port: 1, Source: "any; rm -rf /"}, {Key: "a", Action: "allow", Proto: "icmp", Port: 1, Source: "any"}} {
		if _, err := f.Apply(context.Background(), FWApplyArgs{PlanID: plan1, Add: []FWRule{bad}}); !errors.As(err, &e) || e.Code != "bad_args" {
			t.Errorf("accepted %+v: %v", bad, err)
		}
	}
	// Identical foreign rule: not owned, never deleted later.
	u.rules = []string{"ufw allow proto tcp from any to any port 80"}
	res, err := f.Apply(context.Background(), FWApplyArgs{PlanID: plan2, Add: []FWRule{web}})
	if err != nil || len(res.Shared) != 1 {
		t.Fatalf("shared: %+v %v", res, err)
	}
	st, _ := f.State(context.Background())
	if _, owned := st.Owned["listener-web"]; owned {
		t.Fatal("foreign rule became owned")
	}
}

func TestSSHDetection(t *testing.T) {
	f, u := newFW(t)
	u.sshPort = 2222
	u.rules = []string{"ufw allow 2222/tcp"}
	st, err := f.State(context.Background())
	if err != nil || !st.SSHOpen || st.SSHPorts[0] != 2222 {
		t.Fatalf("%+v %v", st, err)
	}
	u.rules = []string{"ufw allow from 10.0.0.0/8 to any port 2222"}
	st, _ = f.State(context.Background())
	if st.SSHOpen {
		t.Fatal("restricted-source rule must not count as open SSH")
	}
}
