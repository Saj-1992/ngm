package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/observe"
)

type fakeRunner struct {
	calls [][]string
	out   map[string][2]string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	o, ok := f.out[name]
	if !ok {
		return nil, nil, errors.New("not found")
	}
	return []byte(o[0]), []byte(o[1]), nil
}

func TestPolicyAndAllowlist(t *testing.T) {
	h := &Helper{Policy: Policy{Allowed: map[uint32][]string{0: {"*"}, 997: {"ping", "observe.nginx"}, 1000: {"ping"}}}, Run: &fakeRunner{}}
	ctx := context.Background()
	if _, err := h.Handle(ctx, ipc.Peer{UID: 997}, ipc.Request{Op: "ping"}); err != nil {
		t.Fatal(err)
	}
	var e *ipc.Error
	if _, err := h.Handle(ctx, ipc.Peer{UID: 1000}, ipc.Request{Op: "observe.nginx"}); !errors.As(err, &e) || e.Code != "forbidden" {
		t.Fatalf("uid 1000 observe: %v", err)
	}
	if _, err := h.Handle(ctx, ipc.Peer{UID: 4242}, ipc.Request{Op: "ping"}); !errors.As(err, &e) || e.Code != "forbidden" {
		t.Fatalf("unknown uid: %v", err)
	}
	for _, op := range []string{"exec", "shell.run", "file.write", "nginx.reload"} {
		if _, err := h.Handle(ctx, ipc.Peer{UID: 0}, ipc.Request{Op: op}); !errors.As(err, &e) || e.Code != "unknown_op" {
			t.Errorf("op %s: %v", op, err)
		}
	}
	if _, err := h.Handle(ctx, ipc.Peer{UID: 0}, ipc.Request{Op: "ping", Args: json.RawMessage(`{"cmd":"id"}`)}); !errors.As(err, &e) || e.Code != "bad_args" {
		t.Fatalf("args accepted: %v", err)
	}
}

func TestExecRunnerRefusesNonAllowlisted(t *testing.T) {
	if _, _, err := (ExecRunner{}).Run(context.Background(), "/bin/sh", "-c", "id"); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := (ExecRunner{}).Run(context.Background(), "bash"); err == nil {
		t.Fatal("bash allowed")
	}
}

func TestParsers(t *testing.T) {
	dp := "nginx\tinstall ok installed\t1.24.0-2ubuntu7.18\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
		"nginx-common\tinstall ok installed\t1.24.0-2ubuntu7.18\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
		"libnginx-mod-stream\tdeinstall ok config-files\t1.24.0-2ubuntu7.18\tUbuntu Developers <x@lists.ubuntu.com>\n"
	pk := ParseDpkg(dp)
	if !pk["nginx"].Installed || pk["libnginx-mod-stream"].Installed || Origin(pk["nginx"]) != "ubuntu" {
		t.Fatalf("%+v", pk)
	}
	if o := Origin(Pkg{Version: "1.26.2-1~noble", Maintainer: "NGINX Packaging <nginx-packaging@f5.com>"}); o != "other" {
		t.Fatalf("nginx.org origin = %s", o)
	}
	var n observe.Nginx
	static, dyn := ParseNginxV("nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL 3.0.13\nconfigure arguments: --with-http_v2_module --with-stream=dynamic --with-stream_ssl_module --with-stream_ssl_preread_module", &n)
	if n.Version != "1.24.0" || !n.HTTPV2 || !n.SSLPreread || static || !dyn {
		t.Fatalf("%+v static=%v dyn=%v", n, static, dyn)
	}
	p := ParseProps("ActiveState=active\nMainPID=812\nLoadState=loaded\n")
	if p["ActiveState"] != "active" || p["MainPID"] != "812" {
		t.Fatal(p)
	}
	ss := `LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=813,fd=5),("nginx",pid=812,fd=5))
LISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=813,fd=6),("nginx",pid=812,fd=6))
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=893,fd=3))`
	l := ParseSSListeners(ss, "nginx")
	if len(l) != 2 || l[0] != "0.0.0.0:80" || l[1] != "[::]:80" {
		t.Fatalf("%v", l)
	}
}

func TestObserveNotInstalled(t *testing.T) {
	r := &fakeRunner{out: map[string][2]string{
		"systemctl": {"ActiveState=inactive\nMainPID=0\nLoadState=not-found\n", ""},
		"ss":        {"LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", ""},
	}}
	n := ObserveNginx(context.Background(), r)
	if n.ServiceState != "not-found" || len(n.Listeners) != 0 || n.StreamModule {
		t.Fatalf("%+v", n)
	}
	// dpkg-query failure is reported, not guessed.
	if len(n.Errors) == 0 {
		t.Fatal("missing error evidence")
	}
}
