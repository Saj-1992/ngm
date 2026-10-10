//go:build linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ngm-gateway/ngm/internal/ipc"
)

type scriptRunner struct {
	failTest   bool
	failReload bool
	calls      []string
}

func (s *scriptRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	c := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, c)
	switch {
	case c == "nginx -t" && s.failTest:
		return nil, []byte("nginx: [emerg] unknown directive"), errors.New("exit 1")
	case c == "nginx -t":
		return nil, []byte("nginx: configuration file test is successful"), nil
	case strings.HasPrefix(c, "systemctl is-active"):
		return []byte("active\n"), nil, nil
	case c == "systemctl reload nginx.service" && s.failReload:
		return nil, []byte("Job failed"), errors.New("exit 1")
	case strings.HasPrefix(c, "systemctl show"):
		return []byte("1234\n"), nil, nil
	}
	return nil, nil, nil
}

const g1 = "01J9AAAAAAAAAAAAAAAAAAAAAA"
const g2 = "01J9BBBBBBBBBBBBBBBBBBBBBB"
const c1 = "01J9CCCCCCCCCCCCCCCCCCCCCC"

func setup(t *testing.T) (*NginxOps, *scriptRunner, string) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "conf.d"), 0o755)
	os.MkdirAll(filepath.Join(root, "modules-enabled"), 0o755)
	r := &scriptRunner{}
	o := &NginxOps{L: NginxLayout{Root: root, Public: filepath.Join(root, "www")}, Run: r}
	if _, err := o.EnsureLayout(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	return o, r, root
}

func stage(t *testing.T, o *NginxOps, gen string) {
	_, err := o.Stage(context.Background(), StageArgs{GenID: gen, Files: map[string]string{"http/ngm.conf": "# " + gen, "stream/ngm.conf": "#", "certs/" + c1 + ".crt": "CERT"},
		Keys: map[string]string{c1: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLayoutHooksAndOwnership(t *testing.T) {
	o, _, root := setup(t)
	b, _ := os.ReadFile(filepath.Join(root, "conf.d", "ngm.conf"))
	if !strings.HasPrefix(string(b), hookMarker) || !strings.Contains(string(b), "include "+root+"/ngm/current/http/*.conf;") {
		t.Fatalf("http hook: %s", b)
	}
	if cur, _ := o.currentGen(); cur != EmptyGen {
		t.Fatalf("current=%s", cur)
	}
	// Foreign file at hook path is never overwritten.
	o2 := &NginxOps{L: NginxLayout{Root: t.TempDir()}, Run: &scriptRunner{}}
	os.MkdirAll(filepath.Join(o2.L.Root, "conf.d"), 0o755)
	os.WriteFile(filepath.Join(o2.L.Root, "conf.d", "ngm.conf"), []byte("server {}"), 0o644)
	if _, err := o2.EnsureLayout(context.Background(), false); err == nil {
		t.Fatal("overwrote foreign hook")
	}
	// Hooks rejected by nginx -t are removed again.
	o3 := &NginxOps{L: NginxLayout{Root: t.TempDir()}, Run: &scriptRunner{failTest: true}}
	os.MkdirAll(filepath.Join(o3.L.Root, "conf.d"), 0o755)
	if _, err := o3.EnsureLayout(context.Background(), false); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(filepath.Join(o3.L.Root, "conf.d", "ngm.conf")); err == nil {
		t.Fatal("rejected hook left behind")
	}
}

func TestStageIsImmutableAndValidated(t *testing.T) {
	o, _, root := setup(t)
	stage(t, o, g1)
	st, _ := os.Stat(filepath.Join(root, "ngm", "keys", c1+".key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	if _, err := o.Stage(context.Background(), StageArgs{GenID: g1, Files: map[string]string{"http/ngm.conf": "x"}}); err == nil {
		t.Fatal("restaged existing generation")
	}
	bad := []StageArgs{
		{GenID: "../../etc", Files: map[string]string{"http/ngm.conf": "x"}},
		{GenID: g2, Files: map[string]string{"../../../etc/passwd": "x"}},
		{GenID: g2, Files: map[string]string{"http/evil.conf": "x"}},
		{GenID: g2, Files: map[string]string{"certs/../../x.crt": "x"}},
		{GenID: g2, Keys: map[string]string{"../x": "PRIVATE KEY"}},
	}
	for _, a := range bad {
		var e *ipc.Error
		if _, err := o.Stage(context.Background(), a); !errors.As(err, &e) || e.Code != "bad_args" {
			t.Errorf("accepted %+v: %v", a, err)
		}
	}
}

func TestActivateTestFailureReverts(t *testing.T) {
	o, r, _ := setup(t)
	stage(t, o, g1)
	res, err := o.Activate(context.Background(), ActivateArgs{GenID: g1, Expected: EmptyGen})
	if err != nil || !res.Activated || res.Reloaded != "reload" {
		t.Fatalf("%+v %v", res, err)
	}
	stage(t, o, g2)
	// CAS guard.
	var e *ipc.Error
	if _, err := o.Activate(context.Background(), ActivateArgs{GenID: g2, Expected: EmptyGen}); !errors.As(err, &e) || e.Code != "current_changed" {
		t.Fatalf("cas: %v", err)
	}
	r.failTest = true
	res, err = o.Activate(context.Background(), ActivateArgs{GenID: g2, Expected: g1})
	if err != nil || res.Activated || !strings.Contains(res.TestOutput, "unknown directive") {
		t.Fatalf("%+v %v", res, err)
	}
	if cur, _ := o.currentGen(); cur != g1 {
		t.Fatalf("pointer not reverted: %s", cur)
	}
	for _, c := range r.calls[len(r.calls)-1:] {
		if strings.Contains(c, "reload") {
			t.Fatal("reloaded after failed test")
		}
	}
	// Reload failure: revert pointer and reload previous.
	r.failTest, r.failReload = false, true
	if _, err := o.Activate(context.Background(), ActivateArgs{GenID: g2, Expected: g1}); !errors.As(err, &e) || e.Code != "reload_failed" {
		t.Fatalf("reload failure: %v", err)
	}
	if cur, _ := o.currentGen(); cur != g1 {
		t.Fatalf("pointer not reverted after reload failure: %s", cur)
	}
}

func TestGCKeepsCurrent(t *testing.T) {
	o, _, root := setup(t)
	stage(t, o, g1)
	stage(t, o, g2)
	o.Activate(context.Background(), ActivateArgs{GenID: g2})
	o.GC(context.Background(), GCArgs{KeepGens: nil, KeepKeys: nil})
	if _, err := os.Stat(filepath.Join(root, "ngm", "gen", g2)); err != nil {
		t.Fatal("current generation removed")
	}
	if _, err := os.Stat(filepath.Join(root, "ngm", "gen", g1)); err == nil {
		t.Fatal("old generation kept")
	}
}

func TestMutatingOpsRequireFence(t *testing.T) {
	o, _, _ := setup(t)
	o.Fence = func(context.Context, string, string, int64) error { return errors.New("stale") }
	h := &Helper{Policy: Policy{Allowed: map[uint32][]string{0: {"*"}}}, Run: &scriptRunner{}, Nginx: o}
	var e *ipc.Error
	if _, err := h.Handle(context.Background(), ipc.Peer{UID: 0}, ipc.Request{Op: "nginx.gc", Args: []byte(`{}`)}); !errors.As(err, &e) || e.Code != "fence_required" {
		t.Fatalf("no fence: %v", err)
	}
	if _, err := h.Handle(context.Background(), ipc.Peer{UID: 0}, ipc.Request{Op: "nginx.gc", JobID: "j", Fence: 3, Args: []byte(`{}`)}); !errors.As(err, &e) || e.Code != "stale_fence" {
		t.Fatalf("stale fence: %v", err)
	}
	if _, err := h.Handle(context.Background(), ipc.Peer{UID: 0}, ipc.Request{Op: "nginx.state"}); err != nil {
		t.Fatalf("read-only op: %v", err)
	}
}

func TestAcmeChallengeFiles(t *testing.T) {
	old := syscall.Umask(0o077) // as under systemd UMask=0077
	defer syscall.Umask(old)
	o, _, root := setup(t)
	ctx := context.Background()
	tok := "AbCdEfGhIjKlMnOpQrStUv0123456789_-x"
	ka := tok + "." + strings.Repeat("Z", 43)
	for _, bad := range []AcmeArgs{
		{Token: "../../etc/passwd", KeyAuth: ka},
		{Token: "short", KeyAuth: "short." + strings.Repeat("Z", 43)},
		{Token: tok, KeyAuth: tok + ".bad"},
		{Token: tok, KeyAuth: "Other0123456789Other." + strings.Repeat("Z", 43)}, // key auth for another token
		{Token: tok, KeyAuth: ka + "\nserver { }"},
	} {
		if _, err := o.AcmePut(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := o.AcmePut(ctx, AcmeArgs{Token: tok, KeyAuth: ka}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "www", "acme", tok)
	st, err := os.Stat(p)
	b, _ := os.ReadFile(p)
	if err != nil || st.Mode().Perm() != 0o644 || string(b) != ka {
		t.Fatalf("challenge file: %v %v %q", err, st.Mode(), b)
	}
	// The directory must not be a symlink (no redirection of writes).
	if _, err := o.AcmeClear(ctx, AcmeArgs{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("not cleared")
	}
	os.RemoveAll(filepath.Join(root, "www", "acme"))
	os.Symlink(t.TempDir(), filepath.Join(root, "www", "acme"))
	if _, err := o.AcmePut(ctx, AcmeArgs{Token: tok, KeyAuth: ka}); err == nil {
		t.Fatal("wrote through a symlinked acme directory")
	}
}

func TestSitePublishActivateGC(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	o, _, root := setup(t)
	o.WebsitesRoot = filepath.Join(root, "websites")
	ctx := context.Background()
	const site, v1, v2 = "01J9SSSSSSSSSSSSSSSSSSSSSS", "01J9V1V1V1V1V1V1V1V1V1V1V1", "01J9V2V2V2V2V2V2V2V2V2V2V2"
	build := func(v, body string) string {
		d := filepath.Join(o.WebsitesRoot, site, "builds", v)
		os.MkdirAll(filepath.Join(d, "assets"), 0o750)
		os.WriteFile(filepath.Join(d, "index.html"), []byte(body), 0o640)
		os.WriteFile(filepath.Join(d, "assets", "a.css"), []byte("x"), 0o640)
		return d
	}
	build(v1, "one")
	res, err := o.SitePublish(ctx, SiteArgs{SiteID: site, VersionID: v1})
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(root, "www", "sites", site)
	b, _ := os.ReadFile(filepath.Join(pub, "current", "index.html"))
	st, _ := os.Stat(filepath.Join(pub, v1, "assets", "a.css"))
	dst, _ := os.Stat(filepath.Join(pub, v1, "assets"))
	if string(b) != "one" || st.Mode().Perm() != 0o644 || dst.Mode().Perm() != 0o755 || res["previous"] != "" {
		t.Fatalf("publish v1: %q %v %v %v", b, st.Mode(), dst.Mode(), res)
	}
	// A symlink inside a build is refused (no reading outside the build).
	d2 := build(v2, "two")
	os.Symlink("/etc/shadow", filepath.Join(d2, "leak.html"))
	if _, err := o.SitePublish(ctx, SiteArgs{SiteID: site, VersionID: v2}); err == nil {
		t.Fatal("symlink in build published")
	}
	if cur, _ := o.siteCurrent(site); cur != v1 {
		t.Fatal("failed publish moved the pointer")
	}
	os.Remove(filepath.Join(d2, "leak.html"))
	if _, err := o.SitePublish(ctx, SiteArgs{SiteID: site, VersionID: v2}); err != nil {
		t.Fatal(err)
	}
	// Rollback with CAS on the expected pointer.
	if _, err := o.SiteActivate(ctx, SiteArgs{SiteID: site, VersionID: v1, Expected: v1}); err == nil {
		t.Fatal("activate with a wrong expected pointer")
	}
	if _, err := o.SiteActivate(ctx, SiteArgs{SiteID: site, VersionID: v1, Expected: v2}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(pub, "current", "index.html"))
	if string(b) != "one" {
		t.Fatal("rollback content")
	}
	// Re-publishing an existing copy verifies it against the build.
	os.WriteFile(filepath.Join(pub, v2, "index.html"), []byte("tampered"), 0o644)
	if _, err := o.SitePublish(ctx, SiteArgs{SiteID: site, VersionID: v2}); err == nil {
		t.Fatal("tampered published copy accepted")
	}
	if r, _ := o.SiteGC(ctx, SiteArgs{SiteID: site}); len(r["removed"].([]string)) != 1 {
		t.Fatalf("gc: %v", r)
	}
	for _, bad := range []SiteArgs{{SiteID: "../../etc", VersionID: v1}, {SiteID: site, VersionID: "../x"}} {
		if _, err := o.SitePublish(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := o.SiteRemove(ctx, SiteArgs{SiteID: site}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pub); !os.IsNotExist(err) {
		t.Fatal("site not removed")
	}
}
