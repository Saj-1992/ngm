package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeRun struct {
	calls   []string
	ufw     string
	added   string
	nginxOK bool
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	switch {
	case c == "ufw status numbered":
		return f.ufw, nil
	case c == "ufw show added":
		return f.added, nil
	case name == "nginx" && !f.nginxOK:
		return "nginx: [emerg] test failure", errors.New("exit 1")
	}
	return "", nil
}

func put(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(p))
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func layout(t *testing.T) string {
	root := t.TempDir()
	put(t, root, "/usr/sbin/nginx", "bin")
	put(t, root, "/etc/nginx/conf.d/ngm.conf", hookMarker+" (Nginx Gateway Manager).\ninclude x;\n")
	put(t, root, "/etc/nginx/modules-enabled/99-ngm-stream.conf", "# operator file that happens to use our name\n")
	put(t, root, "/etc/nginx/conf.d/thirdparty.conf", "server {}\n")
	put(t, root, "/etc/nginx/sites-available/default", "server {}\n")
	put(t, root, "/etc/nginx/ngm/.default-site-disabled", "/etc/nginx/sites-available/default\n")
	put(t, root, "/etc/systemd/system/ngm-api.service", "[Unit]\n")
	put(t, root, "/etc/systemd/system/other.service", "[Unit]\n")
	put(t, root, "/opt/ngm/releases/1.0.0/ngm", "bin")
	put(t, root, "/etc/ngm/ngm.json", "{}")
	put(t, root, "/var/lib/ngm/ngm.db", "")
	put(t, root, "/var/www/ngm/sites/x/index.html", "hi")
	os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0o755)
	return root
}

const ufwOut = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # ngm:http
[ 3] 7000/tcp                   ALLOW IN    Anywhere                   # ngm:echo
[ 4] 9000/tcp                   ALLOW IN    Anywhere                   # someone-else
`

func TestKeepDataPreservesDataAndThirdParty(t *testing.T) {
	root := layout(t)
	fr := &fakeRun{ufw: ufwOut, nginxOK: true}
	u := &Uninstaller{Root: root, Run: fr}
	plan := u.Plan(context.Background(), KeepData)
	var kept bool
	for _, a := range plan {
		if a.Kind == "keep" && strings.Contains(a.Target, "99-ngm-stream.conf") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("unowned file with NGM's name must be kept: %+v", plan)
	}
	if err := u.Execute(context.Background(), KeepData, t.Logf); err != nil {
		t.Fatal(err)
	}
	gone := []string{"/etc/nginx/conf.d/ngm.conf", "/opt/ngm", "/etc/systemd/system/ngm-api.service"}
	stay := []string{"/etc/nginx/modules-enabled/99-ngm-stream.conf", "/etc/nginx/conf.d/thirdparty.conf", "/etc/systemd/system/other.service",
		"/etc/ngm/ngm.json", "/var/lib/ngm/ngm.db", "/var/www/ngm/sites/x/index.html"}
	for _, p := range gone {
		if exists(filepath.Join(root, p)) {
			t.Errorf("%s should be removed", p)
		}
	}
	for _, p := range stay {
		if !exists(filepath.Join(root, p)) {
			t.Errorf("%s must be kept", p)
		}
	}
	if l, err := os.Readlink(filepath.Join(root, "/etc/nginx/sites-enabled/default")); runtime.GOOS != "windows" && (err != nil || l != "/etc/nginx/sites-available/default") {
		t.Errorf("default site not restored: %q %v", l, err)
	}
	for _, c := range fr.calls {
		if strings.HasPrefix(c, "ufw --force delete") || strings.HasPrefix(c, "userdel") {
			t.Errorf("keep-data ran %q", c)
		}
	}
}

func TestPurgeRemovesOnlyNGMRules(t *testing.T) {
	root := layout(t)
	fr := &fakeRun{ufw: ufwOut, nginxOK: true}
	u := &Uninstaller{Root: root, Run: fr}
	if err := u.Execute(context.Background(), Purge, t.Logf); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, c := range fr.calls {
		if strings.HasPrefix(c, "ufw --force delete") {
			dels = append(dels, strings.TrimPrefix(c, "ufw --force delete "))
		}
	}
	// Highest number first so earlier numbers stay valid; non-NGM 1 and 4 untouched.
	if strings.Join(dels, ",") != "3,2" {
		t.Fatalf("ufw deletes: %v", dels)
	}
	for _, p := range []string{"/etc/ngm", "/var/lib/ngm", "/var/www/ngm"} {
		if exists(filepath.Join(root, p)) {
			t.Errorf("%s should be purged", p)
		}
	}
	if !exists(filepath.Join(root, "/etc/nginx/conf.d/thirdparty.conf")) {
		t.Error("third-party nginx file removed")
	}
}

func TestPurgeKeepsOnlySSHRule(t *testing.T) {
	root := layout(t)
	out := strings.Replace(ufwOut, "[ 1] 22/tcp                     ALLOW IN    Anywhere\n", "[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ngm:ssh\n", 1)
	fr := &fakeRun{ufw: out, nginxOK: true}
	if rs := (&Uninstaller{Root: root, Run: fr}).ufwRules(context.Background()); strings.Join(rs, ",") != "3,2" {
		t.Fatalf("the only SSH allow rule must survive purge: %v", rs)
	}
}

func TestNginxTestFailureRestoresHooks(t *testing.T) {
	root := layout(t)
	fr := &fakeRun{nginxOK: false}
	u := &Uninstaller{Root: root, Run: fr}
	if err := u.Execute(context.Background(), KeepData, t.Logf); err == nil {
		t.Fatal("expected failure")
	}
	if !exists(filepath.Join(root, "/etc/nginx/conf.d/ngm.conf")) || !exists(filepath.Join(root, "/opt/ngm")) {
		t.Fatal("hooks must be restored and nothing else removed")
	}
	if exists(filepath.Join(root, "/etc/nginx/sites-enabled/default")) {
		t.Fatal("default site re-enable must be undone")
	}
}

func TestAptSimulationAndModuleSet(t *testing.T) {
	sim := `Reading package lists...
Inst nginx-common [1.24.0-2ubuntu7] (1.24.0-2ubuntu7.1 Ubuntu:24.04/noble-updates [all])
Inst libnginx-mod-stream [1.24.0-2ubuntu7] (1.24.0-2ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])
Inst nginx [1.24.0-2ubuntu7] (1.24.0-2ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])
Conf nginx-common (1.24.0-2ubuntu7.1 Ubuntu:24.04/noble-updates [all])`
	up := ParseSimulation(sim)
	if len(up) != 3 || up[0].From != "1.24.0-2ubuntu7" || up[0].To != "1.24.0-2ubuntu7.1" {
		t.Fatalf("parse: %+v", up)
	}
	inst := []string{"nginx", "nginx-common", "libnginx-mod-stream", "libnginx-mod-http-geoip"}
	if err := CheckModuleSet(inst, up); err == nil {
		t.Fatal("module left behind must be refused")
	}
	if err := CheckModuleSet(inst[:3], up); err != nil {
		t.Fatal(err)
	}
}

func TestGCReleasesKeepsCurrentPreviousAndRecent(t *testing.T) {
	dir := t.TempDir()
	rels := filepath.Join(dir, "releases")
	names := []string{"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0"}
	for i, n := range names {
		os.MkdirAll(filepath.Join(rels, n), 0o755)
		ts := time.Now().Add(time.Duration(i-len(names)) * time.Hour)
		os.Chtimes(filepath.Join(rels, n), ts, ts)
	}
	cur := filepath.Join(dir, "current")
	if err := os.Symlink(filepath.Join(rels, "0.2.0"), cur); err != nil {
		t.Skip("symlinks unavailable")
	}
	gone, err := GCReleases(rels, cur, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	// Kept: current 0.2.0, protected 0.1.0, newest three 0.7/0.6/0.5. Removed: 0.4, 0.3.
	if strings.Join(gone, ",") != "0.4.0,0.3.0" {
		t.Fatalf("removed %v", gone)
	}
}

func TestPurgeWithInactiveUFW(t *testing.T) {
	root := layout(t)
	added := "Added user rules (see 'ufw status' for running firewall):\n" +
		"ufw allow 22/tcp comment 'ngm:ssh-guard'\n" +
		"ufw allow 80/tcp comment 'ngm:listener-80'\n" +
		"ufw allow 9000/tcp comment 'someone-else'\n"
	fr := &fakeRun{ufw: "Status: inactive\n", added: added, nginxOK: true}
	if err := (&Uninstaller{Root: root, Run: fr}).Execute(context.Background(), Purge, t.Logf); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, c := range fr.calls {
		if strings.HasPrefix(c, "ufw --force delete") {
			dels = append(dels, strings.TrimPrefix(c, "ufw --force delete "))
		}
	}
	// Only the NGM listener rule; the only SSH rule and the foreign rule stay.
	if strings.Join(dels, ",") != "allow 80/tcp" {
		t.Fatalf("deletes: %v", dels)
	}
}
