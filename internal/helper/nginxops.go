package helper

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/store"
)

// NginxLayout describes the NGM-owned Nginx tree. Paths are fixed in
// production; tests point Root at a temporary directory.
type NginxLayout struct {
	Root string // /etc/nginx
	// Public is the NGM-owned tree Nginx workers may read (ACME challenges,
	// published websites): /var/www/ngm. The generation/key tree stays 0700.
	Public string
	// LogDir is where generated servers write logs (/var/log/ngm/nginx).
	LogDir string
}

func (n NginxLayout) public() string {
	if n.Public != "" {
		return n.Public
	}
	return "/var/www/ngm"
}

func (n NginxLayout) ngm() string      { return filepath.Join(n.Root, "ngm") }
func (n NginxLayout) gens() string     { return filepath.Join(n.ngm(), "gen") }
func (n NginxLayout) keys() string     { return filepath.Join(n.ngm(), "keys") }
func (n NginxLayout) current() string  { return filepath.Join(n.ngm(), "current") }
func (n NginxLayout) marker() string   { return filepath.Join(n.ngm(), ".ngm-owned") }
func (n NginxLayout) httpHook() string { return filepath.Join(n.Root, "conf.d", "ngm.conf") }
func (n NginxLayout) streamHook() string {
	return filepath.Join(n.Root, "modules-enabled", "99-ngm-stream.conf")
}

const hookMarker = "# NGM hook — owned by NGM (Nginx Gateway Manager). Removing it disconnects NGM-managed routes."

// EmptyGen is the generation active before the first apply.
const EmptyGen = "empty"

var (
	genIDRe  = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	stageRel = regexp.MustCompile(`^(http/ngm\.conf|stream/ngm\.conf|certs/[0-9A-HJKMNP-TV-Z]{26}\.crt)$`)
)

// Limits on staged content.
const (
	maxFile  = 4 << 20
	maxTotal = 12 << 20
)

// FenceChecker verifies that job/fence currently hold the lock on resource.
type FenceChecker func(ctx context.Context, resource, jobID string, fence int64) error

// DBFenceChecker opens the NGM database read-only and checks the lease.
func DBFenceChecker(dbPath string) FenceChecker {
	return func(ctx context.Context, resource, jobID string, fence int64) error {
		db, err := store.Open(dbPath, store.Options{ReadOnly: true, MaxOpenConns: 1})
		if err != nil {
			return err
		}
		defer db.Close()
		var latest int64
		if err := db.QueryRowContext(ctx, "SELECT latest_token FROM lock_fences WHERE resource=?", resource).Scan(&latest); err != nil {
			return fmt.Errorf("no %s lease: %w", resource, err)
		}
		var holder, exp string
		err = db.QueryRowContext(ctx, "SELECT holder_job_id, expires_at FROM lock_leases WHERE resource=? AND fencing_token=?", resource, fence).Scan(&holder, &exp)
		if errors.Is(err, sql.ErrNoRows) || latest != fence {
			return errors.New("stale fencing token")
		}
		if err != nil {
			return err
		}
		t, _ := store.ParseTime(exp)
		if holder != jobID || !time.Now().Before(t) {
			return errors.New("lease not held by this job")
		}
		return nil
	}
}

// NginxOps implements data-plane operations.
type NginxOps struct {
	L NginxLayout
	// WebsitesRoot is where builds are read from (default /var/lib/ngm/websites).
	WebsitesRoot string
	Run          Runner
	Fence        FenceChecker
	mu           sync.Mutex // serialises mutations inside the helper
}

type fencedArgs struct {
	JobID string `json:"job_id"`
	Fence int64  `json:"fence"`
}

func (o *NginxOps) checkFence(ctx context.Context, req ipc.Request) error {
	return o.checkFenceFor("gateway-config")(ctx, req)
}

func (o *NginxOps) checkFenceFor(resource string) func(context.Context, ipc.Request) error {
	return func(ctx context.Context, req ipc.Request) error {
		if o.Fence == nil {
			return nil
		}
		if req.JobID == "" || req.Fence == 0 {
			return &ipc.Error{Code: "fence_required", Message: "mutating operations require job_id and fence"}
		}
		if err := o.Fence(ctx, resource, req.JobID, req.Fence); err != nil {
			return &ipc.Error{Code: "stale_fence", Message: err.Error()}
		}
		return nil
	}
}

func notSymlinkDir(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("%s must be a real directory", p)
	}
	return nil
}

func writeExclusive(p string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func hookOwned(p string) (exists, owned bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return false, false
	}
	return true, strings.HasPrefix(string(b), hookMarker)
}

// EnsureLayout creates the NGM tree, an empty generation and the include
// hooks. It refuses to overwrite hook files it does not own.
func (o *NginxOps) EnsureLayout(ctx context.Context, withStream bool) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, d := range []string{o.L.ngm(), o.L.gens(), o.L.keys()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		if err := notSymlinkDir(d); err != nil {
			return nil, err
		}
	}
	_ = os.Chmod(o.L.keys(), 0o700)
	// NGM log files (nginx -t fails if the directory is missing). The files
	// are created here, 0640 and group-readable (directory is setgid ngm), so
	// the unprivileged log indexer can read them whatever umask Nginx runs
	// with; Nginx keeps the mode of an existing file when it (re)opens it.
	if o.L.LogDir != "" {
		if err := os.MkdirAll(o.L.LogDir, 0o751); err != nil {
			return nil, err
		}
		if err := notSymlinkDir(o.L.LogDir); err != nil {
			return nil, err
		}
		// Workers (www-data) reopen logs by path after rotation: traversal
		// (o+x) is required on this directory and its parent.
		// The helper unit runs with RestrictSUIDSGID=yes, so a chmod whose mode
		// carries the setgid bit is refused by seccomp. The installer sets
		// setgid (group inheritance); here only permission bits are repaired,
		// and only when they differ.
		if st, err := os.Stat(o.L.LogDir); err != nil {
			return nil, err
		} else if st.Mode().Perm() != 0o751 {
			if err := os.Chmod(o.L.LogDir, 0o751); err != nil {
				return nil, err
			}
		}
		if st, err := os.Stat(filepath.Dir(o.L.LogDir)); err == nil && st.Mode().Perm()&0o001 == 0 {
			_ = os.Chmod(filepath.Dir(o.L.LogDir), st.Mode().Perm()|0o001)
		}
		for _, n := range []string{"access.jsonl", "stream.jsonl", "error.log"} {
			p := filepath.Join(o.L.LogDir, n)
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND|oNoFollow, 0o640)
			if err != nil {
				return nil, fmt.Errorf("log file %s: %w", n, err)
			}
			f.Close()
			if err := os.Chmod(p, 0o640); err != nil {
				return nil, err
			}
		}
	}
	if _, err := os.Stat(o.L.marker()); err != nil {
		if err := os.WriteFile(o.L.marker(), []byte("owned-by=ngm\n"), 0o644); err != nil {
			return nil, err
		}
	}
	empty := filepath.Join(o.L.gens(), EmptyGen)
	if _, err := os.Stat(empty); err != nil {
		for _, sub := range []string{"http", "stream"} {
			if err := os.MkdirAll(filepath.Join(empty, sub), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(empty, sub, "ngm.conf"), []byte("# NGM: no routes deployed yet\n"), 0o644); err != nil {
				return nil, err
			}
		}
	}
	if _, err := os.Lstat(o.L.current()); err != nil {
		if err := os.Symlink(filepath.Join("gen", EmptyGen), o.L.current()); err != nil {
			return nil, err
		}
	}
	created := []string{}
	hooks := map[string]string{o.L.httpHook(): hookMarker + "\ninclude " + filepath.ToSlash(filepath.Join(o.L.current(), "http", "*.conf")) + ";\n"}
	if withStream {
		hooks[o.L.streamHook()] = hookMarker + "\nstream {\n    include " + filepath.ToSlash(filepath.Join(o.L.current(), "stream", "*.conf")) + ";\n}\n"
	}
	for p, content := range hooks {
		exists, owned := hookOwned(p)
		if exists && !owned {
			return nil, fmt.Errorf("%s exists and is not owned by NGM; refusing to overwrite", p)
		}
		if !exists {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return nil, err
			}
			if err := writeExclusive(p, []byte(content), 0o644); err != nil {
				return nil, err
			}
			created = append(created, p)
		}
	}
	if len(created) > 0 {
		if out, err := o.test(ctx); err != nil {
			for _, p := range created {
				_ = os.Remove(p)
			}
			return nil, &ipc.Error{Code: "nginx_test_failed", Message: "include hooks rejected by nginx -t; hooks removed: " + out}
		}
	}
	cur, _ := o.currentGen()
	return map[string]any{"hooks_created": created, "current": cur}, nil
}

func (o *NginxOps) test(ctx context.Context) (string, error) {
	_, se, err := o.Run.Run(ctx, "nginx", "-t")
	out := strings.TrimSpace(string(se))
	if len(out) > 4000 {
		out = out[len(out)-4000:]
	}
	return out, err
}

func (o *NginxOps) currentGen() (string, error) {
	t, err := os.Readlink(o.L.current())
	if err != nil {
		return "", err
	}
	return filepath.Base(t), nil
}

// StageArgs carries a generation.
type StageArgs struct {
	fencedArgs
	GenID string            `json:"gen_id"`
	Files map[string]string `json:"files"`
	Keys  map[string]string `json:"keys"` // certificate id → PEM private key
}

// Stage writes an immutable generation directory and deploys keys.
func (o *NginxOps) Stage(ctx context.Context, a StageArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !genIDRe.MatchString(a.GenID) {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid generation id"}
	}
	total := 0
	for rel, c := range a.Files {
		if !stageRel.MatchString(rel) || len(c) > maxFile {
			return nil, &ipc.Error{Code: "bad_args", Message: "file path not allowed or too large: " + rel}
		}
		total += len(c)
	}
	for id, k := range a.Keys {
		if !genIDRe.MatchString(id) || len(k) > 16<<10 || !strings.Contains(k, "PRIVATE KEY") {
			return nil, &ipc.Error{Code: "bad_args", Message: "invalid key entry"}
		}
		total += len(k)
	}
	if total > maxTotal {
		return nil, &ipc.Error{Code: "bad_args", Message: "generation too large"}
	}
	if err := notSymlinkDir(o.L.gens()); err != nil {
		return nil, err
	}
	final := filepath.Join(o.L.gens(), a.GenID)
	if _, err := os.Lstat(final); err == nil {
		return nil, &ipc.Error{Code: "exists", Message: "generation already staged (generations are immutable)"}
	}
	tmp := final + ".staging"
	_ = os.RemoveAll(tmp)
	manifest := map[string]string{}
	names := make([]string, 0, len(a.Files))
	for n := range a.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, rel := range names {
		p := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := writeExclusive(p, []byte(a.Files[rel]), 0o644); err != nil {
			_ = os.RemoveAll(tmp)
			return nil, err
		}
		sum := sha256.Sum256([]byte(a.Files[rel]))
		manifest[rel] = hex.EncodeToString(sum[:])
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := notSymlinkDir(o.L.keys()); err != nil {
		return nil, err
	}
	keySums := map[string]string{}
	for id, k := range a.Keys {
		p := filepath.Join(o.L.keys(), id+".key")
		tk := p + ".tmp"
		_ = os.Remove(tk)
		if err := writeExclusive(tk, []byte(k), 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tk, p); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(k))
		keySums[id] = hex.EncodeToString(sum[:])
	}
	return map[string]any{"gen_id": a.GenID, "manifest": manifest, "key_sha256": keySums}, nil
}

// ActivateArgs switches the active generation.
type ActivateArgs struct {
	fencedArgs
	GenID    string `json:"gen_id"`
	Expected string `json:"expected_current"` // compare-and-swap guard
}

// ActivateResult reports the outcome.
type ActivateResult struct {
	Activated  bool   `json:"activated"`
	Previous   string `json:"previous"`
	Current    string `json:"current"`
	TestOutput string `json:"test_output"`
	Reloaded   string `json:"reloaded"` // reload | start | none
	MainPID    string `json:"main_pid"`
}

func (o *NginxOps) swap(gen string) error {
	tmp := o.L.current() + ".ngm-tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join("gen", gen), tmp); err != nil {
		return err
	}
	return os.Rename(tmp, o.L.current())
}

// Activate points `current` at gen, runs `nginx -t` against the real
// configuration root, and reloads. On test or reload failure the previous
// generation is restored before returning; Nginx keeps serving throughout.
func (o *NginxOps) Activate(ctx context.Context, a ActivateArgs) (*ActivateResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if a.GenID != EmptyGen && !genIDRe.MatchString(a.GenID) {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid generation id"}
	}
	if st, err := os.Lstat(filepath.Join(o.L.gens(), a.GenID)); err != nil || !st.IsDir() {
		return nil, &ipc.Error{Code: "not_staged", Message: "generation is not staged"}
	}
	prev, err := o.currentGen()
	if err != nil {
		return nil, &ipc.Error{Code: "layout", Message: "current generation pointer missing; run layout setup"}
	}
	if a.Expected != "" && prev != a.Expected {
		return nil, &ipc.Error{Code: "current_changed", Message: fmt.Sprintf("active generation is %s, expected %s", prev, a.Expected)}
	}
	res := &ActivateResult{Previous: prev, Current: prev, Reloaded: "none"}
	if err := o.swap(a.GenID); err != nil {
		return nil, err
	}
	out, terr := o.test(ctx)
	res.TestOutput = out
	if terr != nil {
		if err := o.swap(prev); err != nil {
			return res, &ipc.Error{Code: "revert_failed", Message: "nginx -t failed and reverting the pointer failed: " + err.Error()}
		}
		return res, nil
	}
	state, _, _ := o.Run.Run(ctx, "systemctl", "is-active", "nginx.service")
	action := "reload"
	if strings.TrimSpace(string(state)) != "active" {
		action = "start"
	}
	if _, se, err := o.Run.Run(ctx, "systemctl", action, "nginx.service"); err != nil {
		_ = o.swap(prev)
		_, _, rerr := o.Run.Run(ctx, "systemctl", "reload", "nginx.service")
		msg := fmt.Sprintf("systemctl %s failed: %v %s", action, err, strings.TrimSpace(string(se)))
		if rerr != nil {
			msg += "; reload of previous generation also failed"
		}
		return res, &ipc.Error{Code: "reload_failed", Message: msg}
	}
	res.Activated, res.Current, res.Reloaded = true, a.GenID, action
	if pid, _, err := o.Run.Run(ctx, "systemctl", "show", "nginx.service", "--property=MainPID", "--value"); err == nil {
		res.MainPID = strings.TrimSpace(string(pid))
	}
	return res, nil
}

// GCArgs lists generations/keys to keep.
type GCArgs struct {
	fencedArgs
	KeepGens []string `json:"keep_gens"`
	KeepKeys []string `json:"keep_keys"`
}

// GC removes generations and keys not listed (never the current one).
func (o *NginxOps) GC(ctx context.Context, a GCArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cur, _ := o.currentGen()
	keep := map[string]bool{cur: true, EmptyGen: true}
	for _, g := range a.KeepGens {
		keep[g] = true
	}
	removed := []string{}
	es, _ := os.ReadDir(o.L.gens())
	for _, e := range es {
		if !keep[e.Name()] && (genIDRe.MatchString(e.Name()) || strings.HasSuffix(e.Name(), ".staging")) {
			if err := os.RemoveAll(filepath.Join(o.L.gens(), e.Name())); err == nil {
				removed = append(removed, e.Name())
			}
		}
	}
	kk := map[string]bool{}
	for _, k := range a.KeepKeys {
		kk[k] = true
	}
	ks, _ := os.ReadDir(o.L.keys())
	for _, e := range ks {
		id := strings.TrimSuffix(e.Name(), ".key")
		if !kk[id] && genIDRe.MatchString(id) {
			_ = os.Remove(filepath.Join(o.L.keys(), e.Name()))
		}
	}
	return map[string]any{"removed": removed}, nil
}

// State reports the current pointer and staged generations.
func (o *NginxOps) State() (map[string]any, error) {
	cur, err := o.currentGen()
	if err != nil {
		cur = ""
	}
	gens := []string{}
	es, _ := os.ReadDir(o.L.gens())
	for _, e := range es {
		gens = append(gens, e.Name())
	}
	hooks := map[string]bool{}
	for _, p := range []string{o.L.httpHook(), o.L.streamHook()} {
		_, owned := hookOwned(p)
		hooks[filepath.Base(p)] = owned
	}
	ds, _ := os.Lstat(filepath.Join(o.L.Root, "sites-enabled", "default"))
	return map[string]any{"current": cur, "generations": gens, "hooks": hooks, "distro_default_site_enabled": ds != nil}, nil
}

// DisableDefaultSite removes the distribution's sites-enabled/default
// symlink (it binds :80 default_server and would conflict with NGM HTTP
// listeners). Only the pristine distro symlink is touched; a record is kept
// so uninstall can restore it.
func (o *NginxOps) DisableDefaultSite(ctx context.Context) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	link := filepath.Join(o.L.Root, "sites-enabled", "default")
	st, err := os.Lstat(link)
	if err != nil {
		return map[string]any{"changed": false}, nil
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return nil, &ipc.Error{Code: "not_distro_default", Message: "sites-enabled/default is not the distribution symlink; refusing to touch it"}
	}
	t, _ := os.Readlink(link)
	if t != "/etc/nginx/sites-available/default" && t != "../sites-available/default" && t != filepath.Join(o.L.Root, "sites-available", "default") {
		return nil, &ipc.Error{Code: "not_distro_default", Message: "sites-enabled/default points elsewhere; refusing to touch it"}
	}
	if err := os.WriteFile(filepath.Join(o.L.ngm(), ".default-site-disabled"), []byte(t+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.Remove(link); err != nil {
		return nil, err
	}
	if out, err := o.test(ctx); err != nil {
		_ = os.Symlink(t, link)
		return nil, &ipc.Error{Code: "nginx_test_failed", Message: out}
	}
	if _, se, err := o.Run.Run(ctx, "systemctl", "reload", "nginx.service"); err != nil {
		return nil, &ipc.Error{Code: "reload_failed", Message: string(se)}
	}
	return map[string]any{"changed": true}, nil
}

// decode strictly decodes args.
func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return &ipc.Error{Code: "bad_args", Message: "arguments required"}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &ipc.Error{Code: "bad_args", Message: "malformed arguments"}
	}
	return nil
}
