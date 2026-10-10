package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/app"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/deployspec"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/lifecycle"
	"github.com/ngm-gateway/ngm/internal/release"
	"github.com/ngm-gateway/ngm/internal/store"
)

func printer(w io.Writer) lifecycle.Logger {
	return func(f string, a ...any) { fmt.Fprintf(w, f+"\n", a...) }
}

// cmdRelease: publisher-side tooling (runs on the build host, no config).
func cmdRelease(args []string, stdout io.Writer) error {
	const u = "usage: ngm release keygen --priv FILE --pub FILE | sign --key FILE --dir DIR --version V --channel C [--commit C] [--db-schema N] | verify --dir DIR"
	if len(args) == 0 {
		return errors.New(u)
	}
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	priv := fs.String("priv", "", "private key output (PEM, mode 0600)")
	pub := fs.String("pub", "", "public key output (PEM)")
	key := fs.String("key", "", "publisher private key (PEM)")
	dir := fs.String("dir", "", "release directory")
	ver := fs.String("version", "", "release version")
	ch := fs.String("channel", "development", "stable | beta | development")
	commit := fs.String("commit", "unknown", "source commit")
	dbs := fs.Int("db-schema", 0, "number of shipped migrations (default: this build's)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		if *priv == "" || *pub == "" {
			return errors.New(u)
		}
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		sp, pp, err := release.MarshalKeys(pk, sk)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*priv, sp, 0o600); err != nil {
			return err
		}
		return os.WriteFile(*pub, pp, 0o644)
	case "sign":
		if *key == "" || *dir == "" || *ver == "" {
			return errors.New(u)
		}
		b, err := os.ReadFile(*key)
		if err != nil {
			return err
		}
		sk, err := release.ParsePrivateKey(b)
		if err != nil {
			return err
		}
		if *dbs == 0 {
			ms, _ := store.Migrations()
			*dbs = len(ms)
		}
		id := strings.TrimSuffix(filepath.Base(*key), filepath.Ext(*key))
		raw, err := release.Build(*dir, release.Manifest{Version: *ver, Channel: *ch, Commit: *commit, Date: time.Now().UTC().Truncate(time.Second),
			KeyID: id, Supported: []string{"ubuntu-22.04", "ubuntu-24.04"}, DBSchema: *dbs, APIVersion: buildinfo.APIVersion,
			Requires: release.Requires{NginxModules: []string{"stream", "ssl_preread", "http_ssl", "http_v2"}, Packages: []string{"nginx"}}})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*dir, "manifest.json"), raw, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*dir, "manifest.sig"), release.Sign(sk, raw), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "signed %s %s (%s) with %s\n", *ver, *ch, *dir, id)
		return nil
	case "verify":
		keys, err := release.Trusted()
		if err != nil {
			return err
		}
		m, _, err := release.LoadDir(*dir, keys)
		if err != nil {
			return err
		}
		for _, a := range m.Artifacts {
			p := filepath.Join(*dir, a.File)
			if _, err := os.Stat(p); err != nil && a.Arch == runtime.GOARCH {
				p = filepath.Join(*dir, "ngm") // installed release layout
			} else if err != nil {
				continue
			}
			if err := release.CheckFile(p, &a); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "ok  %s %d bytes sha256 %s\n", a.File, a.Size, a.SHA256)
		}
		fmt.Fprintf(stdout, "manifest %s %s signed by pinned key %s\n", m.Version, m.Channel, m.KeyID)
		return nil
	}
	return errors.New(u)
}

func cmdUpdate(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	const u = "usage: ngm update check --from DIR | apply --from DIR [--yes] | rollback [--yes] | status"
	if len(args) == 0 {
		return errors.New(u)
	}
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	from := fs.String("from", "", "verified release directory")
	yes := fs.Bool("yes", false, "administrator approval")
	reinstall := fs.Bool("reinstall", false, "allow re-installing the same development version")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	logf := printer(stdout)
	switch args[0] {
	case "status":
		st, err := release.LoadState(cfg.Paths.StateDir)
		if err != nil {
			return err
		}
		cur, _ := filepath.EvalSymlinks(cfg.Paths.Current)
		fmt.Fprintf(stdout, "running %s (%s channel); current → %s\n", buildinfo.Version, buildinfo.Channel, cur)
		if es, err := os.ReadDir(cfg.Paths.Releases); err == nil {
			for _, e := range es {
				signed := "unsigned"
				if _, err := os.Stat(filepath.Join(cfg.Paths.Releases, e.Name(), "manifest.sig")); err == nil {
					signed = "signed"
				}
				fmt.Fprintf(stdout, "  release %-20s %s\n", e.Name(), signed)
			}
		}
		if st != nil {
			fmt.Fprintf(stdout, "last update: %s → %s %s at %s %s\n", st.From, st.To, st.Phase, st.StartedAt.Format(time.RFC3339), st.Error)
		}
		return nil
	case "check":
		if *from == "" {
			return errors.New(u)
		}
		p, err := lifecycle.Check(ctx, cfg, *from, *reinstall)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "verified %s %s signed by %s; schema %d → %d; encrypted backup configured: %v; OS supported: %v\nrun `ngm update apply --from %s --yes` to install\n",
			p.Manifest.Version, p.Manifest.Channel, p.Manifest.KeyID, p.FromDB, p.Manifest.DBSchema, p.Backup, p.Supported, *from)
		return nil
	case "apply":
		if err := requireRoot(); err != nil {
			return err
		}
		if *from == "" {
			return errors.New(u)
		}
		return lifecycle.Apply(ctx, cfg, lifecycle.UpdateOptions{From: *from, Yes: *yes, Reinstall: *reinstall, Actor: "cli:root"}, logf)
	case "rollback":
		if err := requireRoot(); err != nil {
			return err
		}
		st, err := release.LoadState(cfg.Paths.StateDir)
		if err != nil {
			return err
		}
		if st == nil || (st.Phase != "succeeded" && st.Phase != "failed") || st.To != buildinfo.Version {
			return errors.New("no update to roll back from this version")
		}
		logf("rollback %s → %s; schema %d → %d", st.To, st.From, st.ToSchema, st.FromSchema)
		if st.ToSchema != st.FromSchema {
			logf("the database will be restored from %s: changes made since the update are lost", st.Snapshot)
		}
		if !*yes {
			return lifecycle.ErrNeedsApproval
		}
		return lifecycle.Rollback(ctx, cfg, st, logf)
	}
	return errors.New(u)
}

func cmdUninstall(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	keep := fs.Bool("keep-data", false, "remove the program; keep configuration, data, logs and backups")
	purge := fs.Bool("purge", false, "also delete all NGM data, NGM firewall rules and accounts")
	yes := fs.Bool("yes", false, "execute (default: print the plan only)")
	confirm := fs.String("confirm", "", `for --purge: the exact text "purge <hostname>"`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keep == *purge {
		return errors.New("choose exactly one of --keep-data or --purge")
	}
	mode := lifecycle.KeepData
	if *purge {
		mode = lifecycle.Purge
	}
	un := &lifecycle.Uninstaller{Root: "/", Run: lifecycle.ExecRunner{}, DBPath: cfg.DBPath()}
	fmt.Fprintf(stdout, "Uninstall plan (%s):\n", mode)
	for _, a := range un.Plan(ctx, mode) {
		fmt.Fprintf(stdout, "  %-8s %s  — %s\n", a.Kind, a.Target, a.Why)
	}
	fmt.Fprintln(stdout, "Third-party Nginx files, non-NGM UFW rules and Nginx itself are never touched.")
	if mode == lifecycle.KeepData || !*yes {
		fmt.Fprintln(stdout, "Advice: run `ngm backup create` and copy /var/lib/ngm/backups off this server first.")
	}
	if !*yes {
		return lifecycle.ErrNeedsApproval
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if mode == lifecycle.Purge {
		host, _ := os.Hostname()
		if *confirm != "purge "+host {
			return fmt.Errorf(`purge needs --confirm "purge %s"`, host)
		}
	}
	return un.Execute(ctx, mode, printer(stdout))
}

func cmdNginx(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	const u = "usage: ngm nginx upgrade [--yes] | reconcile"
	if len(args) == 0 {
		return errors.New(u)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("nginx", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "administrator approval")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "upgrade":
		return lifecycle.NginxUpgrade(ctx, cfg, *yes, printer(stdout))
	case "reconcile":
		return lifecycle.NginxReconcile(ctx, cfg, "ngm nginx reconcile", printer(stdout))
	}
	return errors.New(u)
}

// cmdConfigTest runs nginx -t over the whole configuration (NGM hook included)
// and reports the active NGM generation.
func cmdConfigTest(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "test" {
		return errors.New("usage: ngm config test")
	}
	out, err := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput()
	fmt.Fprint(stdout, string(out))
	cur, _ := os.Readlink(filepath.Join(cfg.Paths.NginxOwned, "current"))
	fmt.Fprintf(stdout, "active NGM generation: %s\n", filepath.Base(cur))
	if err != nil {
		return errors.New("nginx configuration test failed")
	}
	return nil
}

// cmdRollback queues a Safe Apply rollback job (executed by ngm-ops) to the
// given or the most recent superseded generation and waits for its outcome.
func cmdRollback(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	gen := ""
	if len(args) > 0 {
		gen = args[0]
	} else if err := db.QueryRowContext(ctx, "SELECT id FROM config_generations WHERE status='superseded' ORDER BY created_at DESC LIMIT 1").Scan(&gen); err != nil {
		return errors.New("no previously active generation to roll back to")
	}
	var n int
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM config_generations WHERE id=? AND status='superseded'", gen).Scan(&n)
	if n == 0 {
		return fmt.Errorf("%s is not a previously active (superseded) generation", gen)
	}
	j, _, err := jobs.NewJournal(db).Submit(ctx, jobs.SubmitRequest{Kind: deployspec.KindRollback, ActorID: "cli:root",
		LockSet: []string{"gateway-config", "certificate"}, Payload: deployspec.RollbackPayload{GenerationID: gen}})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "rollback job %s queued (target generation %s); waiting for ngm-ops…\n", j.ID, gen)
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		var state, errJSON string
		_ = db.QueryRowContext(ctx, "SELECT state, COALESCE(error_json,'') FROM jobs WHERE id=?", j.ID).Scan(&state, &errJSON)
		switch state {
		case "Succeeded":
			fmt.Fprintln(stdout, "rollback succeeded")
			return nil
		case "Failed", "RolledBack", "Blocked", "RecoveryRequired", "Cancelled":
			return fmt.Errorf("rollback ended %s %s", state, errJSON)
		}
		time.Sleep(time.Second)
	}
	return errors.New("timed out waiting for ngm-ops; check `ngm status`")
}

// cmdSetOrigin sets (or clears) the HTTPS management origin used when the
// Control Center is published through Nginx, then restarts ngm-api.
func cmdSetOrigin(ctx context.Context, cfgPath string, args []string, stdout io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: ngm admin set-origin https://host[:port] [/base-path] | --clear")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	apiSec, _ := raw["api"].(map[string]any)
	if apiSec == nil {
		apiSec = map[string]any{}
	}
	if args[0] == "--clear" {
		delete(apiSec, "public_origin")
		delete(apiSec, "public_path")
	} else {
		apiSec["public_origin"] = strings.TrimRight(args[0], "/")
		if len(args) == 2 {
			p := "/" + strings.Trim(args[1], "/")
			if err := config.ValidatePublicPath(p); err != nil {
				return fmt.Errorf("base path: %w", err)
			}
			apiSec["public_path"] = p
		} else {
			delete(apiSec, "public_path")
		}
	}
	raw["api"] = apiSec
	out, _ := json.MarshalIndent(raw, "", "  ")
	tmp := cfgPath + ".tmp"
	fi, err := os.Stat(cfgPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, append(out, '\n'), fi.Mode().Perm()); err != nil {
		return err
	}
	if _, err := config.Load(tmp); err != nil { // validates the origin (https, host only)
		os.Remove(tmp)
		return err
	}
	chownLike(tmp, fi)
	if err := os.Rename(tmp, cfgPath); err != nil {
		return err
	}
	if o, err := exec.CommandContext(ctx, "systemctl", "restart", "ngm-api.service", "ngm-ops.service").CombinedOutput(); err != nil {
		return fmt.Errorf("restart ngm-api: %s", strings.TrimSpace(string(o)))
	}
	fmt.Fprintf(stdout, "management origin set to %q; ngm-api and ngm-ops restarted. Route that host to 127.0.0.1:9999 through an HTTPS listener.\n", apiSec["public_origin"])
	return nil
}
