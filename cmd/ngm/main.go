// Command ngm is the single NGM binary. Roles run as separate systemd units
// under separate accounts (DECISIONS ADR-001); CLI subcommands are for
// operators on the host.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ngm-gateway/ngm/internal/app"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/installer"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/lifecycle"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

const usage = `ngm — Nginx Gateway Manager

Roles (run by systemd):
  ngm api              REST API + Control Center on loopback (default 127.0.0.1:9999)
  ngm ops              operations worker (deployments, firewall, backups, observation)
  ngm helper           privileged allowlisted helper (root, Unix socket)
  ngm monitor          active backend health checks
  ngm log-indexer      log collection into the rebuildable search index

Operator commands (run as root on the gateway):
  ngm install [--adopt-existing-nginx]   install or upgrade this binary (idempotent)
  ngm doctor           read-only diagnostics (preflight, database, vault, audit, helper)
  ngm status           service and data-plane status from recorded evidence
  ngm migrate          apply pending database migrations (fail closed on tamper/newer schema)
  ngm db check         SQLite integrity and foreign-key checks
  ngm audit verify     verify the audit hash chain
  ngm admin reset USER          set a new random password, clear MFA, revoke sessions
  ngm admin bootstrap-token     issue a new first-run token (only while no user exists)
  ngm admin set-origin URL      publish the Control Center through Nginx at this HTTPS origin (--clear)
  ngm backup set-passphrase     set the recovery passphrase (stdin or NGM_BACKUP_PASSPHRASE)
  ngm backup create | list      write a verified encrypted archive / list archives
  ngm restore [--preview] [--apply] FILE   supervised restore (passphrase via stdin/env)
  ngm vault status | rotate | retire N     KEK status, crash-resumable rotation, retirement
  ngm logs reindex     rebuild the log search index from the source log files
  ngm config test      nginx -t over the full configuration + active NGM generation
  ngm rollback [GEN]   Safe Apply rollback to the previous (or given) known-good generation
  ngm update check|apply --from DIR [--yes] | rollback [--yes] | status
                       signed, administrator-approved updates with automatic rollback
  ngm nginx upgrade [--yes] | reconcile   coordinated Nginx APT upgrade / accept external change
  ngm repair           re-verify the signed release and re-apply install state
  ngm uninstall --keep-data|--purge [--yes] [--confirm "purge HOST"]   plan first, then remove
  ngm release keygen|sign|verify          publisher tooling (build host)
  ngm version          print build information

Global flags:
  --config PATH        configuration file (default /etc/ngm/ngm.json, env NGM_CONFIG)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ngm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", envOr("NGM_CONFIG", config.DefaultPath), "configuration file")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	log := slog.New(slog.NewJSONHandler(appLogWriter(rest[0], stderr), &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch rest[0] {
	case "version":
		b := buildinfo.Get()
		fmt.Fprintf(stdout, "ngm %s (commit %s, built %s, %s/%s, %s, channel %s)\n", b.Version, b.Commit, b.Date, b.OS, b.Arch, b.GoVersion, b.Channel)
		return 0
	case "help", "-h", "--help":
		fs.Usage()
		return 0
	case "install":
		return cmdInstall(ctx, rest[1:], stdout, stderr)
	case "release":
		if err := cmdRelease(rest[1:], stdout); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	fail := func(err error) int {
		if err == nil {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	switch rest[0] {
	case "api":
		if err := app.RunAPI(ctx, cfg, log); err != nil {
			log.Error("api", "err", err.Error())
			return 1
		}
		return 0
	case "ops":
		if err := app.RunOps(ctx, cfg, log); err != nil {
			log.Error("ops", "err", err.Error())
			return 1
		}
		return 0
	case "helper":
		if err := app.RunHelper(ctx, cfg, log); err != nil {
			log.Error("helper", "err", err.Error())
			return 1
		}
		return 0
	case "monitor":
		if err := app.RunMonitor(ctx, cfg, log); err != nil {
			log.Error("monitor", "err", err.Error())
			return 1
		}
		return 0
	case "log-indexer":
		if err := app.RunLogIndexer(ctx, cfg, log); err != nil {
			log.Error("log-indexer", "err", err.Error())
			return 1
		}
		return 0
	case "migrate":
		return fail(withDB(cfg, func(db *store.DB) error {
			applied, err := db.Migrate(ctx)
			if err != nil {
				return err
			}
			v, _ := db.SchemaVersion(ctx)
			fmt.Fprintf(stdout, "applied %d migration(s); schema version %d\n", len(applied), v)
			return nil
		}))
	case "db":
		if len(rest) < 2 || rest[1] != "check" {
			fmt.Fprintln(stderr, "usage: ngm db check")
			return 2
		}
		return fail(withDB(cfg, func(db *store.DB) error {
			if err := db.IntegrityCheck(ctx); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "database integrity: ok")
			return nil
		}))
	case "audit":
		if len(rest) < 2 || rest[1] != "verify" {
			fmt.Fprintln(stderr, "usage: ngm audit verify")
			return 2
		}
		return fail(withDB(cfg, func(db *store.DB) error {
			r, err := audit.New(db).Verify(ctx)
			if err != nil {
				return err
			}
			if !r.OK {
				return fmt.Errorf("audit chain BROKEN at seq %d: %s (%d events)", r.BrokenAt, r.Reason, r.Events)
			}
			fmt.Fprintf(stdout, "audit chain ok (%d events)\n", r.Events)
			return nil
		}))
	case "fw-revert":
		// Invoked by the firewall dead-man watchdog (transient systemd timer, root).
		if len(rest) != 2 {
			fmt.Fprintln(stderr, "usage: ngm fw-revert PLAN_ID")
			return 2
		}
		res, err := app.NewFirewall(cfg).Revert(ctx, rest[1])
		if err != nil {
			return fail(err)
		}
		log.Warn("firewall watchdog: change reverted (not confirmed in time)", "plan", rest[1], "result", res)
		return 0
	case "admin":
		if len(rest) > 1 && rest[1] == "set-origin" {
			return fail(cmdSetOrigin(ctx, *cfgPath, rest[2:], stdout))
		}
		return fail(cmdAdmin(ctx, cfg, rest[1:], stdout))
	case "backup":
		return fail(cmdBackup(ctx, cfg, rest[1:], os.Stdin, stdout))
	case "restore":
		return fail(cmdRestore(ctx, cfg, rest[1:], os.Stdin, stdout))
	case "vault":
		return fail(cmdVault(ctx, cfg, rest[1:], stdout))
	case "update":
		return fail(cmdUpdate(ctx, cfg, rest[1:], stdout))
	case "repair":
		if err := requireRoot(); err != nil {
			return fail(err)
		}
		return fail(lifecycle.Repair(ctx, cfg, printer(stdout)))
	case "uninstall":
		return fail(cmdUninstall(ctx, cfg, rest[1:], stdout))
	case "nginx":
		return fail(cmdNginx(ctx, cfg, rest[1:], stdout))
	case "config":
		return fail(cmdConfigTest(ctx, cfg, rest[1:], stdout))
	case "rollback":
		return fail(cmdRollback(ctx, cfg, rest[1:], stdout))
	case "logs":
		return fail(cmdLogs(ctx, cfg, rest[1:], stdout))
	case "status":
		return fail(cmdStatus(ctx, cfg, stdout))
	case "doctor":
		return cmdDoctor(ctx, cfg, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", rest[0])
		fs.Usage()
		return 2
	}
}

func withDB(cfg config.Config, fn func(*store.DB) error) error {
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

func cmdInstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adopt := fs.Bool("adopt-existing-nginx", false, "install alongside a customised Ubuntu nginx without modifying it")
	relDir := fs.String("release-dir", "", "directory with the signed manifest of this binary (verified before anything changes)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := installer.Install(ctx, installer.Options{AdoptExistingNginx: *adopt, ReleaseDir: *relDir}, func(f string, a ...any) { fmt.Fprintf(stdout, f+"\n", a...) })
	if err != nil {
		fmt.Fprintln(stderr, "install failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "\nNGM %s installed.\n", res.Version)
	if res.BootstrapToken != "" {
		fmt.Fprintf(stdout, `
First-run setup (local access only):
  1. From your workstation:  ssh -L 9999:127.0.0.1:9999 root@<this-server>
  2. Open:                   http://127.0.0.1:9999/setup
  3. Bootstrap token:        %s
     (single use; regenerate with `+"`ngm admin bootstrap-token`"+` while no user exists)
`, res.BootstrapToken)
	}
	return 0
}

func cmdAdmin(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ngm admin reset USER | ngm admin bootstrap-token")
	}
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "bootstrap-token":
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("setup already completed; use `ngm admin reset USER` to recover access")
		}
		tok, err := installer.NewBootstrapToken(ctx, db)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "bootstrap token: %s\n", tok)
		return nil
	case "reset":
		if len(args) != 2 {
			return errors.New("usage: ngm admin reset USER")
		}
		v, err := app.OpenVault(ctx, cfg, db)
		if err != nil {
			return err
		}
		pw := randomPassword()
		if err := app.NewAuth(db, v).AdminReset(ctx, args[1], pw); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "user %s reset.\nnew password: %s\nMFA cleared: enrol a new authenticator at next sign-in. All sessions revoked.\n", args[1], pw)
		return nil
	}
	return fmt.Errorf("unknown admin command %q", args[0])
}

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b) + "-Aa9"
}

func cmdStatus(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	now := time.Now()
	fmt.Fprintf(stdout, "NGM %s\n\n", buildinfo.Version)
	rows, err := db.QueryContext(ctx, "SELECT service,status,detail,observed_at FROM service_heartbeats ORDER BY service")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Services (from heartbeats):")
	for rows.Next() {
		var s, st, d, at string
		rows.Scan(&s, &st, &d, &at)
		t, _ := store.ParseTime(at)
		if now.Sub(t) > 90*time.Second {
			st = "unknown (stale)"
		}
		fmt.Fprintf(stdout, "  %-12s %-16s %s  (%s ago)\n", s, st, d, now.Sub(t).Round(time.Second))
	}
	rows.Close()
	var n observe.Nginx
	if at, err := observe.Latest(ctx, db, observe.KindNginx, &n); err == nil {
		fmt.Fprintf(stdout, "\nNginx (observed %s ago): installed=%v version=%s origin=%s service=%s stream=%v ssl_preread=%v listeners=%v\n",
			now.Sub(at).Round(time.Second), n.Installed, n.Version, n.PackageOrigin, n.ServiceState, n.StreamModule, n.SSLPreread, n.Listeners)
	} else {
		fmt.Fprintln(stdout, "\nNginx: unknown (no observation)")
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + cfg.API.Listen + "/api/v1/system/health")
	if err != nil {
		fmt.Fprintf(stdout, "\nAPI: unreachable on %s (%v)\n", cfg.API.Listen, err)
		return nil
	}
	defer resp.Body.Close()
	var h struct {
		Status string `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&h)
	fmt.Fprintf(stdout, "\nAPI: %s on %s (overall %s)\n", resp.Status, cfg.API.Listen, h.Status)
	return nil
}

func cmdDoctor(ctx context.Context, cfg config.Config, stdout io.Writer) int {
	bad := false
	line := func(status, id, detail string) {
		if status == "fail" {
			bad = true
		}
		fmt.Fprintf(stdout, "[%s] %-14s %s\n", strings.ToUpper(status), id, detail)
	}
	rep := installer.Preflight(ctx, installer.Options{APIListen: cfg.API.Listen})
	for _, c := range rep.Checks {
		if c.ID == "api_port" || c.ID == "nginx" && rep.NginxState == "ngm-managed" {
			continue
		}
		line(c.Status, c.ID, c.Detail)
	}
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		line("fail", "database", err.Error())
		return 1
	}
	defer db.Close()
	if err := db.IntegrityCheck(ctx); err != nil {
		line("fail", "database", err.Error())
	} else {
		line("pass", "database", "integrity ok")
	}
	if _, err := app.OpenVault(ctx, cfg, db); err != nil {
		line("fail", "vault", err.Error())
	} else {
		line("pass", "vault", "keys present and verified")
	}
	if bad := keyPermProblems(cfg.Paths.KeysDir); len(bad) > 0 {
		line("fail", "vault_perms", "services cannot read: "+strings.Join(bad, ", ")+" (fix: chown root:ngm-vault, chmod 0440)")
	} else {
		line("pass", "vault_perms", "key files root:ngm-vault 0440")
	}
	if r, err := audit.New(db).Verify(ctx); err != nil || !r.OK {
		line("fail", "audit", fmt.Sprintf("chain broken: %+v %v", r, err))
	} else {
		line("pass", "audit", fmt.Sprintf("chain ok (%d events)", r.Events))
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ping map[string]any
	if err := ipc.Call(cctx, app.HelperSocket(cfg), ipc.Request{Op: "ping"}, &ping); err != nil {
		line("fail", "helper", err.Error())
	} else {
		line("pass", "helper", fmt.Sprintf("version %v", ping["version"]))
	}
	if bad {
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// appLogWriter also writes the structured log of the api, ops and monitor
// roles to /var/log/ngm/app/<role>.jsonl (read by the log indexer) when that
// directory is writable.
func appLogWriter(role string, stderr io.Writer) io.Writer {
	switch role {
	case "api", "ops", "monitor":
	default:
		return stderr
	}
	f, err := os.OpenFile(filepath.Join("/var/log/ngm/app", role+".jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return stderr
	}
	return io.MultiWriter(stderr, f)
}
