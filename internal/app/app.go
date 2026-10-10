// Package app wires NGM roles (api, ops, helper) from configuration.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/ngm-gateway/ngm/internal/alerts"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/certauto"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/deploy"
	"github.com/ngm-gateway/ngm/internal/dnsq"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/httpapi"
	"github.com/ngm-gateway/ngm/internal/ipc"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/monitor"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/perf"
	"github.com/ngm-gateway/ngm/internal/sse"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
	"github.com/ngm-gateway/ngm/web"
)

// HelperSocket is the helper's Unix socket path.
func HelperSocket(cfg config.Config) string { return filepath.Join(cfg.Paths.RunDir, "helper.sock") }

// OpenDB opens the database and refuses to proceed on an unmigrated, newer or
// tampered schema (fail closed). Migrations are an explicit operator step.
func OpenDB(ctx context.Context, cfg config.Config) (*store.DB, error) {
	db, err := store.Open(cfg.DBPath(), store.Options{})
	if err != nil {
		return nil, err
	}
	if err := RequireCurrentSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// RequireCurrentSchema verifies the schema exactly matches this binary.
func RequireCurrentSchema(ctx context.Context, db *store.DB) error {
	ms, err := store.Migrations()
	if err != nil {
		return err
	}
	v, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	want := ms[len(ms)-1].Version
	if v != want {
		return fmt.Errorf("database schema version %d, binary expects %d; run `ngm migrate`", v, want)
	}
	return nil
}

// OpenVault loads KEKs from the keys directory and verifies them against the database.
func OpenVault(ctx context.Context, cfg config.Config, db *store.DB) (*vault.Vault, error) {
	kr, err := vault.LoadDir(cfg.Paths.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("load vault keys: %w", err)
	}
	v := vault.New(db, kr)
	if err := v.Verify(ctx); err != nil {
		return nil, fmt.Errorf("vault key verification: %w", err)
	}
	return v, nil
}

// NewAuth builds the identity service with production policy.
func NewAuth(db *store.DB, v *vault.Vault) *auth.Service {
	return auth.NewService(db, v, audit.New(db), auth.DefaultPolicy())
}

// RunAPI serves the REST API and Control Center on the loopback listener.
func RunAPI(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	v, err := OpenVault(ctx, cfg, db)
	if err != nil {
		return err
	}
	as := NewAuth(db, v)
	if err := as.EnsureBuiltins(ctx); err != nil {
		return fmt.Errorf("built-in roles: %w", err)
	}
	broker := sse.NewBroker(db)
	gw := gwstore.New(db, v, audit.New(db))
	gw.OnChange = func(ctx context.Context, kind, id string) {
		_, _ = broker.Publish(ctx, "gateway.changed", "global", map[string]string{"kind": kind, "id": id})
	}
	srv := httpapi.New(httpapi.Deps{
		Log: log, DB: db, Jobs: jobs.NewJournal(db), Locks: locks.NewManager(db), Broker: broker,
		Audit: audit.New(db), Config: cfg, Auth: as, Vault: v, GW: gw, UI: web.Dist(),
	})
	if err := config.ValidateLoopbackListen(cfg.API.Listen); err != nil {
		return fmt.Errorf("refusing to bind: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	log.Info("ngm api listening", "addr", ln.Addr().String(), "version", buildinfo.Version)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
		log.Info("ngm api stopped")
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// RunHelper serves the privileged helper socket. Allowed peers: root and the
// ngm-ops service account.
func RunHelper(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if runtime.GOOS != "linux" {
		return helper.ErrNotLinux
	}
	if os.Geteuid() != 0 {
		return errors.New("ngm helper must run as root")
	}
	allowed := map[uint32][]string{0: {"*"}}
	if u, err := user.Lookup("ngm-ops"); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		allowed[uint32(uid)] = helper.Ops
	} else {
		log.Warn("ngm-ops account not found; only root may call the helper")
	}
	gid := -1
	if g, err := user.LookupGroup("ngm-helper"); err == nil {
		n, _ := strconv.Atoi(g.Gid)
		gid = n
	}
	if err := os.MkdirAll(cfg.Paths.RunDir, 0o750); err != nil {
		return err
	}
	sock := HelperSocket(cfg)
	if st, err := os.Lstat(sock); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket; refusing to remove it", sock)
		}
		_ = os.Remove(sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Chown(sock, 0, gid); err != nil {
		ln.Close()
		return err
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return err
	}
	h := &helper.Helper{Policy: helper.Policy{Allowed: allowed}, Run: helper.ExecRunner{},
		Nginx: &helper.NginxOps{L: helper.NginxLayout{Root: "/etc/nginx", LogDir: filepath.Join(cfg.Paths.LogDir, "nginx")}, Run: helper.ExecRunner{}, Fence: helper.DBFenceChecker(cfg.DBPath()), WebsitesRoot: cfg.Paths.Websites},
		FW:    NewFirewall(cfg),
		Log:   func(msg string, kv ...any) { log.Warn(msg, kv...) }}
	log.Info("ngm helper listening", "socket", sock, "version", buildinfo.Version)
	srv := &ipc.Server{Handler: h.Handle}
	return srv.Serve(ctx, ln)
}

// RunOps runs the operations worker. Phase 2 scope: runtime observation of the
// data plane via the helper, service heartbeats and session housekeeping.
// Deployment jobs arrive in Phase 3.
func RunOps(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	sock := HelperSocket(cfg)
	v, err := OpenVault(ctx, cfg, db)
	if err != nil {
		return err
	}
	al := audit.New(db)
	broker := sse.NewBroker(db)
	host, _ := os.Hostname()
	coord := &deploy.Coordinator{DB: db, Jobs: jobs.NewJournal(db), Locks: locks.NewManager(db), GW: gwstore.New(db, v, al), Audit: al, Broker: broker,
		Helper: deploy.SocketHelper{Path: sock}, Prober: deploy.NetProber{}, Log: log, Worker: fmt.Sprintf("ngm-ops@%s/%d", host, os.Getpid()), APIListen: cfg.API.Listen, PublicOrigin: cfg.API.PublicOrigin, PublicPath: cfg.API.PublicPath,
		Backups: &backup.Service{DB: db, Vault: v, Dir: cfg.Paths.Backups}, KeysDir: cfg.Paths.KeysDir, Hostname: host,
		ACME: &certauto.Issuer{DB: db, Vault: v, NewClient: certauto.DefaultClient, Check: certauto.HTTPSelfCheck}, Vault: v, WebsitesRoot: cfg.Paths.Websites}
	log.Info("ngm ops started", "version", buildinfo.Version)
	// Resolve deployments interrupted by a previous crash before taking new work.
	if err := coord.Reconcile(ctx); err != nil {
		log.Error("startup reconciliation", "err", err)
	}
	// Jobs run in their own goroutine so that long steps (e.g. waiting for a
	// firewall confirmation) never stall heartbeats or observations.
	// Several workers: jobs of different lock families (gateway, firewall,
	// certificate, backup, website) proceed in parallel; the lease locks
	// serialise jobs that share a resource.
	// Notification delivery (retry/backoff/rate limit inside Run).
	go func() {
		nt := &alerts.Notifier{DB: db, Vault: v, Host: host}
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if sent, failed, err := nt.Run(ctx, time.Now()); err != nil {
					log.Warn("notifications", "err", err)
				} else if sent+failed > 0 {
					log.Info("notifications", "sent", sent, "failed", failed)
				}
			}
		}
	}()
	for w := 0; w < 3; w++ {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for {
						ran, err := coord.RunOnce(ctx)
						if err != nil {
							log.Error("job worker", "err", err)
						}
						if !ran || err != nil {
							break
						}
					}
				}
			}
		}()
	}
	observeTick := time.NewTicker(30 * time.Second)
	defer observeTick.Stop()
	purgeTick := time.NewTicker(10 * time.Minute)
	defer purgeTick.Stop()
	step := func() {
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		var ping map[string]any
		if err := ipc.Call(cctx, sock, ipc.Request{Op: "ping"}, &ping); err != nil {
			_ = observe.Heartbeat(ctx, db, "ngm-helper", "down", "unreachable: "+trim(err.Error()))
			log.Warn("helper ping failed", "err", err)
		} else {
			_ = observe.Heartbeat(ctx, db, "ngm-helper", "healthy", fmt.Sprintf("version %v", ping["version"]))
			var n observe.Nginx
			if err := ipc.Call(cctx, sock, ipc.Request{Op: "observe.nginx"}, &n); err != nil {
				log.Warn("observe nginx failed", "err", err)
			} else if err := observe.Record(ctx, db, observe.KindNginx, n, 60*time.Second); err != nil {
				log.Warn("record observation", "err", err)
			}
			var pst observe.Pointer
			if err := ipc.Call(cctx, sock, ipc.Request{Op: "nginx.state"}, &pst); err == nil {
				_ = observe.Record(ctx, db, observe.KindPointer, pst, 60*time.Second)
			}
			var fwst map[string]any
			if err := ipc.Call(cctx, sock, ipc.Request{Op: "fw.state"}, &fwst); err == nil {
				_ = observe.Record(ctx, db, deploy.KindFirewallObservation, fwst, 60*time.Second)
			}
		}
		_ = observe.Heartbeat(ctx, db, "ngm-ops", "healthy", buildinfo.Version)
	}
	purge := func() {
		now := time.Now()
		_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)",
			store.FormatTime(now), store.FormatTime(now.Add(-24*time.Hour)))
		if err != nil {
			log.Warn("session purge", "err", err)
		}
	}
	step()
	purge()
	for {
		select {
		case <-ctx.Done():
			_ = observe.Heartbeat(context.Background(), db, "ngm-ops", "down", "stopped")
			log.Info("ngm ops stopped")
			return nil
		case <-observeTick.C:
			step()

		case <-purgeTick.C:
			purge()
			if err := coord.ScheduleBackups(ctx); err != nil {
				log.Warn("backup scheduler", "err", err)
			}
			if n, err := coord.ScheduleRenewals(ctx); err != nil {
				log.Warn("certificate renewal scheduler", "err", err)
			} else if n > 0 {
				log.Info("certificate renewals queued", "count", n)
			}
		}
	}
}

// NewFirewall returns the root-side UFW implementation.
func NewFirewall(cfg config.Config) *helper.Firewall {
	return &helper.Firewall{Run: helper.ExecRunner{}, PlanDir: filepath.Join(cfg.Paths.StateDir, "fw"), NGMBin: filepath.Join(cfg.Paths.Current, "ngm"), Config: config.DefaultPath}
}

// RunMonitor runs active backend health checks.
func RunMonitor(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	apiPort := 9999
	if _, p, err := net.SplitHostPort(cfg.API.Listen); err == nil {
		apiPort, _ = strconv.Atoi(p)
	}
	m := &monitor.Monitor{DB: db, GW: gwstore.New(db, nil, audit.New(db)), Broker: sse.NewBroker(db), Guard: monitor.Guard{APIPort: apiPort}, Log: log,
		ConcurrencyFn: func(ctx context.Context) int { return perf.Current(ctx, db).Internal.MonitorConcurrency }}
	log.Info("ngm monitor started", "version", buildinfo.Version)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()
	// DNS evidence: every registered domain every 5 minutes, and on request
	// (the API only records the request; it never performs network lookups).
	reg := &domains.Service{DB: db, Audit: audit.New(db)}
	chk := &domains.Checker{DB: db, Q: &dnsq.Client{Timeout: 3 * time.Second}, Resolvers: cfg.Monitor.DNSResolvers}
	dnsTick := time.NewTicker(10 * time.Second)
	defer dnsTick.Stop()
	// Metrics + alert evaluation (evidence only; delivery happens in ngm-ops,
	// which can read notification secrets).
	alertTick := time.NewTicker(30 * time.Second)
	defer alertTick.Stop()
	sampler := &alerts.Sampler{}
	alertStore := &alerts.Store{DB: db}
	host, _ := os.Hostname()
	notifier := &alerts.Notifier{DB: db, Host: host}
	var lastFull time.Time
	_ = observe.Heartbeat(ctx, db, "ngm-monitor", "healthy", buildinfo.Version)
	for {
		select {
		case <-ctx.Done():
			_ = observe.Heartbeat(context.Background(), db, "ngm-monitor", "down", "stopped")
			return nil
		case <-hb.C:
			_ = observe.Heartbeat(ctx, db, "ngm-monitor", "healthy", buildinfo.Version)
		case <-t.C:
			if err := m.Tick(ctx); err != nil {
				log.Warn("monitor tick", "err", err)
			}
		case <-alertTick.C:
			if m, err := sampler.Sample("/"); err == nil {
				_ = observe.Record(ctx, db, alerts.KindSystem, m, 0)
				_, _ = db.ExecContext(ctx, "INSERT OR REPLACE INTO metric_samples(ts,cpu_pct,load1,mem_used,mem_total,disk_used,disk_total) VALUES(?,?,?,?,?,?,?)",
					m.At.Unix(), m.CPUPct, m.Load1, m.MemUsed, m.MemTotal, m.DiskUsed, m.DiskTotal)
				_, _ = db.ExecContext(ctx, "DELETE FROM metric_samples WHERE ts<?", time.Now().Add(-7*24*time.Hour).Unix())
			}
			conds, err := alerts.Evaluate(ctx, db, time.Now())
			if err == nil {
				trs, err := alertStore.Sync(ctx, conds, time.Now())
				if err != nil {
					log.Warn("alerts", "err", err)
				} else if len(trs) > 0 {
					n, _ := notifier.Enqueue(ctx, trs)
					log.Info("alert transitions", "count", len(trs), "deliveries", n)
					if m.Broker != nil {
						_, _ = m.Broker.Publish(ctx, "alerts.changed", "global", map[string]any{"transitions": len(trs)})
					}
				}
			}
		case <-dnsTick.C:
			if time.Since(lastFull) >= 5*time.Minute {
				lastFull = time.Now()
				if n, err := chk.CheckAll(ctx, reg); err != nil {
					log.Warn("dns check", "err", err)
				} else if n > 0 {
					log.Info("dns checked", "domains", n)
				}
				_, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE key LIKE 'dns.check_request.%'")
				continue
			}
			for _, id := range domains.PendingChecks(ctx, db) {
				if d, err := reg.Get(ctx, id); err == nil {
					cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
					if err := chk.Check(cctx, d); err != nil {
						log.Warn("dns check", "domain", d.FQDN, "err", err)
					}
					cancel()
				}
				_, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE key=?", "dns.check_request."+id)
			}
		}
	}
}

func trim(s string) string {
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
