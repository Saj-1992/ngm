package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/app"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/restore"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// ngmServices are stopped around operations that must not race the services
// (Nginx is never stopped).
var ngmServices = []string{"ngm-api.service", "ngm-ops.service", "ngm-monitor.service"}

// readPassphrase takes NGM_BACKUP_PASSPHRASE or the first line of stdin, so the
// passphrase never appears in argv (visible in ps) or shell history.
func readPassphrase(stdin io.Reader) (string, error) {
	if p := os.Getenv("NGM_BACKUP_PASSPHRASE"); p != "" {
		return p, nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("passphrase required: set NGM_BACKUP_PASSPHRASE or pipe it on stdin")
	}
	return line, nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root on the gateway host")
	}
	return nil
}

func cmdBackup(ctx context.Context, cfg config.Config, args []string, stdin io.Reader, stdout io.Writer) error {
	const u = "usage: ngm backup create | ngm backup set-passphrase (stdin/NGM_BACKUP_PASSPHRASE) | ngm backup list"
	if len(args) != 1 {
		return errors.New(u)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	v, err := app.OpenVault(ctx, cfg, db)
	if err != nil {
		return err
	}
	bs := &backup.Service{DB: db, Vault: v, Dir: cfg.Paths.Backups}
	switch args[0] {
	case "set-passphrase":
		p, err := readPassphrase(stdin)
		if err != nil {
			return err
		}
		if err := bs.SetPassphrase(ctx, p); err != nil {
			return err
		}
		_, _ = audit.New(db).Record(ctx, audit.Event{ActorKind: "cli", Action: "backup.passphrase_set", TargetKind: "settings", TargetID: backup.SettingKDF, Result: "success"})
		fmt.Fprintln(stdout, "backup passphrase set. Store it safely OFF this server: without it, archives cannot be restored on a new host.")
		return nil
	case "create":
		host, _ := os.Hostname()
		a, err := bs.CreateArchive(ctx, cfg.Paths.KeysDir, host, "manual", "")
		if err != nil {
			return err
		}
		fixGroup(filepath.Join(cfg.Paths.Backups, a.FileName))
		_, _ = audit.New(db).Record(ctx, audit.Event{ActorKind: "cli", Action: "backup.create", TargetKind: "backup", TargetID: a.ID, Result: "success"})
		fmt.Fprintf(stdout, "backup written and verified: %s\n  size %d bytes, sha256 %s\n", filepath.Join(cfg.Paths.Backups, a.FileName), a.Size, a.SHA256)
		return nil
	case "list":
		items, err := bs.List(ctx)
		if err != nil {
			return err
		}
		for _, a := range items {
			fmt.Fprintf(stdout, "%s  %s  %-10s %10d  %s\n", a.ID, a.CreatedAt.Format("2006-01-02 15:04:05Z"), a.Trigger, a.Size, a.FileName)
		}
		return nil
	}
	return errors.New(u)
}

// fixGroup gives a root-created archive to group ngm so the API can serve it.
func fixGroup(p string) {
	if g, err := user.LookupGroup("ngm"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		_ = os.Chown(p, 0, gid)
	}
}

func cmdRestore(ctx context.Context, cfg config.Config, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	preview := fs.Bool("preview", false, "decrypt and verify only; change nothing")
	apply := fs.Bool("apply", false, "after restoring, queue a deployment of the restored gateway configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ngm restore [--preview] [--apply] FILE  (passphrase via NGM_BACKUP_PASSPHRASE or stdin)")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	p, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	res, err := restore.Run(ctx, restore.Options{File: fs.Arg(0), Passphrase: p, Preview: *preview, Apply: *apply, Config: cfg, Services: ngmServices,
		Logf: func(f string, a ...any) { fmt.Fprintf(stdout, f+"\n", a...) }})
	if err != nil {
		return err
	}
	if *preview {
		fmt.Fprintln(stdout, "preview only: nothing was changed.")
		return nil
	}
	fmt.Fprintf(stdout, "restore complete.\n  previous database: %s\n  safety backup:     %s\n", res.Previous, res.SafetyBackup)
	if res.DeployJob != "" {
		fmt.Fprintf(stdout, "  deployment job:    %s (watch it in the Control Center)\n", res.DeployJob)
	} else {
		fmt.Fprintln(stdout, "  the restored gateway configuration is Desired only; review it and deploy from the Control Center (or re-run with --apply).")
	}
	fmt.Fprintln(stdout, "  all sessions were revoked: sign in again.")
	return nil
}

func systemctl(ctx context.Context, verb string, units []string) error {
	for _, u := range units {
		if out, err := exec.CommandContext(ctx, "systemctl", verb, u).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s %s: %v: %s", verb, u, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func cmdVault(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) (err error) {
	const u = "usage: ngm vault status | ngm vault rotate | ngm vault retire VERSION"
	if len(args) == 0 {
		return errors.New(u)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	db, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	v, err := app.OpenVault(ctx, cfg, db)
	if err != nil {
		return err
	}
	switch {
	case args[0] == "status" && len(args) == 1:
		st, err := v.Status(ctx)
		if err != nil {
			return err
		}
		kv, _ := v.KeyVersions(ctx)
		fmt.Fprintf(stdout, "active KEK version: %d\n", st.ActiveVersion)
		for _, k := range kv {
			fmt.Fprintf(stdout, "  v%d  %-9s secrets=%d\n", k.Version, k.Status, st.Versions[k.Version])
		}
		return nil
	case args[0] == "retire" && len(args) == 2:
		n, err := strconv.Atoi(args[1])
		if err != nil {
			return errors.New(u)
		}
		if err := v.Retire(ctx, n); err != nil {
			return err
		}
		_, _ = audit.New(db).Record(ctx, audit.Event{ActorKind: "cli", Action: "vault.retire", TargetKind: "kek", TargetID: args[1], Result: "success"})
		fmt.Fprintf(stdout, "KEK v%d retired. Remove %s only after a verified backup taken since the rotation.\n", n, filepath.Join(cfg.Paths.KeysDir, vault.KeyFileName(n)))
		return nil
	case args[0] == "rotate" && len(args) == 1:
	default:
		return errors.New(u)
	}

	// Rotate: resume a staged version after a crash, else generate the next one.
	kv, err := v.KeyVersions(ctx)
	if err != nil {
		return err
	}
	next := 0
	for _, k := range kv {
		if k.Status == "staged" {
			next = k.Version
		}
	}
	resumed := next != 0
	if !resumed {
		for _, k := range kv {
			if k.Version >= next {
				next = k.Version + 1
			}
		}
		// A key file from an aborted, never-staged attempt is reused only if no row exists for it.
		p := filepath.Join(cfg.Paths.KeysDir, vault.KeyFileName(next))
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if _, err := vault.GenerateKeyFile(cfg.Paths.KeysDir, next); err != nil {
				return err
			}
		}
	}
	// Always (re)assert key ownership: a rotation killed between creating the
	// key file and chown-ing it would otherwise leave a root:root key that the
	// services cannot read, and they would crash-loop after restart.
	if err := fixKeyPerms(cfg.Paths.KeysDir); err != nil {
		return err
	}
	// Services keep the keyring they loaded at start; stop them so nothing
	// writes under the old KEK mid-rotation, then restart with the new key.
	if err := systemctl(ctx, "stop", ngmServices); err != nil {
		_ = systemctl(ctx, "start", ngmServices)
		return err
	}
	defer func() {
		bg := context.WithoutCancel(ctx)
		if perr := fixKeyPerms(cfg.Paths.KeysDir); perr != nil && err == nil {
			err = perr
		}
		if serr := systemctl(bg, "start", ngmServices); serr != nil && err == nil {
			err = serr
		}
		if herr := servicesStayUp(bg, ngmServices); herr != nil && err == nil {
			err = herr
		}
	}()
	db.Close()
	db, err = app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	if v, err = app.OpenVault(ctx, cfg, db); err != nil {
		return err
	}
	st, err := v.Rotate(ctx, next)
	if err != nil {
		return fmt.Errorf("rotation to KEK v%d stopped (re-run `ngm vault rotate` to resume): %w", next, err)
	}
	_, _ = audit.New(db).Record(ctx, audit.Event{ActorKind: "cli", Action: "vault.rotate", TargetKind: "kek", TargetID: strconv.Itoa(next), Result: "success",
		Context: map[string]any{"resumed": resumed}})
	fmt.Fprintf(stdout, "vault rotated to KEK v%d (%v). Previous versions are 'retiring': take a new backup, then `ngm vault retire N`.\n", st.ActiveVersion, st.Versions)
	return nil
}

// fixKeyPerms sets every KEK file to root:ngm-vault 0440 (the services read
// keys through the ngm-vault group).
func fixKeyPerms(dir string) error {
	g, err := user.LookupGroup("ngm-vault")
	if err != nil {
		return fmt.Errorf("group ngm-vault: %w", err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	files, err := filepath.Glob(filepath.Join(dir, "kek-*.key"))
	if err != nil {
		return err
	}
	for _, p := range files {
		if err := os.Chown(p, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o440); err != nil {
			return err
		}
	}
	return nil
}

// servicesStayUp checks that restarted services are still running a few
// seconds later (a unit that crash-loops reports "activating"/"failed").
func servicesStayUp(ctx context.Context, units []string) error {
	time.Sleep(5 * time.Second)
	var bad []string
	for _, u := range units {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", u).Output()
		if st := strings.TrimSpace(string(out)); st != "active" {
			bad = append(bad, u+"="+st)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("services not healthy after rotation: %s (see journalctl -u ngm-api -u ngm-ops)", strings.Join(bad, ", "))
	}
	return nil
}

// keyPermProblems lists KEK files whose ownership/mode would stop the
// services (group ngm-vault) from reading them.
func keyPermProblems(dir string) []string {
	g, err := user.LookupGroup("ngm-vault")
	if err != nil {
		return []string{"group ngm-vault missing"}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "kek-*.key"))
	var bad []string
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil {
			bad = append(bad, filepath.Base(p)+": "+err.Error())
			continue
		}
		if fileGID(st) != g.Gid || st.Mode().Perm() != 0o440 {
			bad = append(bad, fmt.Sprintf("%s (gid %s, mode %v)", filepath.Base(p), fileGID(st), st.Mode().Perm()))
		}
	}
	return bad
}

func cmdLogs(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "reindex" {
		return errors.New("usage: ngm logs reindex")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unit := []string{"ngm-log-indexer.service"}
	if err := systemctl(ctx, "stop", unit); err != nil {
		return err
	}
	p := app.LogIndexPath(cfg)
	for _, suf := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(p + suf); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = systemctl(ctx, "start", unit)
			return err
		}
	}
	if err := systemctl(ctx, "start", unit); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "log index removed; ngm-log-indexer is rebuilding it from the current and last rotated log files (source logs were not modified).")
	return nil
}
