package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/backup"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func backupEnv(t *testing.T, withPassphrase bool) *env {
	e := newEnv(t)
	kr := vault.NewKeyring()
	k := make([]byte, 32)
	kr.Add(1, k)
	v := vault.New(e.db, kr)
	kdf := backup.DefaultKDF()
	kdf.MemoryKiB, kdf.Time, kdf.Threads = 8*1024, 1, 1
	keys := t.TempDir()
	os.WriteFile(filepath.Join(keys, "kek-1.key"), k, 0o400)
	e.c.Backups = &backup.Service{DB: e.db, Vault: v, Dir: t.TempDir(), KDF: &kdf}
	e.c.KeysDir, e.c.Hostname = keys, "test-host"
	if withPassphrase {
		if err := e.c.Backups.SetPassphrase(context.Background(), "a-long-test-passphrase-123"); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func runQueued(t *testing.T, e *env) {
	for {
		ok, err := e.c.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return
		}
	}
}

func TestBackupJobNeedsPassphrase(t *testing.T) {
	e := backupEnv(t, false)
	j := e.submit(t, KindBackup, BackupPayload{Trigger: "manual"})
	if j.State != jobs.Blocked || !strings.Contains(string(j.Error), "no_passphrase") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
}

func TestBackupJobWritesVerifiedArchive(t *testing.T) {
	e := backupEnv(t, true)
	j := e.submit(t, KindBackup, BackupPayload{Trigger: "manual"})
	if j.State != jobs.Succeeded {
		t.Fatalf("%s %s", j.State, j.Error)
	}
	l, _ := e.c.Backups.List(context.Background())
	if len(l) != 1 || l[0].Trigger != "manual" {
		t.Fatalf("%+v", l)
	}
}

func TestScheduledBackupsOncePerWindowWithRetention(t *testing.T) {
	ctx := context.Background()
	e := backupEnv(t, true)
	// Disabled schedule → nothing queued.
	if err := e.c.ScheduleBackups(ctx); err != nil {
		t.Fatal(err)
	}
	if js, _ := e.c.Jobs.List(ctx, jobs.ListFilter{Limit: 10}); len(js) != 0 {
		t.Fatalf("queued while disabled: %d", len(js))
	}
	e.c.Backups.SetSchedule(ctx, backup.Schedule{Enabled: true, IntervalHours: 1, Retain: 2})
	// Repeated ticks inside one window queue a single job (idempotency key).
	for i := 0; i < 3; i++ {
		if err := e.c.ScheduleBackups(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if js, _ := e.c.Jobs.List(ctx, jobs.ListFilter{Limit: 10}); len(js) != 1 {
		t.Fatalf("want 1 scheduled job, got %d", len(js))
	}
	runQueued(t, e)
	// A recent scheduled archive suppresses the next one.
	e.c.ScheduleBackups(ctx)
	if js, _ := e.c.Jobs.List(ctx, jobs.ListFilter{Limit: 10}); len(js) != 1 {
		t.Fatalf("queued again before interval: %d", len(js))
	}
	// Age the archives; each new scheduled run applies retention (keep 2).
	for i := 0; i < 3; i++ {
		e.db.ExecContext(ctx, "UPDATE backup_artifacts SET created_at=? WHERE status='complete'", store.FormatTime(time.Now().Add(-2*time.Hour-time.Duration(i)*time.Minute)))
		e.submit(t, KindBackup, BackupPayload{Trigger: "scheduled"})
	}
	l, _ := e.c.Backups.List(ctx)
	if len(l) != 2 {
		t.Fatalf("retention kept %d archives", len(l))
	}
}
