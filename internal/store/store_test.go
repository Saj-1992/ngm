package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "ngm.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestFreshMigrateAndRerun(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	applied, err := db.Migrate(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) != len(ms) {
		t.Fatalf("applied %v, want %d migrations", applied, len(ms))
	}
	again, err := db.Migrate(ctx)
	if err != nil || len(again) != 0 {
		t.Fatalf("rerun applied=%v err=%v, want no-op", again, err)
	}
	v, err := db.SchemaVersion(ctx)
	if err != nil || v != ms[len(ms)-1].Version {
		t.Fatalf("schema version %d err=%v", v, err)
	}
	if err := db.IntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPragmasEnforced(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Exercise several pooled connections: every one must have FK + WAL.
	for i := 0; i < 6; i++ {
		var mode string
		var fk int
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode=%q err=%v", mode, err)
		}
		if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys=%d err=%v", fk, err)
		}
	}
	now := FormatTime(time.Now())
	_, err := db.ExecContext(ctx, `INSERT INTO routes(id,name,listener_id,protocol,destination_kind,created_at,updated_at)
		VALUES('r1','r1','missing-listener','http','reject',?,?)`, now, now)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("expected FK violation, got %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO listeners(id,name,kind,address,port,family,created_at,updated_at)
		VALUES('l1','l1','udp','0.0.0.0',80,'ipv4',?,?)`, now, now)
	if err == nil {
		t.Fatal("expected CHECK constraint failure for kind=udp")
	}
}

func TestChecksumTamperFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET checksum='deadbeef' WHERE version=1"); err != nil {
		t.Fatal(err)
	}
	_, err := db.Migrate(ctx)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("got %v, want ErrChecksumMismatch", err)
	}
}

func TestNewerSchemaFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(999,'future','x',?)", FormatTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	_, err := db.Migrate(ctx)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("got %v, want ErrSchemaTooNew", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	fsys := fstest.MapFS{
		"m/0001_ok.sql":  {Data: []byte("CREATE TABLE a(x INTEGER) STRICT;")},
		"m/0002_bad.sql": {Data: []byte("CREATE TABLE b(x INTEGER) STRICT; THIS IS NOT SQL;")},
	}
	ms, err := loadMigrations(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := db.migrate(ctx, ms)
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(applied) != 1 || applied[0] != 1 {
		t.Fatalf("applied=%v", applied)
	}
	var n int
	db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name='b'").Scan(&n)
	if n != 0 {
		t.Fatal("partial migration 0002 left table b behind")
	}
}

func TestLoadMigrationsRejectsGaps(t *testing.T) {
	fsys := fstest.MapFS{
		"m/0001_a.sql": {Data: []byte("SELECT 1;")},
		"m/0003_c.sql": {Data: []byte("SELECT 1;")},
	}
	if _, err := loadMigrations(fsys, "m"); err == nil {
		t.Fatal("expected gap error")
	}
}

func TestSnapshotIsConsistentCopy(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := FormatTime(time.Now())
	if _, err := db.ExecContext(ctx, "INSERT INTO settings(key,value_json,updated_at) VALUES('k','1',?)", now); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap.db")
	if err := db.Snapshot(ctx, dest); err != nil {
		t.Fatal(err)
	}
	snap, err := Open(dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if err := snap.IntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
	var v string
	if err := snap.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='k'").Scan(&v); err != nil || v != "1" {
		t.Fatalf("snapshot content v=%q err=%v", v, err)
	}
	if _, err := snap.Migrate(ctx); err != nil {
		t.Fatalf("snapshot should carry migration ledger: %v", err)
	}
}
