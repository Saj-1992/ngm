// Package store owns the SQLite database: connection policy (WAL, foreign keys,
// busy handling), checksummed migrations, integrity checks and online snapshots.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, see DECISIONS ADR-002
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// TimeFormat is the canonical timestamp encoding stored in TEXT columns.
const TimeFormat = time.RFC3339Nano

// FormatTime renders t in UTC using TimeFormat.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime parses a stored timestamp.
func ParseTime(s string) (time.Time, error) { return time.Parse(TimeFormat, s) }

// DB wraps *sql.DB with NGM's connection policy.
type DB struct {
	*sql.DB
	path string
}

// Options controls Open.
type Options struct {
	BusyTimeout  time.Duration // default 5s
	MaxOpenConns int           // default 4
	ReadOnly     bool
}

// Open opens (creating if needed) the database at path with WAL and foreign keys
// enforced on every connection. Write transactions use BEGIN IMMEDIATE so that
// lock contention surfaces at BEGIN (bounded by busy_timeout) instead of as a
// deadlock-prone upgrade inside the transaction.
func Open(path string, opt Options) (*DB, error) {
	if opt.BusyTimeout <= 0 {
		opt.BusyTimeout = 5 * time.Second
	}
	if opt.MaxOpenConns <= 0 {
		opt.MaxOpenConns = 4
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout("+strconv.FormatInt(opt.BusyTimeout.Milliseconds(), 10)+")")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_txlock", "immediate")
	if opt.ReadOnly {
		q.Set("mode", "ro")
	}
	dsn := "file:" + filepath.ToSlash(path) + "?" + q.Encode()
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sdb.SetMaxOpenConns(opt.MaxOpenConns)
	sdb.SetConnMaxIdleTime(5 * time.Minute)
	db := &DB{DB: sdb, path: path}
	if err := db.verifyPragmas(context.Background(), opt.ReadOnly); err != nil {
		sdb.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) verifyPragmas(ctx context.Context, readOnly bool) error {
	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return fmt.Errorf("probe foreign_keys: %w", err)
	}
	if fk != 1 {
		return errors.New("sqlite: foreign_keys not enabled")
	}
	if readOnly {
		return nil
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("probe journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("sqlite: journal_mode=%s, want wal", mode)
	}
	return nil
}

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// Tx runs fn in a write transaction, committing on nil error.
func (db *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Migration is one embedded schema step.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// ErrSchemaTooNew means the database was migrated by a newer NGM release; this
// binary must not touch it (fail closed, MASTER_SPEC §7.3).
var ErrSchemaTooNew = errors.New("database schema is newer than this binary supports")

// ErrChecksumMismatch means an applied migration differs from the embedded one.
var ErrChecksumMismatch = errors.New("applied migration checksum mismatch")

// Migrations returns the embedded migrations sorted by version.
func Migrations() ([]Migration, error) { return loadMigrations(migrationFS, "migrations") }

func loadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []Migration
	seen := map[int]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		num, name, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: want NNNN_name.sql", e.Name())
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: bad version", e.Name())
		}
		if seen[v] {
			return nil, fmt.Errorf("duplicate migration version %d", v)
		}
		seen[v] = true
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, Migration{Version: v, Name: name, SQL: string(b), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 1; got %d at position %d", m.Version, i+1)
		}
	}
	return out, nil
}

// SchemaVersion returns the highest applied migration version (0 if none).
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	if err := db.ensureMigrationTable(ctx); err != nil {
		return 0, err
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

func (db *DB) ensureMigrationTable(ctx context.Context) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at TEXT NOT NULL
	) STRICT`)
	return err
}

// Migrate verifies already-applied migrations and applies pending ones, each in
// its own transaction. It refuses to run against a newer or tampered schema.
func (db *DB) Migrate(ctx context.Context) (applied []int, err error) {
	ms, err := Migrations()
	if err != nil {
		return nil, err
	}
	return db.migrate(ctx, ms)
}

func (db *DB) migrate(ctx context.Context, ms []Migration) ([]int, error) {
	if err := db.ensureMigrationTable(ctx); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	have := map[int]string{}
	for rows.Next() {
		var v int
		var c string
		if err := rows.Scan(&v, &c); err != nil {
			rows.Close()
			return nil, err
		}
		have[v] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	known := map[int]Migration{}
	for _, m := range ms {
		known[m.Version] = m
	}
	for v, c := range have {
		m, ok := known[v]
		if !ok {
			return nil, fmt.Errorf("%w: applied version %d unknown to this binary", ErrSchemaTooNew, v)
		}
		if m.Checksum != c {
			return nil, fmt.Errorf("%w: version %d", ErrChecksumMismatch, v)
		}
	}
	var applied []int
	for _, m := range ms {
		if _, ok := have[m.Version]; ok {
			continue
		}
		err := db.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
				m.Version, m.Name, m.Checksum, FormatTime(time.Now()))
			return err
		})
		if err != nil {
			return applied, err
		}
		applied = append(applied, m.Version)
	}
	if err := db.CheckForeignKeys(ctx); err != nil {
		return applied, err
	}
	return applied, nil
}

// IntegrityCheck runs PRAGMA integrity_check and returns an error describing any problem.
func (db *DB) IntegrityCheck(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		if s != "ok" {
			problems = append(problems, s)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("integrity_check: %s", strings.Join(problems, "; "))
	}
	return db.CheckForeignKeys(ctx)
}

// CheckForeignKeys reports any foreign-key violations.
func (db *DB) CheckForeignKeys(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	var first string
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return err
		}
		if n == 0 {
			first = fmt.Sprintf("%s(rowid=%d)->%s", table, rowid.Int64, parent)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("foreign_key_check: %d violation(s), first %s", n, first)
	}
	return nil
}

// Snapshot writes a transactionally consistent copy of the live database to
// dest using VACUUM INTO (safe with concurrent WAL writers). dest must not exist.
func (db *DB) Snapshot(ctx context.Context, dest string) error {
	_, err := db.ExecContext(ctx, "VACUUM INTO ?", dest)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}
