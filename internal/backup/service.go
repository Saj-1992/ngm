package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Settings keys.
const (
	SettingKDF      = "backup.kdf"      // KDF params (salt) used with the stored key
	SettingSchedule = "backup.schedule" // Schedule
)

// keyRef is the vault reference of the passphrase-derived archive key. The
// passphrase itself is never stored; the derived key lets scheduled backups
// run unattended, and restore needs only the passphrase.
var keyRef = vault.Ref{Type: "backup_key", Scope: "global", Name: "archive"}

var (
	ErrNoPassphrase = errors.New("no backup passphrase configured")
	ErrWeak         = errors.New("backup passphrase must be at least 16 characters")
)

// Schedule configures automatic backups.
type Schedule struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"`
	Retain        int  `json:"retain"`
}

// Artifact is a recorded archive.
type Artifact struct {
	ID        string    `json:"id"`
	FileName  string    `json:"file_name"`
	Size      int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	Status    string    `json:"status"`
	Trigger   string    `json:"trigger"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Manifest  Manifest  `json:"manifest"`
}

// Service manages archives on the local disk.
type Service struct {
	DB    *store.DB
	Vault *vault.Vault
	Dir   string // backups directory
	// KDF overrides parameters (tests); zero value = DefaultKDF.
	KDF *KDF
}

func (s *Service) setting(ctx context.Context, key string, out any) error {
	var v string
	if err := s.DB.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", key).Scan(&v); err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), out)
}

func putSetting(ctx context.Context, tx *sql.Tx, key string, v any) error {
	b, _ := json.Marshal(v)
	_, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, revision=revision+1, updated_at=excluded.updated_at`, key, string(b), store.FormatTime(time.Now()))
	return err
}

// SetPassphrase derives and stores the archive key. Existing archives keep
// their own salt and stay restorable with the passphrase used at the time.
func (s *Service) SetPassphrase(ctx context.Context, passphrase string) error {
	if utf8.RuneCountInString(passphrase) < 16 || len(passphrase) > 1024 {
		return ErrWeak
	}
	k := DefaultKDF()
	if s.KDF != nil {
		k = *s.KDF
		k.Salt = DefaultKDF().Salt
	}
	key, err := k.Derive(passphrase)
	if err != nil {
		return err
	}
	defer clear(key)
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := s.Vault.PutTx(ctx, tx, keyRef, key); err != nil {
			return err
		}
		return putSetting(ctx, tx, SettingKDF, k)
	})
}

// Configured reports whether a passphrase-derived key exists.
func (s *Service) Configured(ctx context.Context) bool {
	var k KDF
	return s.setting(ctx, SettingKDF, &k) == nil
}

// Key returns the stored archive key and its KDF parameters.
func (s *Service) Key(ctx context.Context) ([]byte, KDF, error) {
	var k KDF
	if err := s.setting(ctx, SettingKDF, &k); err != nil {
		return nil, k, ErrNoPassphrase
	}
	key, err := s.Vault.Get(ctx, keyRef)
	if err != nil {
		return nil, k, ErrNoPassphrase
	}
	return key, k, nil
}

// GetSchedule returns the schedule (disabled by default).
func (s *Service) GetSchedule(ctx context.Context) Schedule {
	sc := Schedule{IntervalHours: 24, Retain: 7}
	_ = s.setting(ctx, SettingSchedule, &sc)
	return sc
}

// SetSchedule validates and stores the schedule.
func (s *Service) SetSchedule(ctx context.Context, sc Schedule) error {
	if sc.IntervalHours < 1 || sc.IntervalHours > 24*30 || sc.Retain < 1 || sc.Retain > 365 {
		return errors.New("interval must be 1–720 h and retention 1–365 archives")
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error { return putSetting(ctx, tx, SettingSchedule, sc) })
}

var fileRe = regexp.MustCompile(`^ngm-[a-z0-9.-]{1,64}-\d{8}T\d{6}(\.\d{3})?Z-[a-z_]{1,20}\.ngmbak$`)

// CreateArchive writes a new archive and records it.
func (s *Service) CreateArchive(ctx context.Context, keysDir, hostname, trigger, actor string) (*Artifact, error) {
	key, kdf, err := s.Key(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if err := os.MkdirAll(s.Dir, 0o770); err != nil {
		return nil, err
	}
	host := strings.ToLower(regexp.MustCompile(`[^a-z0-9.-]`).ReplaceAllString(strings.ToLower(hostname), "-"))
	if host == "" {
		host = "host"
	}
	name := fmt.Sprintf("ngm-%s-%s-%s.ngmbak", host, time.Now().UTC().Format("20060102T150405.000Z"), trigger)
	final := filepath.Join(s.Dir, name)
	tmp := final + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	m, err := Create(ctx, io.MultiWriter(f, h), key, kdf, Sources{DB: s.DB, KeysDir: keysDir, TmpDir: s.Dir, Hostname: hostname, Trigger: trigger})
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	// Verify the written archive before publishing it.
	if _, err := s.verifyFile(ctx, tmp, key); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("post-write verification failed: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	st, _ := os.Stat(final)
	a := &Artifact{ID: ids.New(), FileName: name, Size: st.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Status: "complete", Trigger: trigger, CreatedBy: actor, CreatedAt: time.Now().UTC(), Manifest: *m}
	mj, _ := json.Marshal(m)
	var by any
	if actor != "" {
		by = actor
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO backup_artifacts(id,file_name,size_bytes,sha256,manifest_json,status,trigger_kind,created_by,created_at) VALUES(?,?,?,?,?,'complete',?,?,?)`,
		a.ID, name, a.Size, a.SHA256, string(mj), trigger, by, store.FormatTime(a.CreatedAt))
	return a, err
}

// verifyFile decrypts the whole archive with key into a throwaway dir.
func (s *Service) verifyFile(ctx context.Context, p string, key []byte) (*Extracted, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dir, err := os.MkdirTemp(s.Dir, ".verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	x, err := ExtractWithKey(bufio.NewReader(f), key, dir, 0)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(x.DBPath(), store.Options{})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return x, db.IntegrityCheck(ctx)
}

// Verify re-checks an archive (needs the configured key).
func (s *Service) Verify(ctx context.Context, id string) (*Manifest, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	key, _, err := s.Key(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	x, err := s.verifyFile(ctx, filepath.Join(s.Dir, a.FileName), key)
	if err != nil {
		return nil, err
	}
	return &x.Manifest, nil
}

// List returns archives, newest first.
func (s *Service) List(ctx context.Context) ([]Artifact, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,file_name,size_bytes,sha256,status,trigger_kind,COALESCE(created_by,''),created_at,manifest_json FROM backup_artifacts
		WHERE status='complete' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Artifact{}
	for rows.Next() {
		var a Artifact
		var c, m string
		if err := rows.Scan(&a.ID, &a.FileName, &a.Size, &a.SHA256, &a.Status, &a.Trigger, &a.CreatedBy, &c, &m); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = store.ParseTime(c)
		_ = json.Unmarshal([]byte(m), &a.Manifest)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrNotFound is returned for unknown archives.
var ErrNotFound = errors.New("backup not found")

// Get returns one archive record.
func (s *Service) Get(ctx context.Context, id string) (*Artifact, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.ID == id {
			if !fileRe.MatchString(a.FileName) {
				return nil, ErrNotFound
			}
			return &a, nil
		}
	}
	return nil, ErrNotFound
}

// Open opens an archive file for download.
func (s *Service) Open(ctx context.Context, id string) (*os.File, *Artifact, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(filepath.Join(s.Dir, a.FileName))
	return f, a, err
}

// Delete removes an archive file and its record.
func (s *Service) Delete(ctx context.Context, id string) error {
	a, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.Dir, a.FileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE backup_artifacts SET status='deleted' WHERE id=?", id)
	return err
}

// ApplyRetention keeps the newest `retain` manual/scheduled archives.
// Safety snapshots (pre_*) are kept for 30 days regardless of count.
func (s *Service) ApplyRetention(ctx context.Context, retain int) (int, error) {
	all, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	kept, removed := 0, 0
	for _, a := range all {
		if strings.HasPrefix(a.Trigger, "pre_") {
			if time.Since(a.CreatedAt) > 30*24*time.Hour {
				if s.Delete(ctx, a.ID) == nil {
					removed++
				}
			}
			continue
		}
		kept++
		if kept > retain {
			if s.Delete(ctx, a.ID) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// LastScheduled returns the time of the newest scheduled archive.
func (s *Service) LastScheduled(ctx context.Context) time.Time {
	var c string
	if err := s.DB.QueryRowContext(ctx, "SELECT created_at FROM backup_artifacts WHERE trigger_kind='scheduled' AND status='complete' ORDER BY created_at DESC LIMIT 1").Scan(&c); err != nil {
		return time.Time{}
	}
	t, _ := store.ParseTime(c)
	return t
}
