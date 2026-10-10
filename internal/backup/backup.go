package backup

import (
	"archive/tar"
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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// FileEntry describes one archived file.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is stored inside the encrypted archive.
type Manifest struct {
	Format        int            `json:"format"`
	Created       time.Time      `json:"created"`
	NGMVersion    string         `json:"ngm_version"`
	SchemaVersion int            `json:"schema_version"`
	Hostname      string         `json:"hostname"`
	Trigger       string         `json:"trigger"`
	Files         []FileEntry    `json:"files"`
	Counts        map[string]int `json:"counts"`
	KEKVersions   []int          `json:"kek_versions"`
}

// Sources lists what a backup captures.
type Sources struct {
	DB       *store.DB
	KeysDir  string // KEK files (encrypted under the passphrase key in the archive)
	TmpDir   string // for the consistent DB snapshot
	Hostname string
	Trigger  string // manual | scheduled | pre_restore | pre_update | pre_migration
}

// archive path constraints for extraction.
var safeName = regexp.MustCompile(`^(manifest\.json|db/ngm\.db|keys/kek-[0-9]+\.key)$`)

// Create writes an encrypted archive to w using key (from KDF params kdf).
func Create(ctx context.Context, w io.Writer, key []byte, kdf KDF, src Sources) (*Manifest, error) {
	if src.TmpDir == "" {
		src.TmpDir = os.TempDir()
	}
	snap := filepath.Join(src.TmpDir, "ngm-backup-"+ids.New()+".db")
	defer os.Remove(snap)
	if err := src.DB.Snapshot(ctx, snap); err != nil {
		return nil, err
	}
	sdb, err := store.Open(snap, store.Options{})
	if err != nil {
		return nil, err
	}
	schema, _ := sdb.SchemaVersion(ctx)
	if err := sdb.IntegrityCheck(ctx); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("snapshot integrity: %w", err)
	}
	counts := map[string]int{}
	for _, t := range []string{"listeners", "routes", "backend_endpoints", "backend_pools", "certificates", "users", "vault_secrets", "config_generations", "managed_firewall_rules"} {
		var n int
		_ = sdb.QueryRowContext(ctx, "SELECT count(*) FROM "+t).Scan(&n)
		counts[t] = n
	}
	sdb.Close()
	files := map[string]string{"db/ngm.db": snap}
	var kekVersions []int
	es, err := os.ReadDir(src.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("keys dir: %w", err)
	}
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "kek-") && strings.HasSuffix(e.Name(), ".key") {
			files["keys/"+e.Name()] = filepath.Join(src.KeysDir, e.Name())
			var v int
			fmt.Sscanf(e.Name(), "kek-%d.key", &v)
			kekVersions = append(kekVersions, v)
		}
	}
	sort.Ints(kekVersions)
	m := &Manifest{Format: 1, Created: time.Now().UTC(), NGMVersion: buildinfo.Version, SchemaVersion: schema, Hostname: src.Hostname,
		Trigger: src.Trigger, Counts: counts, KEKVersions: kekVersions}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fe, err := hashFile(files[n])
		if err != nil {
			return nil, err
		}
		fe.Path = n
		m.Files = append(m.Files, fe)
	}
	ew, err := NewWriter(w, key, Header{KDF: kdf, Created: m.Created, NGMVersion: m.NGMVersion, SchemaVersion: schema, Hostname: src.Hostname, Trigger: src.Trigger})
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(ew)
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(mb)), ModTime: m.Created}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(mb); err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := addFile(tw, n, files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := ew.Close(); err != nil {
		return nil, err
	}
	return m, nil
}

func hashFile(p string) (FileEntry, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileEntry{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return FileEntry{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, err
}

func addFile(tw *tar.Writer, name, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Extracted is a verified, decrypted archive on disk.
type Extracted struct {
	Dir      string
	Header   Header
	Manifest Manifest
}

// DBPath is the extracted database.
func (x *Extracted) DBPath() string { return filepath.Join(x.Dir, "db", "ngm.db") }

// KeysDir holds the source KEKs.
func (x *Extracted) KeysDir() string { return filepath.Join(x.Dir, "keys") }

// Extract decrypts and verifies an archive into dir (0700). Nothing outside
// dir is touched; any authentication, hash or path failure aborts.
func Extract(r io.Reader, passphrase, dir string, maxBytes int64) (*Extracted, error) {
	br := bufio.NewReader(r)
	dr, h, err := NewReader(br, passphrase)
	if err != nil {
		return nil, err
	}
	return extract(dr, h, dir, maxBytes)
}

// ExtractWithKey is Extract with a pre-derived key (scheduled-backup key).
func ExtractWithKey(r io.Reader, key []byte, dir string, maxBytes int64) (*Extracted, error) {
	br := bufio.NewReader(r)
	h, hb, err := ReadHeader(br)
	if err != nil {
		return nil, err
	}
	dr, h, err := NewReaderWithKey(br, key, h, hb)
	if err != nil {
		return nil, err
	}
	return extract(dr, h, dir, maxBytes)
}

func extract(dr io.Reader, h Header, dir string, maxBytes int64) (*Extracted, error) {
	if maxBytes <= 0 {
		maxBytes = 4 << 30
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	x := &Extracted{Dir: dir, Header: h}
	tr := tar.NewReader(dr)
	var total int64
	got := map[string]FileEntry{}
	for {
		th, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrCorrupt) {
				return nil, err
			}
			return nil, ErrCorrupt
		}
		name := path.Clean(th.Name)
		if !safeName.MatchString(name) || th.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrCorrupt, th.Name)
		}
		total += th.Size
		if total > maxBytes {
			return nil, fmt.Errorf("%w: archive larger than %s", ErrCorrupt, fmtSize(maxBytes))
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		hh := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, hh), io.LimitReader(tr, th.Size))
		f.Close()
		if err != nil {
			if errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrCorrupt) {
				return nil, err
			}
			return nil, ErrCorrupt
		}
		got[name] = FileEntry{Path: name, Size: n, SHA256: hex.EncodeToString(hh.Sum(nil))}
	}
	// The tar end marker precedes the final encrypted chunk: drain the stream
	// so the final-chunk flag and the absence of trailing data are verified.
	if _, err := io.Copy(io.Discard, dr); err != nil {
		if errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrCorrupt) {
			return nil, err
		}
		return nil, ErrCorrupt
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: manifest missing", ErrCorrupt)
	}
	if err := json.Unmarshal(mb, &x.Manifest); err != nil {
		return nil, ErrCorrupt
	}
	for _, fe := range x.Manifest.Files {
		g, ok := got[fe.Path]
		if !ok || g.SHA256 != fe.SHA256 || g.Size != fe.Size {
			return nil, fmt.Errorf("%w: %s does not match the manifest", ErrCorrupt, fe.Path)
		}
	}
	if len(got) != len(x.Manifest.Files)+1 {
		return nil, fmt.Errorf("%w: unexpected extra files", ErrCorrupt)
	}
	return x, nil
}

// Rekey rewraps every vault secret in the database at dbPath from the source
// keyring (archive KEKs) to the destination keyring's active key, and replaces
// the key-version table with the destination's. The database must not be in
// use (it is a staged copy).
func Rekey(ctx context.Context, dbPath string, src, dst *vault.Keyring, dstVersions []vault.KeyVersion) error {
	db, err := store.Open(dbPath, store.Options{MaxOpenConns: 1})
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	if err := rekeyOn(ctx, conn, src, dst, dstVersions); err != nil {
		conn.Close()
		return err
	}
	// Release the only connection before using the pool again.
	if err := conn.Close(); err != nil {
		return err
	}
	return db.IntegrityCheck(ctx)
}

func rekeyOn(ctx context.Context, conn *sql.Conn, src, dst *vault.Keyring, dstVersions []vault.KeyVersion) error {
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := vault.RewrapAll(ctx, tx, src, dst, dstVersions); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "PRAGMA foreign_keys=ON")
	return err
}
