// Package vault is the local encrypted secrets vault (MASTER_SPEC §10.1,
// SECURITY_MODEL.md).
//
// Envelope encryption: every secret has its own random 256-bit DEK; the
// plaintext is sealed with AES-256-GCM under the DEK, and the DEK is sealed
// with AES-256-GCM under a versioned local KEK. Both seals bind the secret's
// identity (id, type, scope, name, version) as additional authenticated data,
// so ciphertext cannot be swapped between records undetected.
//
// The KEK lives in protected files outside the database; root compromise with
// access to the KEK and process memory is outside this guarantee.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

const keyLen = 32

var (
	ErrNotFound      = errors.New("secret not found")
	ErrTampered      = errors.New("secret failed authentication (tampered or wrong key)")
	ErrNoActiveKey   = errors.New("vault has no active key")
	ErrKeyMissing    = errors.New("key material for version is not loaded")
	ErrKeyMismatch   = errors.New("key file does not match recorded check value")
	ErrInsecureKey   = errors.New("key file permissions are too open")
	checkPlain       = []byte("ngm-vault-kek-check-v1")
	validSecretTypes = map[string]bool{"totp": true, "tls_key": true, "backup_key": true, "cloudflare_token": true, "notification": true, "acme_account": true, "generic": true}
)

// Keyring holds loaded KEK versions.
type Keyring struct {
	mu   sync.RWMutex
	keys map[int][]byte
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{keys: map[int][]byte{}} }

// Add registers key material for a version (copied).
func (k *Keyring) Add(version int, key []byte) error {
	if len(key) != keyLen {
		return fmt.Errorf("KEK must be %d bytes", keyLen)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[version] = append([]byte(nil), key...)
	return nil
}

func (k *Keyring) get(v int) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	b, ok := k.keys[v]
	return b, ok
}

// KeyFileName is the on-disk name of KEK version v.
func KeyFileName(v int) string { return "kek-" + strconv.Itoa(v) + ".key" }

// LoadDir loads every kek-<n>.key file in dir. On Linux each file must not be
// accessible by "other" and must not be group-writable.
func LoadDir(dir string) (*Keyring, error) {
	kr := NewKeyring()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, "kek-") || !strings.HasSuffix(n, ".key") {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(n, "kek-"), ".key"))
		if err != nil || v <= 0 {
			continue
		}
		p := filepath.Join(dir, n)
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file", n)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o027 != 0 {
			return nil, fmt.Errorf("%w: %s has mode %v", ErrInsecureKey, n, st.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if err := kr.Add(v, b); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
	}
	return kr, nil
}

// GenerateKeyFile creates a new random KEK file for version v (mode 0440 on
// Linux; the installer sets ownership root:ngm-vault). It refuses to overwrite.
func GenerateKeyFile(dir string, v int) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, KeyFileName(v))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(p)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// Vault stores and retrieves secrets.
type Vault struct {
	db  *store.DB
	kr  *Keyring
	now func() time.Time
}

// New returns a Vault over db using the keyring.
func New(db *store.DB, kr *Keyring) *Vault { return &Vault{db: db, kr: kr, now: time.Now} }

func seal(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, ErrTampered
	}
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrTampered
	}
	return pt, nil
}

// aad binds a ciphertext to its record identity. Length-prefixed fields avoid
// ambiguity between e.g. ("ab","c") and ("a","bc").
func aad(purpose, id, typ, scope, name string, version int, kekVersion int) []byte {
	var b bytes.Buffer
	for _, s := range []string{purpose, id, typ, scope, name} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b.Write(l[:])
		b.WriteString(s)
	}
	var n [8]byte
	binary.BigEndian.PutUint32(n[:4], uint32(version))
	binary.BigEndian.PutUint32(n[4:], uint32(kekVersion))
	b.Write(n[:])
	return b.Bytes()
}

func checkValue(key []byte, v int) ([]byte, error) {
	nonce, ct, err := seal(key, checkPlain, []byte("kek-check|"+strconv.Itoa(v)))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func verifyCheck(key []byte, v int, cv []byte) bool {
	if len(cv) < 12 {
		return false
	}
	pt, err := open(key, cv[:12], cv[12:], []byte("kek-check|"+strconv.Itoa(v)))
	return err == nil && bytes.Equal(pt, checkPlain)
}

// Init registers key version 1 as active if the vault has no keys yet. It is
// idempotent: if version 1 already exists the loaded key must match it.
func (v *Vault) Init(ctx context.Context) error {
	return v.db.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM vault_key_versions").Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		key, ok := v.kr.get(1)
		if !ok {
			return fmt.Errorf("%w: 1", ErrKeyMissing)
		}
		cv, err := checkValue(key, 1)
		if err != nil {
			return err
		}
		now := store.FormatTime(v.now())
		_, err = tx.ExecContext(ctx, "INSERT INTO vault_key_versions(version,status,check_value,created_at,activated_at) VALUES(1,'active',?,?,?)", cv, now, now)
		return err
	})
}

// Verify checks that every non-retired key version recorded in the database is
// loaded and matches its check value. Services call this at startup.
func (v *Vault) Verify(ctx context.Context) error {
	rows, err := v.db.QueryContext(ctx, "SELECT version, check_value FROM vault_key_versions WHERE status <> 'retired'")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ver int
		var cv []byte
		if err := rows.Scan(&ver, &cv); err != nil {
			return err
		}
		key, ok := v.kr.get(ver)
		if !ok {
			return fmt.Errorf("%w: %d", ErrKeyMissing, ver)
		}
		if !verifyCheck(key, ver, cv) {
			return fmt.Errorf("%w: version %d", ErrKeyMismatch, ver)
		}
	}
	return rows.Err()
}

func (v *Vault) activeVersion(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, []byte, error) {
	var ver int
	err := q.QueryRowContext(ctx, "SELECT version FROM vault_key_versions WHERE status='active'").Scan(&ver)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, ErrNoActiveKey
	}
	if err != nil {
		return 0, nil, err
	}
	key, ok := v.kr.get(ver)
	if !ok {
		return 0, nil, fmt.Errorf("%w: %d", ErrKeyMissing, ver)
	}
	return ver, key, nil
}

// Ref identifies a secret.
type Ref struct {
	Type  string
	Scope string
	Name  string
}

func (r Ref) validate() error {
	if !validSecretTypes[r.Type] {
		return fmt.Errorf("unknown secret type %q", r.Type)
	}
	if r.Scope == "" || r.Name == "" || len(r.Scope) > 128 || len(r.Name) > 128 {
		return errors.New("secret scope and name are required (max 128 chars)")
	}
	return nil
}

func encrypt(id string, r Ref, version, kekVer int, kek, plaintext []byte) (wrapped, dekNonce, nonce, ct []byte, err error) {
	dek := make([]byte, keyLen)
	if _, err = rand.Read(dek); err != nil {
		return
	}
	defer clear(dek)
	nonce, ct, err = seal(dek, plaintext, aad("data", id, r.Type, r.Scope, r.Name, version, 0))
	if err != nil {
		return
	}
	dekNonce, wrapped, err = seal(kek, dek, aad("dek", id, r.Type, r.Scope, r.Name, version, kekVer))
	return
}

// PutTx creates or replaces a secret inside tx. It returns the secret ID.
func (v *Vault) PutTx(ctx context.Context, tx *sql.Tx, r Ref, plaintext []byte) (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	kekVer, kek, err := v.activeVersion(ctx, tx)
	if err != nil {
		return "", err
	}
	var id string
	var version int
	err = tx.QueryRowContext(ctx, "SELECT id, version FROM vault_secrets WHERE type=? AND scope=? AND name=?", r.Type, r.Scope, r.Name).Scan(&id, &version)
	now := store.FormatTime(v.now())
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id, version = ids.New(), 1
		w, dn, n, ct, err := encrypt(id, r, version, kekVer, kek, plaintext)
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO vault_secrets(id,type,scope,name,kek_version,wrapped_dek,dek_nonce,nonce,ciphertext,version,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, r.Type, r.Scope, r.Name, kekVer, w, dn, n, ct, version, now, now)
		return id, err
	case err != nil:
		return "", err
	default:
		version++
		w, dn, n, ct, err := encrypt(id, r, version, kekVer, kek, plaintext)
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `UPDATE vault_secrets SET kek_version=?, wrapped_dek=?, dek_nonce=?, nonce=?, ciphertext=?, version=?, updated_at=? WHERE id=?`,
			kekVer, w, dn, n, ct, version, now, id)
		return id, err
	}
}

// Put creates or replaces a secret.
func (v *Vault) Put(ctx context.Context, r Ref, plaintext []byte) (id string, err error) {
	err = v.db.Tx(ctx, func(tx *sql.Tx) error {
		id, err = v.PutTx(ctx, tx, r, plaintext)
		return err
	})
	return id, err
}

type row struct {
	id, typ, scope, name string
	kekVer, version      int
	wrapped, dn, n, ct   []byte
}

func (v *Vault) decryptRow(r row) ([]byte, error) {
	kek, ok := v.kr.get(r.kekVer)
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrKeyMissing, r.kekVer)
	}
	dek, err := open(kek, r.dn, r.wrapped, aad("dek", r.id, r.typ, r.scope, r.name, r.version, r.kekVer))
	if err != nil {
		return nil, ErrTampered
	}
	defer clear(dek)
	pt, err := open(dek, r.n, r.ct, aad("data", r.id, r.typ, r.scope, r.name, r.version, 0))
	if err != nil {
		return nil, ErrTampered
	}
	return pt, nil
}

const rowCols = "id,type,scope,name,kek_version,version,wrapped_dek,dek_nonce,nonce,ciphertext"

func scanRow(s interface{ Scan(...any) error }) (row, error) {
	var r row
	err := s.Scan(&r.id, &r.typ, &r.scope, &r.name, &r.kekVer, &r.version, &r.wrapped, &r.dn, &r.n, &r.ct)
	return r, err
}

// Get decrypts a secret by reference. Callers must keep the plaintext's
// lifetime short and never log or return it to clients.
func (v *Vault) Get(ctx context.Context, ref Ref) ([]byte, error) {
	r, err := scanRow(v.db.QueryRowContext(ctx, "SELECT "+rowCols+" FROM vault_secrets WHERE type=? AND scope=? AND name=?", ref.Type, ref.Scope, ref.Name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return v.decryptRow(r)
}

// GetByID decrypts a secret by ID.
func (v *Vault) GetByID(ctx context.Context, id string) ([]byte, error) {
	r, err := scanRow(v.db.QueryRowContext(ctx, "SELECT "+rowCols+" FROM vault_secrets WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return v.decryptRow(r)
}

// DeleteTx removes a secret.
func (v *Vault) DeleteTx(ctx context.Context, tx *sql.Tx, ref Ref) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM vault_secrets WHERE type=? AND scope=? AND name=?", ref.Type, ref.Scope, ref.Name)
	return err
}

// Metadata describes a secret without its value (no read-back, §10.1).
type Metadata struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Scope      string    `json:"scope"`
	Name       string    `json:"name"`
	Version    int       `json:"version"`
	KEKVersion int       `json:"kek_version"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// List returns secret metadata.
func (v *Vault) List(ctx context.Context) ([]Metadata, error) {
	rows, err := v.db.QueryContext(ctx, "SELECT id,type,scope,name,version,kek_version,updated_at FROM vault_secrets ORDER BY type,scope,name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Metadata
	for rows.Next() {
		var m Metadata
		var u string
		if err := rows.Scan(&m.ID, &m.Type, &m.Scope, &m.Name, &m.Version, &m.KEKVersion, &u); err != nil {
			return nil, err
		}
		m.UpdatedAt, _ = store.ParseTime(u)
		out = append(out, m)
	}
	return out, rows.Err()
}

// RotationStatus reports progress of a KEK rotation.
type RotationStatus struct {
	ActiveVersion int         `json:"active_version"`
	Versions      map[int]int `json:"secrets_per_version"`
}

// Rotate moves the vault to KEK version newVer (whose key must be loaded).
// It is journaled through the database itself and crash-resumable: the new
// version is first recorded as 'staged', each secret's DEK is re-wrapped in
// small transactions (the row's kek_version records progress), every secret is
// then verified to decrypt, and only then is newVer activated and the old
// version marked 'retiring' (retired later via Retire, after a grace period
// and backup). Re-running Rotate after a crash continues where it stopped.
func (v *Vault) Rotate(ctx context.Context, newVer int) (RotationStatus, error) {
	newKey, ok := v.kr.get(newVer)
	if !ok {
		return RotationStatus{}, fmt.Errorf("%w: %d", ErrKeyMissing, newVer)
	}
	// Stage.
	err := v.db.Tx(ctx, func(tx *sql.Tx) error {
		var status string
		var cv []byte
		err := tx.QueryRowContext(ctx, "SELECT status, check_value FROM vault_key_versions WHERE version=?", newVer).Scan(&status, &cv)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			var maxV int
			if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM vault_key_versions").Scan(&maxV); err != nil {
				return err
			}
			if newVer <= maxV {
				return fmt.Errorf("new KEK version must be greater than %d", maxV)
			}
			cv, err := checkValue(newKey, newVer)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO vault_key_versions(version,status,check_value,created_at) VALUES(?,'staged',?,?)", newVer, cv, store.FormatTime(v.now()))
			return err
		case err != nil:
			return err
		default:
			if !verifyCheck(newKey, newVer, cv) {
				return fmt.Errorf("%w: version %d", ErrKeyMismatch, newVer)
			}
			if status != "staged" && status != "active" {
				return fmt.Errorf("cannot rotate to version %d in status %s", newVer, status)
			}
			return nil
		}
	})
	if err != nil {
		return RotationStatus{}, err
	}
	// Rewrap in batches.
	for {
		n, err := v.rewrapBatch(ctx, newVer, newKey, 50)
		if err != nil {
			return RotationStatus{}, err
		}
		if n == 0 {
			break
		}
	}
	// Verify every secret decrypts under its recorded key.
	rows, err := v.db.QueryContext(ctx, "SELECT "+rowCols+" FROM vault_secrets")
	if err != nil {
		return RotationStatus{}, err
	}
	var all []row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return RotationStatus{}, err
		}
		all = append(all, r)
	}
	rows.Close()
	for _, r := range all {
		if r.kekVer != newVer {
			return RotationStatus{}, fmt.Errorf("secret %s still on KEK %d after rewrap", r.id, r.kekVer)
		}
		pt, err := v.decryptRow(r)
		if err != nil {
			return RotationStatus{}, fmt.Errorf("verify secret %s: %w", r.id, err)
		}
		clear(pt)
	}
	// Activate.
	err = v.db.Tx(ctx, func(tx *sql.Tx) error {
		now := store.FormatTime(v.now())
		if _, err := tx.ExecContext(ctx, "UPDATE vault_key_versions SET status='retiring' WHERE status='active' AND version<>?", newVer); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE vault_key_versions SET status='active', activated_at=COALESCE(activated_at, ?) WHERE version=?", now, newVer)
		return err
	})
	if err != nil {
		return RotationStatus{}, err
	}
	return v.Status(ctx)
}

func (v *Vault) rewrapBatch(ctx context.Context, newVer int, newKey []byte, limit int) (int, error) {
	n := 0
	err := v.db.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT "+rowCols+" FROM vault_secrets WHERE kek_version<>? LIMIT ?", newVer, limit)
		if err != nil {
			return err
		}
		var batch []row
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		for _, r := range batch {
			oldKek, ok := v.kr.get(r.kekVer)
			if !ok {
				return fmt.Errorf("%w: %d", ErrKeyMissing, r.kekVer)
			}
			dek, err := open(oldKek, r.dn, r.wrapped, aad("dek", r.id, r.typ, r.scope, r.name, r.version, r.kekVer))
			if err != nil {
				return fmt.Errorf("unwrap %s: %w", r.id, ErrTampered)
			}
			dn, w, err := seal(newKey, dek, aad("dek", r.id, r.typ, r.scope, r.name, r.version, newVer))
			clear(dek)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE vault_secrets SET kek_version=?, wrapped_dek=?, dek_nonce=? WHERE id=? AND kek_version=?",
				newVer, w, dn, r.id, r.kekVer); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// Retire marks a retiring KEK version retired once no secret uses it. The key
// file may then be removed by the operator after a verified backup.
func (v *Vault) Retire(ctx context.Context, ver int) error {
	return v.db.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM vault_secrets WHERE kek_version=?", ver).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("KEK %d still protects %d secret(s)", ver, n)
		}
		res, err := tx.ExecContext(ctx, "UPDATE vault_key_versions SET status='retired', retired_at=? WHERE version=? AND status='retiring'", store.FormatTime(v.now()), ver)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != 1 {
			return fmt.Errorf("KEK %d is not in retiring state", ver)
		}
		return nil
	})
}

// Status summarises key usage.
func (v *Vault) Status(ctx context.Context) (RotationStatus, error) {
	st := RotationStatus{Versions: map[int]int{}}
	_ = v.db.QueryRowContext(ctx, "SELECT version FROM vault_key_versions WHERE status='active'").Scan(&st.ActiveVersion)
	rows, err := v.db.QueryContext(ctx, "SELECT kek_version, count(*) FROM vault_secrets GROUP BY kek_version")
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, c int
		if err := rows.Scan(&k, &c); err != nil {
			return st, err
		}
		st.Versions[k] = c
	}
	return st, rows.Err()
}

// Fingerprint returns a short non-secret identifier for a key (for diagnostics).
func Fingerprint(key []byte) string {
	h := sha256.Sum256(append([]byte("ngm-kek-fp|"), key...))
	return fmt.Sprintf("%x", h[:6])
}

// SortedVersions lists loaded versions (diagnostics).
func (k *Keyring) SortedVersions() []int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]int, 0, len(k.keys))
	for v := range k.keys {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// KeyVersion is a vault_key_versions row.
type KeyVersion struct {
	Version     int
	Status      string
	CheckValue  []byte
	CreatedAt   string
	ActivatedAt sql.NullString
	RetiredAt   sql.NullString
}

// KeyVersions returns the key-version rows of this vault's database.
func (v *Vault) KeyVersions(ctx context.Context) ([]KeyVersion, error) {
	rows, err := v.db.QueryContext(ctx, "SELECT version,status,check_value,created_at,activated_at,retired_at FROM vault_key_versions ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyVersion
	for rows.Next() {
		var k KeyVersion
		if err := rows.Scan(&k.Version, &k.Status, &k.CheckValue, &k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RewrapAll moves every secret in tx's database from the source keyring to
// the destination's active key and replaces the key-version table with
// dstVersions. Used when restoring a backup onto a host with a different KEK.
// Plaintext secrets are never materialised: only DEKs are unwrapped/rewrapped.
func RewrapAll(ctx context.Context, tx *sql.Tx, src, dst *Keyring, dstVersions []KeyVersion) error {
	active := 0
	for _, k := range dstVersions {
		if k.Status == "active" {
			active = k.Version
		}
	}
	newKey, ok := dst.get(active)
	if !ok {
		return fmt.Errorf("%w: destination active version %d", ErrKeyMissing, active)
	}
	for _, k := range dstVersions {
		if dk, ok := dst.get(k.Version); ok && !verifyCheck(dk, k.Version, k.CheckValue) {
			return fmt.Errorf("%w: destination version %d", ErrKeyMismatch, k.Version)
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+rowCols+" FROM vault_secrets")
	if err != nil {
		return err
	}
	var all []row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	type rewrapped struct {
		id       string
		wrapped  []byte
		dekNonce []byte
	}
	var out []rewrapped
	for _, r := range all {
		oldKey, ok := src.get(r.kekVer)
		if !ok {
			return fmt.Errorf("%w: source version %d (secret %s)", ErrKeyMissing, r.kekVer, r.id)
		}
		dek, err := open(oldKey, r.dn, r.wrapped, aad("dek", r.id, r.typ, r.scope, r.name, r.version, r.kekVer))
		if err != nil {
			return fmt.Errorf("unwrap %s: %w", r.id, ErrTampered)
		}
		dn, w, err := seal(newKey, dek, aad("dek", r.id, r.typ, r.scope, r.name, r.version, active))
		clear(dek)
		if err != nil {
			return err
		}
		out = append(out, rewrapped{r.id, w, dn})
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM vault_key_versions"); err != nil {
		return err
	}
	for _, k := range dstVersions {
		if _, err := tx.ExecContext(ctx, "INSERT INTO vault_key_versions(version,status,check_value,created_at,activated_at,retired_at) VALUES(?,?,?,?,?,?)",
			k.Version, k.Status, k.CheckValue, k.CreatedAt, k.ActivatedAt, k.RetiredAt); err != nil {
			return err
		}
	}
	for _, o := range out {
		if _, err := tx.ExecContext(ctx, "UPDATE vault_secrets SET kek_version=?, wrapped_dek=?, dek_nonce=? WHERE id=?", active, o.wrapped, o.dekNonce, o.id); err != nil {
			return err
		}
	}
	return nil
}
