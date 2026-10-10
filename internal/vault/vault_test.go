package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

func key() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func newVault(t *testing.T) (*Vault, *store.DB) {
	db := storetest.New(t)
	kr := NewKeyring()
	kr.Add(1, key())
	v := New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return v, db
}

var ref = Ref{Type: "totp", Scope: "user:U1", Name: "seed"}

func TestRoundTripAndReplace(t *testing.T) {
	ctx := context.Background()
	v, db := newVault(t)
	if _, err := v.Put(ctx, ref, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, ref)
	if err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%q %v", got, err)
	}
	// Plaintext must not be stored anywhere in the DB row.
	var ct, w []byte
	db.QueryRowContext(ctx, "SELECT ciphertext, wrapped_dek FROM vault_secrets").Scan(&ct, &w)
	if bytes.Contains(ct, []byte("JBSWY3")) || bytes.Contains(w, []byte("JBSWY3")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	if _, err := v.Put(ctx, ref, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, _ = v.Get(ctx, ref)
	if string(got) != "new" {
		t.Fatalf("replace: %q", got)
	}
	if _, err := v.Get(ctx, Ref{Type: "totp", Scope: "user:U2", Name: "seed"}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestTamperDetection(t *testing.T) {
	ctx := context.Background()
	cases := map[string]string{
		"nonce swap":       "UPDATE vault_secrets SET nonce = randomblob(12)",
		"scope rebinding":  "UPDATE vault_secrets SET scope='user:ATTACKER'",
		"version rollback": "UPDATE vault_secrets SET version = version + 1",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			v, db := newVault(t)
			id, _ := v.Put(ctx, ref, []byte("secret-value"))
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
			if _, err := v.GetByID(ctx, id); !errors.Is(err, ErrTampered) {
				t.Fatalf("got %v, want ErrTampered", err)
			}
		})
	}
	for _, col := range []string{"ciphertext", "wrapped_dek", "dek_nonce"} {
		t.Run(col+" bit flip", func(t *testing.T) {
			v, db := newVault(t)
			id, _ := v.Put(ctx, ref, []byte("secret-value"))
			var b []byte
			db.QueryRowContext(ctx, "SELECT "+col+" FROM vault_secrets WHERE id=?", id).Scan(&b)
			b[len(b)/2] ^= 0x01
			if _, err := db.ExecContext(ctx, "UPDATE vault_secrets SET "+col+"=? WHERE id=?", b, id); err != nil {
				t.Fatal(err)
			}
			if _, err := v.GetByID(ctx, id); !errors.Is(err, ErrTampered) {
				t.Fatalf("got %v, want ErrTampered", err)
			}
		})
	}
	t.Run("row swap between secrets", func(t *testing.T) {
		v, db := newVault(t)
		a, _ := v.Put(ctx, Ref{"totp", "user:A", "seed"}, []byte("aaaa"))
		b, _ := v.Put(ctx, Ref{"totp", "user:B", "seed"}, []byte("bbbb"))
		// Copy B's ciphertext material into A's row.
		_, err := db.ExecContext(ctx, `UPDATE vault_secrets SET (wrapped_dek,dek_nonce,nonce,ciphertext) =
			(SELECT wrapped_dek,dek_nonce,nonce,ciphertext FROM vault_secrets WHERE id=?) WHERE id=?`, b, a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.GetByID(ctx, a); !errors.Is(err, ErrTampered) {
			t.Fatalf("swapped ciphertext accepted: %v", err)
		}
	})
}

func TestWrongKEKFailsVerify(t *testing.T) {
	ctx := context.Background()
	v, db := newVault(t)
	v.Put(ctx, ref, []byte("x"))
	kr2 := NewKeyring()
	kr2.Add(1, key())
	v2 := New(db, kr2)
	if err := v2.Verify(ctx); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("verify with wrong key: %v", err)
	}
	if _, err := v2.Get(ctx, ref); !errors.Is(err, ErrTampered) {
		t.Fatalf("decrypt with wrong key: %v", err)
	}
	if err := New(db, NewKeyring()).Verify(ctx); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestRotationIsResumable(t *testing.T) {
	ctx := context.Background()
	v, db := newVault(t)
	for i := 0; i < 120; i++ {
		v.Put(ctx, Ref{"generic", "global", "s" + string(rune('A'+i%26)) + string(rune('a'+i/26))}, []byte{byte(i)})
	}
	v.kr.Add(2, key())
	// Simulate a crash mid-rotation: stage + rewrap one batch only.
	if _, err := v.Rotate(ctx, 7); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("rotate to unloaded key: %v", err)
	}
	// Manually run a partial rotation.
	cv, _ := checkValue(mustKey(v, 2), 2)
	db.ExecContext(ctx, "INSERT INTO vault_key_versions(version,status,check_value,created_at) VALUES(2,'staged',?,?)", cv, store.FormatTime(v.now()))
	n, err := v.rewrapBatch(ctx, 2, mustKey(v, 2), 50)
	if err != nil || n != 50 {
		t.Fatalf("partial rewrap n=%d err=%v", n, err)
	}
	st, _ := v.Status(ctx)
	if st.ActiveVersion != 1 || st.Versions[1] != 70 || st.Versions[2] != 50 {
		t.Fatalf("mid-rotation state %+v", st)
	}
	// Mixed state must still decrypt everything.
	for _, m := range mustList(t, v) {
		if _, err := v.GetByID(ctx, m.ID); err != nil {
			t.Fatalf("mid-rotation decrypt %s: %v", m.Name, err)
		}
	}
	// Resume.
	st, err = v.Rotate(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if st.ActiveVersion != 2 || st.Versions[2] != 120 || st.Versions[1] != 0 {
		t.Fatalf("after rotation %+v", st)
	}
	// New writes use KEK 2; old key no longer needed.
	v.Put(ctx, ref, []byte("after"))
	delete(v.kr.keys, 1)
	for _, m := range mustList(t, v) {
		if _, err := v.GetByID(ctx, m.ID); err != nil {
			t.Fatalf("after retirement of key 1, %s: %v", m.Name, err)
		}
	}
	if err := v.Retire(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(ctx); err != nil {
		t.Fatalf("verify after retire: %v", err)
	}
}

func mustKey(v *Vault, n int) []byte { k, _ := v.kr.get(n); return k }
func mustList(t *testing.T, v *Vault) []Metadata {
	l, err := v.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	k, err := GenerateKeyFile(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKeyFile(dir, 1); err == nil {
		t.Fatal("overwrote existing KEK")
	}
	kr, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := kr.get(1)
	if !ok || !bytes.Equal(got, k) {
		t.Fatal("loaded key differs")
	}
	if runtime.GOOS != "windows" {
		p := filepath.Join(dir, KeyFileName(2))
		os.WriteFile(p, key(), 0o644)
		if _, err := LoadDir(dir); !errors.Is(err, ErrInsecureKey) {
			t.Fatalf("world-readable key accepted: %v", err)
		}
	}
}

func TestRejectsUnknownTypeAndNoLeakInErrors(t *testing.T) {
	v, _ := newVault(t)
	if _, err := v.Put(context.Background(), Ref{"shell", "x", "y"}, []byte("p")); err == nil {
		t.Fatal("unknown type accepted")
	}
	_, err := v.Put(context.Background(), Ref{"generic", "", ""}, []byte("hunter2"))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err=%v", err)
	}
}
