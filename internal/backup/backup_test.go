package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

var fastKDF = func() KDF { k := DefaultKDF(); k.MemoryKiB, k.Time, k.Threads = 8*1024, 1, 1; return k }

const pass = "correct horse battery staple 2026"

type host struct {
	db   *store.DB
	keys string
	kr   *vault.Keyring
	v    *vault.Vault
}

func newHost(t *testing.T) *host {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	os.MkdirAll(keys, 0o700)
	if _, err := vault.GenerateKeyFile(keys, 1); err != nil {
		t.Fatal(err)
	}
	kr, err := vault.LoadDir(keys)
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.New(t)
	v := vault.New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &host{db, keys, kr, v}
}

func makeArchive(t *testing.T, h *host, kdf KDF) []byte {
	key, _ := kdf.Derive(pass)
	var buf bytes.Buffer
	if _, err := Create(context.Background(), &buf, key, kdf, Sources{DB: h.db, KeysDir: h.keys, TmpDir: t.TempDir(), Hostname: "src", Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTripAndCrossHostRekey(t *testing.T) {
	ctx := context.Background()
	src := newHost(t)
	src.v.Put(ctx, vault.Ref{Type: "tls_key", Scope: "cert:X", Name: "key"}, []byte("PRIVATE KEY MATERIAL"))
	src.v.Put(ctx, vault.Ref{Type: "totp", Scope: "user:U", Name: "seed"}, []byte("JBSWY3DP"))
	arch := makeArchive(t, src, fastKDF())
	if bytes.Contains(arch, []byte("PRIVATE KEY MATERIAL")) || bytes.Contains(arch, []byte("SQLite format")) {
		t.Fatal("plaintext visible in archive")
	}
	dir := filepath.Join(t.TempDir(), "x")
	x, err := Extract(bytes.NewReader(arch), pass, dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if x.Manifest.Counts["vault_secrets"] != 2 || x.Manifest.Hostname != "src" || len(x.Manifest.KEKVersions) != 1 {
		t.Fatalf("%+v", x.Manifest)
	}
	// "New host": different KEK, its own key-version rows. The source KEK
	// comes only from the archive.
	dst := newHost(t)
	srcKR, err := vault.LoadDir(x.KeysDir())
	if err != nil {
		t.Fatal(err)
	}
	vers, _ := dst.v.KeyVersions(ctx)
	if err := Rekey(ctx, x.DBPath(), srcKR, dst.kr, vers); err != nil {
		t.Fatal(err)
	}
	rdb, _ := store.Open(x.DBPath(), store.Options{})
	defer rdb.Close()
	rv := vault.New(rdb, dst.kr)
	if err := rv.Verify(ctx); err != nil {
		t.Fatalf("restored vault does not verify with destination KEK: %v", err)
	}
	got, err := rv.Get(ctx, vault.Ref{Type: "tls_key", Scope: "cert:X", Name: "key"})
	if err != nil || string(got) != "PRIVATE KEY MATERIAL" {
		t.Fatalf("%q %v", got, err)
	}
	// The source KEK is no longer needed.
	if _, err := vault.New(rdb, srcKR).Get(ctx, vault.Ref{Type: "totp", Scope: "user:U", Name: "seed"}); err == nil {
		t.Fatal("restored secrets still readable with the source KEK")
	}
}

func TestWrongPassphraseAndTampering(t *testing.T) {
	h := newHost(t)
	arch := makeArchive(t, h, fastKDF())
	ex := func(b []byte, p string) error {
		_, err := Extract(bytes.NewReader(b), p, filepath.Join(t.TempDir(), "x"), 0)
		return err
	}
	if err := ex(arch, "wrong passphrase!"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	hdrEnd := bytes.IndexByte(arch[len(magic):], '\n') + len(magic) + 1
	cases := map[string][]byte{}
	flip := append([]byte(nil), arch...)
	flip[len(flip)-20] ^= 1
	cases["bit flip in body"] = flip
	cases["truncated (final chunk dropped)"] = arch[:len(arch)-40]
	cases["trailing data"] = append(append([]byte(nil), arch...), []byte("extra")...)
	hdr := append([]byte(nil), arch...)
	i := bytes.Index(hdr[:hdrEnd], []byte(`"hostname":"src"`))
	copy(hdr[i:], []byte(`"hostname":"evl"`))
	cases["header altered"] = hdr
	cases["not a backup"] = []byte("hello world\n")
	for name, b := range cases {
		if err := ex(b, pass); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRejectsUnsafeEntries(t *testing.T) {
	kdf := fastKDF()
	key, _ := kdf.Derive(pass)
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key, Header{KDF: kdf})
	tw := tar.NewWriter(w)
	for _, name := range []string{"../../etc/cron.d/evil"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 3})
		tw.Write([]byte("bad"))
	}
	tw.Close()
	w.Close()
	dir := filepath.Join(t.TempDir(), "x")
	_, err := Extract(&buf, pass, dir, 0)
	if err == nil || !strings.Contains(err.Error(), "unexpected entry") {
		t.Fatalf("traversal entry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "etc")); err == nil {
		t.Fatal("wrote outside the extraction dir")
	}
}

func TestLargeStreamChunking(t *testing.T) {
	kdf := fastKDF()
	key, _ := kdf.Derive(pass)
	data := make([]byte, 3*chunkSize+123)
	rand.Read(data)
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key, Header{KDF: kdf})
	w.Write(data[:1000])
	w.Write(data[1000:])
	w.Close()
	r, _, err := NewReader(bufioReader(&buf), pass)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("round trip mismatch: %v", err)
	}
}

func bufioReader(b *bytes.Buffer) *bufio.Reader { return bufio.NewReader(b) }
