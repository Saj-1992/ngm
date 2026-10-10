package release

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, channel, keyID string) (dir string, raw []byte, priv ed25519.PrivateKey, keys []Key) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "ngm-linux-amd64"), []byte("amd64 binary"), 0o755)
	os.WriteFile(filepath.Join(dir, "ngm-linux-arm64"), []byte("arm64 binary"), 0o755)
	raw, err := Build(dir, Manifest{Version: "1.2.3", Channel: channel, KeyID: keyID, DBSchema: 6, APIVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644)
	os.WriteFile(filepath.Join(dir, "manifest.sig"), Sign(priv, raw), 0o644)
	ch := []string{"stable", "beta"}
	if strings.HasPrefix(keyID, "dev-") {
		ch = []string{"development"}
	}
	return dir, raw, priv, []Key{{ID: keyID, Channels: ch, Pub: pub}}
}

func TestVerifyAndDigest(t *testing.T) {
	dir, _, _, keys := fixture(t, "stable", "pub-1")
	m, _, err := LoadDir(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.ArtifactFor("arm64")
	if err != nil || CheckFile(filepath.Join(dir, a.File), a) != nil {
		t.Fatalf("artifact: %v", err)
	}
	// Tampered binary → digest error.
	os.WriteFile(filepath.Join(dir, "ngm-linux-arm64"), []byte("evil binary!"), 0o755)
	if err := CheckFile(filepath.Join(dir, a.File), a); !errors.Is(err, ErrDigest) {
		t.Fatalf("tampered binary accepted: %v", err)
	}
}

func TestFailClosed(t *testing.T) {
	dir, raw, _, keys := fixture(t, "stable", "pub-1")
	sig, _ := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	// One flipped byte in the manifest.
	bad := append([]byte{}, raw...)
	bad[len(bad)/2] ^= 1
	if _, err := Verify(bad, sig, keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	// A different key (e.g. one shipped next to the artifacts) is not trusted.
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(raw, sig, []Key{{ID: "pub-1", Channels: []string{"stable"}, Pub: other}}); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	// Missing/garbage signature.
	for _, s := range [][]byte{nil, []byte("not base64"), []byte("AAAA")} {
		if _, err := Verify(raw, s, keys); !errors.Is(err, ErrSignature) {
			t.Fatalf("sig %q: %v", s, err)
		}
	}
	os.Remove(filepath.Join(dir, "manifest.sig"))
	if _, _, err := LoadDir(dir, keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("missing sig: %v", err)
	}
}

func TestChannelAndKeyID(t *testing.T) {
	// A development key cannot sign a stable release.
	_, raw, priv, keys := fixture(t, "stable", "dev-x")
	if _, err := Verify(raw, Sign(priv, raw), keys); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("dev key signed stable: %v", err)
	}
	// Manifest naming another key id than the signer.
	_, raw, priv, keys = fixture(t, "stable", "pub-1")
	keys[0].ID = "pub-2"
	if _, err := Verify(raw, Sign(priv, raw), keys); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("key id mismatch: %v", err)
	}
	// Unknown fields are rejected (no silent extension).
	_, raw, priv, keys = fixture(t, "stable", "pub-1")
	raw2 := []byte(strings.Replace(string(raw), `"schema": 1,`, `"schema": 1, "postinstall": "curl x|sh",`, 1))
	if _, err := Verify(raw2, Sign(priv, raw2), keys); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestPinnedKeysLoad(t *testing.T) {
	ks, err := Trusted()
	if err != nil || len(ks) == 0 {
		t.Fatalf("pinned keys: %v %d", err, len(ks))
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		w    int
	}{{"1.0.0", "1.0.1", -1}, {"1.10.0", "1.9.9", 1}, {"1.0.0-beta", "1.0.0", -1}, {"0.7.0-dev", "0.6.7-dev", 1}, {"1.0.0", "1.0.0", 0}, {"0.8.0-rc.10", "0.8.0-rc.9", 1}, {"0.8.0-rc.9", "0.8.0-rc.10", -1}, {"1.0.0-alpha", "1.0.0-alpha.1", -1}, {"1.0.0-1", "1.0.0-alpha", -1}, {"0.8.0-rc.2", "0.8.0-dev", 1}} {
		if g := CompareVersions(c.a, c.b); g != c.w {
			t.Errorf("%s vs %s = %d", c.a, c.b, g)
		}
	}
}
