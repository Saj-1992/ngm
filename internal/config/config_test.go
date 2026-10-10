package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAreLoopback(t *testing.T) {
	c := Default()
	if c.API.Listen != "127.0.0.1:9999" {
		t.Fatalf("default listen %q", c.API.Listen)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:9999", ":9999", "[::]:9999", "10.0.0.5:9999", "localhost:9999", "127.0.0.1:0", "127.0.0.1:99999"} {
		if err := ValidateLoopbackListen(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
	for _, a := range []string{"127.0.0.1:9999", "[::1]:9999", "127.0.0.2:8080"} {
		if err := ValidateLoopbackListen(a); err != nil {
			t.Errorf("%q rejected: %v", a, err)
		}
	}
}

func TestLoadRejectsUnknownFieldsAndBadOrigin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ngm.json")
	os.WriteFile(p, []byte(`{"api":{"listen":"127.0.0.1:9999"},"shell":"rm"}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	os.WriteFile(p, []byte(`{"api":{"listen":"127.0.0.1:9999","public_origin":"http://x.example"}}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("http origin accepted")
	}
	os.WriteFile(p, []byte(`{"api":{"listen":"127.0.0.1:9999","public_origin":"https://ngm.example.com"}}`), 0o600)
	c, err := Load(p)
	if err != nil || c.API.PublicOrigin != "https://ngm.example.com" || c.Paths.StateDir != "/var/lib/ngm" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatalf("missing file should give defaults: %v", err)
	}
}

func TestValidatePublicPath(t *testing.T) {
	for _, ok := range []string{"", "/a1b2c3d4", "/admin/panel", "/x-y_z~1"} {
		if err := ValidatePublicPath(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"admin", "/admin/", "/", "/api", "/assets", "/.well-known", "/a b", "/a/b/c/d/e", "/..", "//x"} {
		if err := ValidatePublicPath(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
