package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/config"
)

func devConfig(t *testing.T) string {
	root := t.TempDir()
	c := config.Default()
	c.Paths = config.RootedPaths(root)
	os.MkdirAll(c.Paths.StateDir, 0o750)
	b, _ := json.Marshal(c)
	p := filepath.Join(root, "ngm.json")
	os.WriteFile(p, b, 0o600)
	return p
}

func TestCLIMigrateCheckVerify(t *testing.T) {
	cfg := devConfig(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--config", cfg, "migrate"}, &out, &errb); code != 0 {
		t.Fatalf("migrate: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "schema version") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := run([]string{"--config", cfg, "db", "check"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "ok") {
		t.Fatalf("db check: %d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"--config", cfg, "audit", "verify"}, &out, &errb); code != 0 {
		t.Fatalf("audit verify: %d %s", code, errb.String())
	}
}

func TestAPIRefusesUnmigratedDB(t *testing.T) {
	cfg := devConfig(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--config", cfg, "api"}, &out, &errb); code == 0 {
		t.Fatal("api started on unmigrated database")
	}
	if !strings.Contains(errb.String(), "ngm migrate") {
		t.Fatalf("unhelpful error: %s", errb.String())
	}
}
