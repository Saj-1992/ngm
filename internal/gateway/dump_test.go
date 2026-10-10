package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpFixture writes the compiled fixture to $NGM_DUMP_DIR for
// validation with a real `nginx -t` (dev tooling; skipped otherwise).
func TestDumpFixture(t *testing.T) {
	dir := os.Getenv("NGM_DUMP_DIR")
	if dir == "" {
		t.Skip("NGM_DUMP_DIR not set")
	}
	mdl := fixture()
	mdl.Endpoints[5].Host = "127.0.0.1" // no DNS during nginx -t
	mdl.Routes = append(mdl.Routes, Route{ID: "R10", Name: "rej", ListenerID: "LTCP2", Protocol: ProtoTCP, DestKind: DestReject, Enabled: true})
	mdl.Listeners = append(mdl.Listeners, Listener{ID: "LTCP2", Name: "tcp-reject", Kind: KindStream, Address: "::", Port: 2223, Family: "ipv6", Enabled: true})
	p := mustValid(t, mdl)
	out := compile(t, p)
	for name, b := range out.Files {
		f := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
