package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/sse"
	storetest "github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func TestBasePathMount(t *testing.T) {
	db := storetest.New(t)
	cfg := config.Default()
	cfg.API.PublicOrigin = "https://ngm.example.com:9443"
	cfg.API.PublicPath = "/a1b2c3d4"
	ui := fstest.MapFS{
		"index.html":      {Data: []byte(`<!doctype html><base href="__NGM_BASE__"><meta name="ngm-csp-nonce" content="__NGM_CSP_NONCE__">`)},
		"assets/app-1.js": {Data: []byte("x")},
	}
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	v := vault.New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	al := audit.New(db)
	as := auth.NewService(db, v, al, auth.DefaultPolicy())
	srv := New(Deps{DB: db, Jobs: jobs.NewJournal(db), Broker: sse.NewBroker(db), Config: cfg, UI: ui, Auth: as, Vault: v, Audit: al, GW: gwstore.New(db, v, al)})

	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	// Mounted index: base rewritten to the panel path.
	if w := get("/a1b2c3d4/"); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/a1b2c3d4/"`) {
		t.Fatalf("mounted index: %d %q", w.Code, w.Body.String())
	}
	// Deep SPA link under the mount still serves the shell with the right base.
	if w := get("/a1b2c3d4/gateway/routes"); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/a1b2c3d4/"`) {
		t.Fatalf("mounted deep link: %d", w.Code)
	}
	// API reachable under the mount.
	if w := get("/a1b2c3d4/api/v1/system/health"); w.Code != 200 {
		t.Fatalf("mounted API health: %d", w.Code)
	}
	// Asset under the mount.
	if w := get("/a1b2c3d4/assets/app-1.js"); w.Code != 200 || w.Body.String() != "x" {
		t.Fatalf("mounted asset: %d %q", w.Code, w.Body.String())
	}
	// No trailing slash → redirect to the slash form.
	if w := get("/a1b2c3d4"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/a1b2c3d4/" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	// Bare root still works (SSH tunnel), base is "/".
	if w := get("/"); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/"`) {
		t.Fatalf("bare index: %d %q", w.Code, w.Body.String())
	}
	if w := get("/api/v1/system/health"); w.Code != 200 {
		t.Fatalf("bare API health: %d", w.Code)
	}
}
