package monitor

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func hostPort(t *testing.T, u string) (string, int) {
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://"))
	n, _ := strconv.Atoi(p)
	return h, n
}

func ep(transport, host string, port int) *gateway.Endpoint {
	return &gateway.Endpoint{ID: "E1", Name: "e", Host: host, Port: port, Transport: transport, TLSVerify: true,
		Health: gateway.HealthPolicy{Path: "/health", IntervalSec: 5, TimeoutMS: 1000, ExpectStatus: "200-299"}}
}

func TestProbeHTTPStatuses(t *testing.T) {
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(code)
	}))
	defer srv.Close()
	h, p := hostPort(t, srv.URL)
	g := Guard{APIPort: 9999}
	for c, want := range map[int]string{200: Healthy, 302: Degraded, 404: Degraded, 503: Down} {
		code = c
		if r := Probe(context.Background(), g, ep("http", h, p)); r.Status != want {
			t.Errorf("HTTP %d → %s (%s), want %s", c, r.Status, r.Detail, want)
		}
	}
	// Redirects are never followed.
	code = 302
	if r := Probe(context.Background(), g, ep("http", h, p)); !strings.Contains(r.Detail, "302") {
		t.Fatalf("redirect followed? %+v", r)
	}
}

func TestProbeTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	h, p := hostPort(t, srv.URL)
	e := ep("https", h, p)
	e.Health.ExpectStatus = "200-399"
	if r := Probe(context.Background(), Guard{}, e); r.Status != Down || !strings.Contains(r.Detail, "certificate") {
		t.Fatalf("self-signed backend with verification on: %+v", r)
	}
	e.TLSVerify = false
	if r := Probe(context.Background(), Guard{}, e); r.Status != Healthy {
		t.Fatalf("verification off: %+v", r)
	}
}

func TestProbeTCP(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	h, p := hostPort(t, "http://"+ln.Addr().String())
	if r := Probe(context.Background(), Guard{}, ep("tcp", h, p)); r.Status != Healthy {
		t.Fatalf("%+v", r)
	}
	ln.Close()
	if r := Probe(context.Background(), Guard{}, ep("tcp", h, p)); r.Status != Down {
		t.Fatalf("closed port: %+v", r)
	}
}

func TestSSRFGuard(t *testing.T) {
	g := Guard{APIPort: 9999, Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "rebind.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("169.254.169.254")}, nil
		case "ok.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return nil, nil
	}}
	bad := []struct {
		h string
		p int
	}{{"169.254.169.254", 80}, {"rebind.example", 80}, {"127.0.42.1", 10001}, {"127.0.0.1", 9999}, {"0.0.0.0", 80}, {"fe80::1", 80}, {"nxdomain.example", 80}}
	for _, b := range bad {
		if _, err := g.Target(context.Background(), b.h, b.p); err == nil {
			t.Errorf("%s:%d allowed", b.h, b.p)
		}
	}
	ap, err := g.Target(context.Background(), "ok.example", 443)
	if err != nil || ap.String() != "93.184.216.34:443" {
		t.Fatalf("%v %v", ap, err)
	}
	// Probe result for a blocked target is Unknown, not Down/Healthy.
	if r := Probe(context.Background(), g, ep("http", "169.254.169.254", 80)); r.Status != Unknown {
		t.Fatalf("%+v", r)
	}
}

func TestMonitorAntiFlapAndStaleness(t *testing.T) {
	ctx := context.Background()
	db := storetest.New(t)
	kr := vault.NewKeyring()
	k := make([]byte, 32)
	rand.Read(k)
	kr.Add(1, k)
	v := vault.New(db, kr)
	v.Init(ctx)
	gw := gwstore.New(db, v, audit.New(db))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	h, p := hostPort(t, "http://"+ln.Addr().String())
	e, err := gw.SaveEndpoint(ctx, nil, &gateway.Endpoint{Name: "t", Host: h, Port: p, Transport: "tcp"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := &Monitor{DB: db, GW: gw}
	m.Tick(ctx)
	hs, _ := Latest(ctx, db, []*gateway.Endpoint{e})
	if hs[0].Status != Healthy {
		t.Fatalf("%+v", hs[0])
	}
	ln.Close()
	m.next[e.ID] = time.Time{}
	m.Tick(ctx)
	hs, _ = Latest(ctx, db, []*gateway.Endpoint{e})
	if hs[0].Status != Degraded {
		t.Fatalf("first failure should be degraded (anti-flap): %+v", hs[0])
	}
	m.next[e.ID] = time.Time{}
	m.Tick(ctx)
	hs, _ = Latest(ctx, db, []*gateway.Endpoint{e})
	if hs[0].Status != Down {
		t.Fatalf("second failure should be down: %+v", hs[0])
	}
	// Stale evidence → Unknown.
	db.ExecContext(ctx, "UPDATE health_samples SET observed_at='2020-01-01T00:00:00Z'")
	hs, _ = Latest(ctx, db, []*gateway.Endpoint{e})
	if hs[0].Status != Unknown || !hs[0].Stale {
		t.Fatalf("stale: %+v", hs[0])
	}
}
