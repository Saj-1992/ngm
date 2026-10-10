package locks

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Manager, *fakeClock) {
	m := NewManager(storetest.New(t))
	c := &fakeClock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	m.SetClock(c.now)
	return m, c
}

func TestCanonicalOrder(t *testing.T) {
	got, err := Canonical([]Resource{Firewall, GatewayConfig, SystemUpdate})
	if err != nil {
		t.Fatal(err)
	}
	want := []Resource{SystemUpdate, GatewayConfig, Firewall}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if _, err := Canonical([]Resource{"rm -rf"}); !errors.Is(err, ErrBadResource) {
		t.Fatal("unknown resource accepted")
	}
	if _, err := Canonical([]Resource{Firewall, Firewall}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestMutualExclusionAndAllOrNothing(t *testing.T) {
	ctx := context.Background()
	m, _ := setup(t)
	a, err := m.Acquire(ctx, "jobA", "w1", []Resource{GatewayConfig}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Acquire(ctx, "jobB", "w2", []Resource{Certificate, GatewayConfig}, 30*time.Second)
	var he *HeldError
	if !errors.As(err, &he) || he.HolderJob != "jobA" {
		t.Fatalf("expected HeldError by jobA, got %v", err)
	}
	// All-or-nothing: Certificate must not have been taken by jobB.
	c, err := m.Acquire(ctx, "jobC", "w3", []Resource{Certificate}, 30*time.Second)
	if err != nil {
		t.Fatalf("certificate should be free: %v", err)
	}
	if c.Token <= a.Token {
		t.Fatalf("tokens not monotonic: %d <= %d", c.Token, a.Token)
	}
}

func TestExpiryTakeoverFencesStaleWorker(t *testing.T) {
	ctx := context.Background()
	m, clk := setup(t)
	old, err := m.Acquire(ctx, "jobA", "w1", []Resource{GatewayConfig, Firewall}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(31 * time.Second) // worker A stalls past its lease
	nw, err := m.Acquire(ctx, "jobB", "w2", []Resource{GatewayConfig}, 30*time.Second)
	if err != nil {
		t.Fatalf("takeover of expired lease: %v", err)
	}
	if err := m.Heartbeat(ctx, old, 30*time.Second); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale heartbeat: %v", err)
	}
	err = m.db.Tx(ctx, func(tx *sql.Tx) error { return m.FenceFunc(old)(ctx, tx) })
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale writer must be fenced: %v", err)
	}
	err = m.db.Tx(ctx, func(tx *sql.Tx) error { return m.FenceFunc(nw)(ctx, tx) })
	if err != nil {
		t.Fatalf("current holder fence: %v", err)
	}
	// Stale release must not drop the new holder's lease.
	if err := m.Release(ctx, old); err != nil {
		t.Fatal(err)
	}
	hs, _ := m.List(ctx)
	found := false
	for _, h := range hs {
		if h.Resource == GatewayConfig && h.JobID == "jobB" {
			found = true
		}
	}
	if !found {
		t.Fatalf("new holder lost lease after stale release: %+v", hs)
	}
}

func TestHeartbeatExtendsAndReleaseFrees(t *testing.T) {
	ctx := context.Background()
	m, clk := setup(t)
	l, _ := m.Acquire(ctx, "jobA", "w1", []Resource{BackupRestore}, 30*time.Second)
	for i := 0; i < 5; i++ {
		clk.advance(20 * time.Second)
		if err := m.Heartbeat(ctx, l, 30*time.Second); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
	}
	if _, err := m.Acquire(ctx, "jobB", "w2", []Resource{BackupRestore}, time.Second); !errors.Is(err, ErrHeld) {
		t.Fatalf("still held after heartbeats: %v", err)
	}
	if err := m.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Acquire(ctx, "jobB", "w2", []Resource{BackupRestore}, time.Second); err != nil {
		t.Fatalf("after release: %v", err)
	}
	// A released lease's fence is stale.
	err := m.db.Tx(ctx, func(tx *sql.Tx) error { return m.CheckFence(ctx, tx, BackupRestore, l.Token) })
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("released token: %v", err)
	}
}

func TestFenceExpiresWithoutHeartbeat(t *testing.T) {
	ctx := context.Background()
	m, clk := setup(t)
	l, _ := m.Acquire(ctx, "jobA", "w1", []Resource{Firewall}, 10*time.Second)
	clk.advance(11 * time.Second)
	err := m.db.Tx(ctx, func(tx *sql.Tx) error { return m.CheckFence(ctx, tx, Firewall, l.Token) })
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired lease must fail fencing even without takeover: %v", err)
	}
}
