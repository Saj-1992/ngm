//go:build linux

package ipc

import (
	"context"
	"os"
	"testing"
)

// TestRealPeerCred verifies kernel-attested credentials reach the handler.
func TestRealPeerCred(t *testing.T) {
	var got Peer
	p := start(t, func(_ context.Context, peer Peer, _ Request) (any, error) { got = peer; return "ok", nil }, nil)
	if err := Call(context.Background(), p, Request{Op: "ping"}, nil); err != nil {
		t.Fatal(err)
	}
	if got.UID != uint32(os.Getuid()) || got.PID != int32(os.Getpid()) {
		t.Fatalf("peer %+v, want uid=%d pid=%d", got, os.Getuid(), os.Getpid())
	}
}
