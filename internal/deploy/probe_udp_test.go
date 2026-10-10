package deploy

import (
	"context"
	"net"
	"runtime"
	"testing"
)

func TestListeningUDP(t *testing.T) {
	var p NetProber
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp sockets unavailable: %v", err)
	}
	addr := pc.LocalAddr().String()
	if !p.ListeningUDP(context.Background(), addr) {
		t.Fatalf("a bound UDP socket at %s must be reported as listening", addr)
	}
	pc.Close()
	if runtime.GOOS != "linux" {
		t.Skip("closed-port detection relies on Linux delivering ICMP port-unreachable as ECONNREFUSED")
	}
	if p.ListeningUDP(context.Background(), addr) {
		t.Fatalf("a closed UDP port %s must not be reported as listening", addr)
	}
}
