package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, h Handler, pc func(net.Conn) (Peer, error)) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{Handler: h, PeerCred: pc, Timeout: 2 * time.Second}
	go s.Serve(ctx, ln)
	return p
}

func fixedPeer(uid uint32) func(net.Conn) (Peer, error) {
	return func(net.Conn) (Peer, error) { return Peer{UID: uid}, nil }
}

func TestRoundTripAndPeerPassed(t *testing.T) {
	var seen Peer
	p := start(t, func(_ context.Context, peer Peer, req Request) (any, error) {
		seen = peer
		var a map[string]int
		json.Unmarshal(req.Args, &a)
		return map[string]int{"sum": a["a"] + a["b"]}, nil
	}, fixedPeer(1234))
	var out map[string]int
	if err := Call(context.Background(), p, Request{Op: "math.add", Args: json.RawMessage(`{"a":2,"b":3}`)}, &out); err != nil {
		t.Fatal(err)
	}
	if out["sum"] != 5 || seen.UID != 1234 {
		t.Fatalf("out=%v peer=%+v", out, seen)
	}
}

func TestStructuredErrorAndPeerFailure(t *testing.T) {
	p := start(t, func(context.Context, Peer, Request) (any, error) {
		return nil, &Error{Code: "forbidden", Message: "peer not allowed"}
	}, fixedPeer(1))
	err := Call(context.Background(), p, Request{Op: "ping"}, nil)
	var e *Error
	if !errors.As(err, &e) || e.Code != "forbidden" {
		t.Fatalf("got %v", err)
	}
	p2 := start(t, func(context.Context, Peer, Request) (any, error) {
		t.Fatal("handler reached without peer")
		return nil, nil
	},
		func(net.Conn) (Peer, error) { return Peer{}, errors.New("no cred") })
	err = Call(context.Background(), p2, Request{Op: "ping"}, nil)
	if !errors.As(err, &e) || e.Code != "peer_unknown" {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsMalformedAndUnknownFields(t *testing.T) {
	p := start(t, func(context.Context, Peer, Request) (any, error) { return "ok", nil }, fixedPeer(0))
	send := func(raw string) string {
		c, err := net.Dial("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(raw))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		return string(buf[:n])
	}
	for _, raw := range []string{
		"not json\n",
		`{"op":"ping","exec":"rm -rf /"}` + "\n",
		`{"op":"../../etc"}` + "\n",
		`{"op":"PING; reboot"}` + "\n",
		strings.Repeat("x", MaxRequest+10) + "\n",
	} {
		if r := send(raw); !strings.Contains(r, `"bad_request"`) {
			t.Errorf("%.40q → %s", raw, r)
		}
	}
}

// A helper that is restarting (socket not yet listening) is waited for, bounded.
func TestCallWaitsForRestartingHelper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "late.sock")
	go func() {
		time.Sleep(700 * time.Millisecond)
		ln, err := net.Listen("unix", p)
		if err != nil {
			return
		}
		s := &Server{Handler: func(context.Context, Peer, Request) (any, error) { return map[string]bool{"ok": true}, nil }, PeerCred: fixedPeer(0), Timeout: 2 * time.Second}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go s.Serve(ctx, ln)
	}()
	var out map[string]bool
	if err := Call(context.Background(), p, Request{Op: "x.y"}, &out); err != nil {
		if strings.Contains(err.Error(), "not supported") {
			t.Skip("unix sockets unavailable")
		}
		t.Fatal(err)
	}
	if !out["ok"] {
		t.Fatal("no result")
	}
	old := DialRetry
	DialRetry = 300 * time.Millisecond
	defer func() { DialRetry = old }()
	start := time.Now()
	if err := Call(context.Background(), filepath.Join(t.TempDir(), "never.sock"), Request{Op: "x.y"}, &out); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("absent helper must fail after the bounded wait: %v %s", err, time.Since(start))
	}
}
