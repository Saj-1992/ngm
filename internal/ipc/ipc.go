// Package ipc is the typed request/response protocol between NGM workers and
// the privileged helper over a Unix-domain socket (MASTER_SPEC §3).
//
// One JSON request line per connection, one JSON response line back. The
// server identifies the caller from kernel-provided peer credentials
// (SO_PEERCRED), never from anything the client sends; presence of the
// socket alone confers no authority.
package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"
)

// MaxRequest bounds request size; MaxResponse bounds response size.
const (
	MaxRequest  = 16 << 20 // staged generations carry config files and keys
	MaxResponse = 4 << 20
)

// Request is a helper call.
type Request struct {
	Op    string          `json:"op"`
	JobID string          `json:"job_id,omitempty"`
	Fence int64           `json:"fence,omitempty"`
	Args  json.RawMessage `json:"args,omitempty"`
}

// Error is a structured helper error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return "helper: " + e.Code + ": " + e.Message }

// Response is a helper reply.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Peer is the kernel-attested identity of the connecting process.
type Peer struct {
	PID int32
	UID uint32
	GID uint32
}

var opRe = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){0,3}$`)

// Handler serves one authenticated request.
type Handler func(ctx context.Context, peer Peer, req Request) (any, error)

// Server accepts connections and dispatches requests.
type Server struct {
	Handler Handler
	Timeout time.Duration // per request (default 60s)
	// PeerCred obtains peer credentials; defaults to the platform implementation.
	PeerCred func(net.Conn) (Peer, error)
	wg       sync.WaitGroup
}

// Serve accepts until ln is closed or ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Timeout <= 0 {
		s.Timeout = 60 * time.Second
	}
	if s.PeerCred == nil {
		s.PeerCred = peerCred
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(ctx, c)
		}()
	}
}

func writeResp(c net.Conn, r Response) {
	b, _ := json.Marshal(r)
	_, _ = c.Write(append(b, '\n'))
}

func errResp(code, msg string) Response {
	return Response{Error: &Error{Code: code, Message: msg}}
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.Timeout))
	peer, err := s.PeerCred(c)
	if err != nil {
		writeResp(c, errResp("peer_unknown", "cannot determine peer credentials"))
		return
	}
	line, err := bufio.NewReaderSize(io.LimitReader(c, MaxRequest+1), 4096).ReadBytes('\n')
	if err != nil || len(line) > MaxRequest {
		writeResp(c, errResp("bad_request", "request missing, unterminated or too large"))
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !opRe.MatchString(req.Op) {
		writeResp(c, errResp("bad_request", "malformed request"))
		return
	}
	rctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	out, err := s.Handler(rctx, peer, req)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			writeResp(c, Response{Error: e})
		} else {
			writeResp(c, errResp("failed", err.Error()))
		}
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		writeResp(c, errResp("failed", "unencodable result"))
		return
	}
	writeResp(c, Response{OK: true, Result: b})
}

// Call performs one request against the socket at path and decodes the result into out.
func Call(ctx context.Context, path string, req Request, out any) error {
	c, err := dialHelper(ctx, path)
	if err != nil {
		return fmt.Errorf("helper unreachable: %w", err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(90 * time.Second))
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(b) > MaxRequest {
		return errors.New("request too large")
	}
	_, werr := c.Write(append(b, '\n'))
	// The helper may answer and close before reading (e.g. it rejects the
	// peer): a failed write is reported only when no response is readable.
	line, err := bufio.NewReader(io.LimitReader(c, MaxResponse)).ReadBytes('\n')
	if err != nil {
		if werr != nil {
			return werr
		}
		return fmt.Errorf("helper response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("helper response: %w", err)
	}
	if !resp.OK {
		if resp.Error == nil {
			return &Error{Code: "failed", Message: "unknown helper error"}
		}
		return resp.Error
	}
	if out != nil {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

// DialRetry bounds how long Call waits for a restarting helper (systemd
// RestartSec=2). Only the dial is retried: nothing has been sent yet, so a
// retry can never repeat an operation.
var DialRetry = 15 * time.Second

func dialHelper(ctx context.Context, path string) (net.Conn, error) {
	deadline := time.Now().Add(DialRetry)
	for {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(250 * time.Millisecond):
		}
	}
}
