// Command ngm-testkit provides real test backends and clients for NGM
// end-to-end tests (development only; never installed on production hosts).
//
//	ngm-testkit http-echo  -listen 127.0.0.1:9101 -name A     HTTP echo + WebSocket echo at /ws
//	ngm-testkit tcp-echo   -listen 127.0.0.1:9201 -name T     line echo
//	ngm-testkit tls-echo   -listen 127.0.0.1:9301 -name X     TLS server reporting SNI/ALPN (own cert, CN=name)
//	ngm-testkit ws-client  -addr 127.0.0.1:80 -host h -path /ws -n 5 -interval 1s
//	ngm-testkit tls-client -addr 127.0.0.1:443 -sni h [-alpn h2,http/1.1]
//	ngm-testkit tcp-client -addr 127.0.0.1:2222 -msg hello
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ngm-testkit <http-echo|tcp-echo|tls-echo|ws-client|tls-client|tcp-client> [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	name := fs.String("name", "backend", "backend name reported in responses")
	addr := fs.String("addr", "", "address to connect to")
	host := fs.String("host", "", "Host header")
	path := fs.String("path", "/ws", "path")
	sni := fs.String("sni", "", "TLS SNI (empty = none)")
	alpn := fs.String("alpn", "", "comma-separated ALPN")
	n := fs.Int("n", 3, "messages")
	interval := fs.Duration("interval", 200*time.Millisecond, "interval between messages")
	msg := fs.String("msg", "hello", "message")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "http-echo":
		err = httpEcho(*listen, *name)
	case "tcp-echo":
		err = tcpEcho(*listen, *name)
	case "https-echo":
		err = httpsEcho(*listen, *name)
	case "tls-echo":
		err = tlsEcho(*listen, *name)
	case "ws-client":
		err = wsClient(*addr, *host, *path, *n, *interval, *sni)
	case "tls-client":
		err = tlsClient(*addr, *sni, *alpn)
	case "tcp-client":
		err = tcpClient(*addr, *msg)
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ─── backends ──────────────────────────────────────────────────────────────

func httpEcho(listen, name string) error { return http.ListenAndServe(listen, echoMux(name)) }

// httpsEcho serves the same handler over TLS with a self-signed certificate
// (for proxy_ssl_verify on/off tests).
func httpsEcho(listen, name string) error {
	cert, err := selfSigned(name)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: listen, Handler: echoMux(name), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	return srv.ListenAndServeTLS("", "")
}

func echoMux(name string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "websocket upgrade required", 400)
			return
		}
		wsServe(w, r, name)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hdr := map[string]string{}
		for _, k := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto", "X-Ngm-Probe", "Connection"} {
			hdr[k] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"backend": name, "host": r.Host, "path": r.URL.Path, "remote": r.RemoteAddr, "headers": hdr})
	})
	return mux
}

func tcpEcho(listen, name string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	fmt.Printf("tcp-echo %s listening on %s\n", name, ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			sc := bufio.NewScanner(c)
			for sc.Scan() {
				fmt.Fprintf(c, "%s:%s\n", name, sc.Text())
			}
		}()
	}
}

func selfSigned(cn string) (tls.Certificate, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func tlsEcho(listen, name string) error {
	cert, err := selfSigned(name)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1", "xray"}}
	ln, err := tls.Listen("tcp", listen, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("tls-echo %s listening on %s\n", name, ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				return
			}
			st := tc.ConnectionState()
			fmt.Fprintf(tc, "tls-backend=%s sni=%s alpn=%s\n", name, st.ServerName, st.NegotiatedProtocol)
		}()
	}
}

// ─── minimal RFC 6455 WebSocket (text frames, echo) ────────────────────────

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func wsServe(w http.ResponseWriter, r *http.Request, name string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key")))
	rw.Flush()
	for {
		op, payload, err := wsRead(rw.Reader)
		if err != nil || op == 8 {
			return
		}
		if err := wsWrite(c, []byte(name+":"+string(payload)), false); err != nil {
			return
		}
	}
}

func wsRead(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 {
		return 0, nil, errors.New("frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return op, p, nil
}

func wsWrite(w io.Writer, p []byte, mask bool) error {
	hdr := []byte{0x81}
	mb := byte(0)
	if mask {
		mb = 0x80
	}
	switch {
	case len(p) < 126:
		hdr = append(hdr, mb|byte(len(p)))
	case len(p) < 1<<16:
		hdr = append(hdr, mb|126, byte(len(p)>>8), byte(len(p)))
	default:
		return errors.New("too large")
	}
	body := append([]byte(nil), p...)
	if mask {
		var m [4]byte
		rand.Read(m[:])
		hdr = append(hdr, m[:]...)
		for i := range body {
			body[i] ^= m[i%4]
		}
	}
	_, err := w.Write(append(hdr, body...))
	return err
}

func wsClient(addr, host, path string, n int, interval time.Duration, sni string) error {
	var c net.Conn
	var err error
	if sni != "" { // wss: TLS terminated by Nginx (test certificate, not verified)
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	} else {
		c, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	key := make([]byte, 16)
	rand.Read(key)
	k := base64.StdEncoding.EncodeToString(key)
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, k)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(k) {
		return fmt.Errorf("handshake failed: %s", resp.Status)
	}
	fmt.Println("ws: upgraded")
	start := time.Now()
	for i := 0; i < n; i++ {
		m := fmt.Sprintf("msg-%d", i)
		if err := wsWrite(c, []byte(m), true); err != nil {
			return fmt.Errorf("write %d after %s: %w", i, time.Since(start).Round(time.Millisecond), err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, p, err := wsRead(br)
		if err != nil {
			return fmt.Errorf("read %d after %s: %w", i, time.Since(start).Round(time.Millisecond), err)
		}
		fmt.Printf("ws: %s\n", p)
		time.Sleep(interval)
	}
	fmt.Printf("ws: %d round trips over %s on one connection\n", n, time.Since(start).Round(time.Millisecond))
	return nil
}

func tlsClient(addr, sni, alpn string) error {
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true} //nolint:gosec // test tool reports identity
	if alpn != "" {
		cfg.NextProtos = strings.Split(alpn, ",")
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	st := c.ConnectionState()
	cn := ""
	if len(st.PeerCertificates) > 0 {
		cn = st.PeerCertificates[0].Subject.CommonName
	}
	fmt.Printf("tls: peer-cert-cn=%s alpn=%s\n", cn, st.NegotiatedProtocol)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "" {
		fmt.Printf("tls: backend says: %s", line)
	}
	return nil
}

func tcpClient(addr, msg string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Fprintln(c, msg)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print("tcp: ", line)
	return nil
}
