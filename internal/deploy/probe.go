package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ngm-gateway/ngm/internal/gateway"
)

// ProbeResult is the evidence for one verification probe.
type ProbeResult struct {
	Probe      gateway.Probe `json:"probe"`
	OK         bool          `json:"ok"`
	Status     int           `json:"status,omitempty"`
	Generation string        `json:"generation,omitempty"`
	CertSHA256 string        `json:"cert_sha256,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// Prober runs verification requests against the local data plane.
type Prober interface {
	Probe(ctx context.Context, p gateway.Probe, token, wantGen, wantCertFP string) ProbeResult
	Listening(ctx context.Context, addr string) bool
}

// NetProber is the real implementation.
type NetProber struct{}

// Probe sends a request carrying the generation's probe token and expects the
// generation header back (proving the new configuration answers). For HTTPS
// it also checks that the served certificate is the expected one.
func (NetProber) Probe(ctx context.Context, p gateway.Probe, token, wantGen, wantCertFP string) ProbeResult {
	r := ProbeResult{Probe: p}
	var peerFP string
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", p.Addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: p.Host,
			// Identity is pinned below by fingerprint; the certificate may be
			// self-signed or not yet trusted by the system store.
			InsecureSkipVerify: true, //nolint:gosec
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) > 0 {
					sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
					peerFP = hex.EncodeToString(sum[:])
				}
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", p.Kind+"://"+p.Host+"/", nil)
	req.Header.Set(gateway.ProbeHdr, token)
	resp, err := c.Do(req)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	resp.Body.Close()
	r.Status = resp.StatusCode
	r.Generation = resp.Header.Get(gateway.GenHdr)
	r.CertSHA256 = peerFP
	switch {
	case r.Generation != wantGen:
		r.Error = fmt.Sprintf("served generation %q, want %q", r.Generation, wantGen)
	case p.Kind == "https" && wantCertFP != "" && peerFP != wantCertFP:
		r.Error = "served certificate does not match the deployed one"
	default:
		r.OK = true
	}
	return r
}

// Listening reports whether a TCP connect to addr succeeds.
func (NetProber) Listening(ctx context.Context, addr string) bool {
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
