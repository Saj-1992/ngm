package helper

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/ngm-gateway/ngm/internal/ipc"
)

// ACME HTTP-01 challenge files under /etc/nginx/ngm/acme (served by the
// generated port-80 location). Token and key authorization are validated
// against RFC 8555 base64url syntax; nothing else can be written there.
var (
	acmeTokenRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	acmeKeyAuthRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{43}$`)
)

func (l NginxLayout) acme() string { return filepath.Join(l.public(), "acme") }

// AcmeArgs puts or clears challenge responses.
type AcmeArgs struct {
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth,omitempty"`
}

func (o *NginxOps) ensureAcmeDir() error {
	return o.ensurePublicDir(o.L.acme())
}

// ensurePublicDir creates a world-readable directory under the public tree,
// refusing symlinks at the tree root and at d.
func (o *NginxOps) ensurePublicDir(d string) error {
	for _, p := range []string{o.L.public(), d} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
		if err := notSymlinkDir(p); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// AcmePut writes one challenge response (world-readable: Nginx serves it).
func (o *NginxOps) AcmePut(_ context.Context, a AcmeArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !acmeTokenRe.MatchString(a.Token) || !acmeKeyAuthRe.MatchString(a.KeyAuth) || a.KeyAuth[:len(a.Token)+1] != a.Token+"." {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid ACME token or key authorization"}
	}
	if err := o.ensureAcmeDir(); err != nil {
		return nil, err
	}
	p := filepath.Join(o.L.acme(), a.Token)
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := writeExclusive(tmp, []byte(a.KeyAuth), 0o644); err != nil {
		return nil, err
	}
	// The helper runs with UMask=0077; Nginx workers must read this file.
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return map[string]any{"written": a.Token}, nil
}

// AcmeClear removes a challenge response (missing files are fine).
func (o *NginxOps) AcmeClear(_ context.Context, a AcmeArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !acmeTokenRe.MatchString(a.Token) {
		return nil, &ipc.Error{Code: "bad_args", Message: "invalid ACME token"}
	}
	err := os.Remove(filepath.Join(o.L.acme(), a.Token))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return map[string]any{"cleared": a.Token}, nil
}
