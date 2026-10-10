package httpapi

import (
	"strings"
	"testing"
)

func TestIndexCarriesPerResponseStyleNonce(t *testing.T) {
	f := newFixture(t)
	a := f.do(t, "GET", "/", nil, true)
	b := f.do(t, "GET", "/system/users", nil, true)
	csp := a.Header().Get("Content-Security-Policy")
	if strings.Contains(a.Body.String(), noncePlaceholder) {
		t.Fatal("placeholder not replaced")
	}
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self';") {
		t.Fatalf("script policy weakened: %q", csp)
	}
	i := strings.Index(csp, "'nonce-")
	if i < 0 {
		t.Fatalf("no style nonce in %q", csp)
	}
	rest := csp[i+len("'nonce-"):]
	nonce := rest[:strings.Index(rest, "'")]
	if !strings.Contains(a.Body.String(), `content="`+nonce+`"`) {
		t.Fatal("body nonce does not match CSP header")
	}
	if b.Header().Get("Content-Security-Policy") == csp {
		t.Fatal("nonce reused across responses")
	}
}
