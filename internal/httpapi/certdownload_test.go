package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCertificateDownload(t *testing.T) {
	_, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)

	r := owner.do("POST", "/api/v1/certificates/self-signed", map[string]any{"name": "dl", "hosts": []string{"a.example.com"}, "days": 30}, nil)
	if r.code != 201 {
		t.Fatalf("create cert: %d %v", r.code, r.body)
	}
	id := r.body["id"].(string)

	get := func(c *client, path string) (int, http.Header, string) {
		req, _ := http.NewRequest("GET", c.base+path, nil)
		resp, err := c.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, resp.Header, string(b)
	}

	// fullchain: certificate chain, correct download headers, no key.
	code, hdr, body := get(owner, "/api/v1/certificates/"+id+"/fullchain")
	if code != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("fullchain: %d body=%.40q", code, body)
	}
	if hdr.Get("Content-Disposition") != `attachment; filename="fullchain.pem"` {
		t.Fatalf("fullchain disposition: %q", hdr.Get("Content-Disposition"))
	}

	// privkey: owner has fresh MFA from enrolment → allowed, is a private key.
	code, hdr, body = get(owner, "/api/v1/certificates/"+id+"/privkey")
	if code != 200 || !strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("privkey: %d body=%.40q", code, body)
	}
	if hdr.Get("Content-Disposition") != `attachment; filename="privkey.pem"` {
		t.Fatalf("privkey disposition: %q", hdr.Get("Content-Disposition"))
	}

	// An API token (never an interactive user) can read the public chain but
	// can never download the private key, even with certificates.write scope.
	tk := owner.do("POST", "/api/v1/tokens", map[string]any{"name": "dl-token", "scopes": []string{"certificates.read", "certificates.write"}, "expires_in_days": 1}, nil)
	if tk.code != 201 {
		t.Fatalf("token: %d %v", tk.code, tk.body)
	}
	tok, _ := tk.body["token"].(string)
	if tok == "" {
		tok, _ = tk.body["secret"].(string)
	}
	tget := func(path string) int {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := owner.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := tget("/api/v1/certificates/" + id + "/privkey"); code != 403 {
		t.Fatalf("token privkey must be 403 (user_required), got %d", code)
	}
	if code := tget("/api/v1/certificates/" + id + "/fullchain"); code != 200 {
		t.Fatalf("token fullchain: %d", code)
	}
}
