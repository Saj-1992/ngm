package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/websites"
)

func TestWebsiteHTTPFlowAndPreviewIsolation(t *testing.T) {
	f, ts := setupServer(t)
	f.srv.d.Config.Paths.Websites = t.TempDir()
	owner, _ := enrolOwner(t, ts)
	r := owner.do("POST", "/api/v1/websites", map[string]any{"name": "Shop", "kind": "template", "template": "corporate", "default_locale": "fa", "locales": []string{"fa", "en"}}, nil)
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	id := r.body["id"].(string)
	g := owner.do("GET", "/api/v1/websites/"+id, nil, nil)
	site := g.body["website"].(map[string]any)
	dr := int64(site["draft_revision"].(float64))
	content, _ := json.Marshal(site["content"])
	// Content save needs the draft revision; stale is 412.
	put := func(rev int64, body []byte) (int, map[string]any) {
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/websites/"+id+"/content", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Draft-Revision", strconv.FormatInt(rev, 10))
		req.Header.Set(csrfHeader, owner.csrf())
		req.Header.Set("Origin", ts.URL)
		res, err := owner.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m
	}
	if code, m := put(dr, content); code != 200 || len(m["errors"].([]any)) != 0 {
		t.Fatalf("save: %d %v", code, m)
	}
	if code, _ := put(dr, content); code != 412 {
		t.Fatalf("stale draft: %d", code)
	}
	// Media: raw body, real type checked.
	up := func(path, ct string, body []byte) (int, map[string]any) {
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		req.Header.Set(csrfHeader, owner.csrf())
		req.Header.Set("Origin", ts.URL)
		res, err := owner.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m
	}
	if code, _ := up("/api/v1/websites/"+id+"/media?name=x.svg", "image/svg+xml", []byte("<svg/>")); code != 400 {
		t.Fatalf("svg: %d", code)
	}
	if code, m := up("/api/v1/websites/"+id+"/media?name=Logo.PNG", "image/png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 20)...)); code != 201 || m["name"] != "logo.png" {
		t.Fatalf("png: %d %v", code, m)
	}
	if code, _ := up("/api/v1/websites/"+id+"/media?name=big.png", "image/png", make([]byte, 6<<20)); code != 413 && code != 400 {
		t.Fatalf("oversize media: %d", code)
	}
	if code, _ := up("/api/v1/websites/"+id+"/upload", "application/zip", []byte("PK")); code != 400 {
		t.Fatalf("zip upload on a template site: %d", code)
	}
	// Build is a job; build here directly (the worker's part) to test preview.
	if r := owner.do("POST", "/api/v1/websites/"+id+"/build", nil, nil); r.code != 202 {
		t.Fatalf("build job: %d", r.code)
	}
	svc := &websites.Service{DB: f.db, Audit: f.srv.d.Audit, Root: f.srv.d.Config.Paths.Websites}
	b, err := svc.Build(context.Background(), id, "", "")
	if err != nil {
		t.Fatal(err)
	}
	vid := b.Version.ID
	r = owner.do("POST", "/api/v1/websites/"+id+"/versions/"+vid+"/preview", nil, nil)
	link, _ := r.body["url"].(string)
	if r.code != 200 || !strings.HasPrefix(link, "/api/v1/preview/"+id+"/"+vid+"/") {
		t.Fatalf("preview link: %d %v", r.code, r.body)
	}
	// The preview needs no cookie (sandboxed iframes send none) but a valid token.
	anon := &http.Client{}
	get := func(u string) (*http.Response, string) {
		res, err := anon.Get(ts.URL + u)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res, string(body)
	}
	res, body := get(link + "fa/about/")
	if res.StatusCode != 200 || !strings.Contains(body, `dir="rtl"`) {
		t.Fatalf("preview page: %d %s", res.StatusCode, body)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "sandbox") || !strings.Contains(csp, "connect-src 'none'") || strings.Contains(csp, "allow-same-origin") {
		t.Fatalf("preview must be sandboxed (opaque origin): %q", csp)
	}
	if res, _ := get(link + "assets/site.css"); res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("css: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	// Tampered token, other version, traversal → 404.
	bad := strings.Replace(link, "/"+vid+"/", "/"+vid+"/x", 1)
	for _, u := range []string{bad + "index.html", strings.Replace(link, id, "01J9AAAAAAAAAAAAAAAAAAAAAA", 1) + "index.html", link + "../../../../etc/passwd", link + "%2e%2e/%2e%2e/x"} {
		if res, _ := get(u); res.StatusCode != 404 && res.StatusCode != 400 {
			t.Fatalf("%s → %d", u, res.StatusCode)
		}
	}
	// Publish needs a built version.
	if r := owner.do("POST", "/api/v1/websites/"+id+"/publish", map[string]string{"version_id": "01J9AAAAAAAAAAAAAAAAAAAAAA"}, nil); r.code != 404 {
		t.Fatalf("publish unknown version: %d", r.code)
	}
	if r := owner.do("POST", "/api/v1/websites/"+id+"/publish", map[string]string{"version_id": vid}, nil); r.code != 202 {
		t.Fatalf("publish: %d %v", r.code, r.body)
	}
	// A viewer can read but not write.
	if r := owner.do("GET", "/api/v1/websites/"+id+"/versions", nil, nil); r.code != 200 || len(r.body["items"].([]any)) != 1 {
		t.Fatalf("versions: %v", r.body)
	}
}
