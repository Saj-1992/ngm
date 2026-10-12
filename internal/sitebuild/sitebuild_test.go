package sitebuild

import (
	"strings"
	"testing"
)

func build(t *testing.T, c *Content, tpl string, media map[string][]byte) *Output {
	t.Helper()
	if media == nil {
		media = StarterMedia(tpl)
	}
	out, err := Build(Input{Content: c, Template: tpl, Locales: []string{"fa", "en"}, Default: "fa", Media: media})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryTemplateBuildsDeterministically(t *testing.T) {
	for _, tpl := range Templates {
		c := Starter(tpl)
		c.Site.BaseURL = "https://example.com"
		a, b := build(t, c, tpl, nil), build(t, Starter2(tpl), tpl, nil)
		if a.Hash != b.Hash {
			t.Fatalf("%s: build not deterministic", tpl)
		}
		for _, f := range []string{"index.html", "fa/index.html", "en/index.html", "assets/site.css", "sitemap.xml", "robots.txt", "404.html"} {
			if _, ok := a.Files[f]; !ok {
				t.Fatalf("%s: missing %s", tpl, f)
			}
		}
		if strings.Contains(string(a.Files["fa/index.html"]), "<script") {
			t.Fatalf("%s: generated pages must not contain scripts", tpl)
		}
	}
}

// Starter2 builds the same content again (separate allocation).
func Starter2(tpl string) *Content {
	c := Starter(tpl)
	c.Site.BaseURL = "https://example.com"
	return c
}

func TestLocalisationSEO(t *testing.T) {
	c := Starter("corporate")
	c.Site.BaseURL = "https://example.com/"
	out := build(t, c, "corporate", nil)
	fa := string(out.Files["fa/about/index.html"])
	en := string(out.Files["en/about/index.html"])
	for _, want := range []string{`<html lang="fa" dir="rtl">`, `<link rel="canonical" href="https://example.com/fa/about/">`,
		`hreflang="en" href="https://example.com/en/about/"`, `hreflang="x-default" href="https://example.com/fa/about/"`, "درباره ما"} {
		if !strings.Contains(fa, want) {
			t.Fatalf("fa page lacks %q:\n%s", want, fa)
		}
	}
	if !strings.Contains(en, `<html lang="en" dir="ltr">`) || !strings.Contains(en, ">About<") {
		t.Fatal("en page")
	}
	sm := string(out.Files["sitemap.xml"])
	if !strings.Contains(sm, "<loc>https://example.com/en/about/</loc>") || !strings.Contains(sm, `xhtml:link rel="alternate" hreflang="fa"`) {
		t.Fatalf("sitemap:\n%s", sm)
	}
	if !strings.Contains(string(out.Files["robots.txt"]), "Sitemap: https://example.com/sitemap.xml") {
		t.Fatal("robots")
	}
	root := string(out.Files["index.html"])
	if !strings.Contains(root, `lang="fa"`) || !strings.Contains(root, `href="assets/site.css"`) || !strings.Contains(root, `rel="canonical" href="https://example.com/fa/"`) || strings.Contains(root, "http-equiv") {
		t.Fatalf("root must be the default locale home page (canonical /fa/), not a redirect page:\n%s", root[:300])
	}
}

func TestEscapingAndUnsafeLinks(t *testing.T) {
	c := Starter("corporate")
	c.Pages[0].Blocks = []Block{{Type: "text", Heading: L{"fa": `<img src=x onerror=alert(1)>`},
		Text: L{"fa": "**bold** <script>alert(1)</script> [ok](https://example.com) [x](javascript:alert(1))"}}}
	_, err := Build(Input{Content: c, Template: "corporate", Locales: []string{"fa"}, Default: "fa"})
	if err == nil || !strings.Contains(err.Error(), "unsafe link") {
		t.Fatalf("javascript: link must be rejected: %v", err)
	}
	c.Pages[0].Blocks[0].Text = L{"fa": `**bold** <script>alert(1)</script> [ok](https://example.com) "quotes"`}
	out := build(t, c, "corporate", nil)
	h := string(out.Files["fa/index.html"])
	if strings.Contains(h, "<script>") || strings.Contains(h, "<img src=x") || !strings.Contains(h, "&lt;script&gt;") || !strings.Contains(h, "<strong>bold</strong>") ||
		!strings.Contains(h, `<a href="https://example.com" rel="noopener noreferrer">ok</a>`) {
		t.Fatalf("escaping:\n%s", h)
	}
	for _, bad := range []string{"javascript:x", "data:text/html,x", "//evil.example", "vbscript:x", "https://", "http://a b"} {
		if _, ok := SafeURL(bad); ok {
			t.Fatalf("SafeURL accepted %q", bad)
		}
	}
	c.Pages[0].Blocks = []Block{{Type: "cta", Label: L{"fa": "x"}, Href: "javascript:alert(1)"}}
	if _, err := Build(Input{Content: c, Template: "corporate", Locales: []string{"fa"}, Default: "fa"}); err == nil {
		t.Fatal("unsafe href accepted")
	}
}

func TestValidation(t *testing.T) {
	c := Starter("blog")
	errs, warns := Validate(c, "blog", []string{"fa", "en", "de"}, "fa", mediaNames(StarterMedia("blog")))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	missingDE := 0
	for _, w := range warns {
		if strings.Contains(w, "no de translation") {
			missingDE++
		}
	}
	if missingDE == 0 {
		t.Fatalf("missing translations must be warned: %v", warns)
	}
	bad := &Content{Site: Site{Title: L{"en": "x"}}, Pages: []Page{{Slug: "Bad Slug", Title: L{"en": "x"}}, {Slug: "media", Title: L{"en": "x"}},
		{Slug: "fa", Title: L{"en": "x"}}, {Slug: "a", Title: L{"en": "x"}, Blocks: []Block{{Type: "iframe"}, {Type: "text", Image: "missing.png"}}}}}
	errs, _ = Validate(bad, "blog", []string{"en"}, "en", map[string]bool{})
	joined := strings.Join(errs, "\n")
	for _, want := range []string{"Bad Slug", `"media"`, `"fa"`, "unknown block type", "not in the media library", "home page"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing error %q in:\n%s", want, joined)
		}
	}
	if errs, _ := Validate(Starter("corporate"), "nope", []string{"xx"}, "en", nil); len(errs) < 2 {
		t.Fatal("template/locale validation")
	}
}

func TestBlogOrdering(t *testing.T) {
	c := Starter("blog")
	c.Pages = append(c.Pages, Page{Slug: "newer", Kind: "post", Date: "2026-10-30", Title: L{"fa": "تازه", "en": "Newer"}})
	out := build(t, c, "blog", nil)
	h := string(out.Files["en/index.html"])
	if strings.Index(h, "Newer") > strings.Index(h, "Why courtyard houses keep coming back") || strings.Index(h, "Newer") < 0 {
		t.Fatal("posts must be newest first")
	}
}

func TestMediaIncluded(t *testing.T) {
	c := Starter("portfolio")
	c.Pages[0].Blocks[1].Items[0].Image = "shot.png"
	png := []byte("\x89PNG\r\n\x1a\nfake")
	m := StarterMedia("portfolio")
	m["shot.png"] = png
	out := build(t, c, "portfolio", m)
	if string(out.Files["media/shot.png"]) != string(png) || !strings.Contains(string(out.Files["en/index.html"]), `<img src="../media/shot.png"`) {
		t.Fatal("media")
	}
}

func TestRelativeLinksForSubpathMounts(t *testing.T) {
	c := Starter("corporate")
	c.Site.BaseURL = "https://example.com/site"
	out := build(t, c, "corporate", nil)
	about := string(out.Files["en/about/index.html"])
	for _, want := range []string{`href="../../assets/site.css"`, `class="brand" href="../../en/"`, `href="../../fa/about/" hreflang="fa"`,
		`<link rel="canonical" href="https://example.com/site/en/about/">`} {
		if !strings.Contains(about, want) {
			t.Fatalf("missing %q:\n%s", want, about)
		}
	}
	if strings.Contains(about, `href="/`) || strings.Contains(about, `src="/`) {
		t.Fatal("site-absolute paths would break sub-path mounts")
	}
}

func mediaNames(m map[string][]byte) map[string]bool {
	out := map[string]bool{}
	for n := range m {
		out[n] = true
	}
	return out
}

// The four branded starter sites must be complete: several pages, both
// languages everywhere, every image present, every internal link resolving.
func TestBrandedStartersAreComplete(t *testing.T) {
	for _, tpl := range []string{"corporate", "blog", "portfolio", "app_showcase"} {
		c := Starter(tpl)
		media := StarterMedia(tpl)
		if len(media) < 4 {
			t.Fatalf("%s: expected generated artwork, got %d files", tpl, len(media))
		}
		errs, warns := Validate(c, tpl, []string{"fa", "en"}, "fa", mediaNames(media))
		if len(errs) != 0 || len(warns) != 1 { // the only warning: no base URL
			t.Fatalf("%s: errs=%v warns=%v", tpl, errs, warns)
		}
		if len(c.Pages) < 6 {
			t.Fatalf("%s: only %d pages", tpl, len(c.Pages))
		}
		slugs := map[string]bool{}
		for _, p := range c.Pages {
			slugs[p.Slug] = true
		}
		var check func(bs []Block)
		check = func(bs []Block) {
			for _, b := range bs {
				if strings.HasPrefix(b.Href, "page:") && !slugs[strings.TrimPrefix(b.Href, "page:")] {
					t.Fatalf("%s: dangling internal link %q", tpl, b.Href)
				}
				for _, it := range b.Items {
					if b.Type != "pricing" && strings.HasPrefix(it.Href, "page:") {
						t.Fatalf("%s: item links do not resolve page: targets", tpl)
					}
				}
			}
		}
		used := map[string]bool{}
		for _, p := range c.Pages {
			check(p.Blocks)
			if p.Image != "" {
				used[p.Image] = true
			}
			for _, b := range p.Blocks {
				if b.Image != "" {
					used[b.Image] = true
				}
				for _, it := range b.Items {
					if it.Image != "" {
						used[it.Image] = true
					}
				}
			}
		}
		for n := range used {
			if media[n] == nil {
				t.Fatalf("%s: image %s has no artwork", tpl, n)
			}
		}
		c.Site.BaseURL = "https://example.com"
		out := build(t, c, tpl, media)
		for _, loc := range []string{"fa", "en"} {
			for _, p := range c.Pages {
				path := loc + "/" + p.Slug + "/index.html"
				if p.Slug == "" {
					path = loc + "/index.html"
				}
				h := string(out.Files[path])
				if h == "" || !strings.Contains(h, "og:image") && p.Image != "" {
					t.Fatalf("%s: %s missing or lacks og:image", tpl, path)
				}
				if strings.Contains(h, "page:") || strings.Contains(h, "<script") {
					t.Fatalf("%s: %s has an unresolved link or script", tpl, path)
				}
			}
		}
		if !strings.Contains(string(out.Files["fa/index.html"]), "rel=\"icon\"") {
			t.Fatalf("%s: no favicon", tpl)
		}
	}
}

func TestStarterMediaIsDeterministicPNG(t *testing.T) {
	a, b := StarterMedia("blog"), StarterMedia("blog")
	for n, d := range a {
		if string(d) != string(b[n]) || len(d) < 1000 || len(d) > 400<<10 || string(d[1:4]) != "PNG" {
			t.Fatalf("%s: not a stable, reasonably sized PNG (%d bytes)", n, len(d))
		}
		if !ValidMediaName(n) {
			t.Fatalf("invalid media name %s", n)
		}
	}
	if StarterMedia("nope") != nil {
		t.Fatal("templates without artwork must return none")
	}
}

func TestFormatDate(t *testing.T) {
	for _, c := range []struct{ loc, in, want string }{
		{"fa", "2026-03-21", "۱ فروردین ۱۴۰۵"},
		{"fa", "2026-10-12", "۲۰ مهر ۱۴۰۵"},
		{"en", "2026-09-28", "28 September 2026"},
		{"fa", "bad", "bad"},
	} {
		if got := formatDate(c.loc, c.in); got != c.want {
			t.Fatalf("%s %s: got %q want %q", c.loc, c.in, got, c.want)
		}
	}
}
