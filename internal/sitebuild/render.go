package sitebuild

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Output is a built site.
type Output struct {
	Files    map[string][]byte `json:"-"`
	Hash     string            `json:"hash"`
	Warnings []string          `json:"warnings"`
	Size     int64             `json:"size_bytes"`
}

// Input is everything a build depends on.
type Input struct {
	Content  *Content
	Template string
	Locales  []string
	Default  string
	Media    map[string][]byte // media file name → bytes
}

var (
	boldRe = regexp.MustCompile(`\*\*([^*\n]{1,500})\*\*`)
	linkRe = regexp.MustCompile(`\[([^\]\n]{1,200})\]\(([^)\s]+)\)`)
)

// inline escapes text, then turns **x** and vetted [label](url) into markup.
func inline(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range linkRe.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(bold(html.EscapeString(s[last:m[0]])))
		label, href := s[m[2]:m[3]], s[m[4]:m[5]]
		if u, ok := SafeURL(href); ok && u != "" {
			rel := ""
			if strings.HasPrefix(u, "http") {
				rel = ` rel="noopener noreferrer"`
			}
			fmt.Fprintf(&b, `<a href="%s"%s>%s</a>`, html.EscapeString(u), rel, bold(html.EscapeString(label)))
		} else {
			b.WriteString(html.EscapeString(s[m[0]:m[1]]))
		}
		last = m[1]
	}
	b.WriteString(bold(html.EscapeString(s[last:])))
	return b.String()
}

func bold(escaped string) string { return boldRe.ReplaceAllString(escaped, "<strong>$1</strong>") }

// paragraphs splits on blank lines; single newlines become <br>.
func paragraphs(s string) string {
	var b strings.Builder
	for _, p := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lines := strings.Split(p, "\n")
		for i := range lines {
			lines[i] = inline(strings.TrimSpace(lines[i]))
		}
		b.WriteString("<p>" + strings.Join(lines, "<br>") + "</p>")
	}
	return b.String()
}

type page struct {
	b   strings.Builder
	loc string
	def string
	up  string // relative path from this page to the site root ("../../")
}

// href turns a site-absolute path ("/fa/about/") into a relative one, so a
// site works when mounted on a sub-path (/docs/) and in the preview.
func (p *page) href(abs string) string { return p.up + strings.TrimPrefix(abs, "/") }

func (p *page) t(l L) string {
	v, _ := l.Get(p.loc, p.def)
	return v
}

func pagePath(loc, slug string) string {
	if slug == "" {
		return "/" + loc + "/"
	}
	return "/" + loc + "/" + slug + "/"
}

func esc(s string) string { return html.EscapeString(s) }

// Build renders the site.
func Build(in Input) (*Output, error) {
	media := map[string]bool{}
	for n := range in.Media {
		media[n] = true
	}
	errs, warns := Validate(in.Content, in.Template, in.Locales, in.Default, media)
	if len(errs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, "; "))
	}
	c := in.Content
	locs := append([]string(nil), in.Locales...)
	sort.Strings(locs)
	out := &Output{Files: map[string][]byte{}, Warnings: append([]string{}, warns...)}
	base := strings.TrimSuffix(c.Site.BaseURL, "/")
	accent := c.Site.Accent
	if accent == "" {
		accent = "#2563eb"
	}
	out.Files["assets/site.css"] = []byte(siteCSS(in.Template, accent))
	for n, b := range in.Media {
		out.Files["media/"+n] = b
	}
	pages := orderedPages(c.Pages, in.Template)
	for _, loc := range locs {
		for _, pg := range pages {
			out.Files[strings.TrimPrefix(pagePath(loc, pg.Slug), "/")+"index.html"] = []byte(renderPage(c, in, pages, pg, loc, base))
		}
	}
	// Root: the default locale's home page itself (an ordinary site answers
	// "/" with content, not a redirect page); its canonical URL stays /<locale>/.
	for _, pg := range pages {
		if pg.Slug == "" {
			out.Files["index.html"] = []byte(renderPageUp(c, in, pages, pg, in.Default, base, ""))
		}
	}
	robots := "User-agent: *\nAllow: /\n"
	if base != "" {
		robots += "Sitemap: " + base + "/sitemap.xml\n"
		out.Files["sitemap.xml"] = []byte(sitemap(base, locs, pages))
	}
	out.Files["robots.txt"] = []byte(robots)
	out.Files["404.html"] = []byte(notFoundPage(c, in, accent))
	out.Hash, out.Size = HashFiles(out.Files)
	return out, nil
}

func (l L) mustGet(loc string, def ...string) string {
	d := loc
	if len(def) > 0 {
		d = def[0]
	}
	v, _ := l.Get(loc, d)
	return v
}

// HashFiles hashes a file set deterministically (sorted paths).
func HashFiles(files map[string][]byte) (string, int64) {
	names := make([]string, 0, len(files))
	var size int64
	for n, b := range files {
		names = append(names, n)
		size += int64(len(b))
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "\x00"))
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), size
}

// orderedPages: home first, then pages; posts last, newest first.
func orderedPages(ps []Page, template string) []Page {
	out := append([]Page(nil), ps...)
	// Strict weak order: home first, other pages in authoring order, posts
	// last and newest first. (A comparator that only orders posts against posts
	// is not transitive once pages and posts are mixed.)
	rank := func(p Page) int {
		switch {
		case p.Slug == "":
			return 0
		case p.Kind == "post":
			return 2
		}
		return 1
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return rank(a) == 2 && a.Date > b.Date
	})
	return out
}

func sitemap(base string, locs []string, pages []Page) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	for _, pg := range pages {
		if pg.Hidden {
			continue
		}
		for _, loc := range locs {
			fmt.Fprintf(&b, "  <url><loc>%s%s</loc>", esc(base), pagePath(loc, pg.Slug))
			for _, alt := range locs {
				fmt.Fprintf(&b, `<xhtml:link rel="alternate" hreflang="%s" href="%s%s"/>`, alt, esc(base), pagePath(alt, pg.Slug))
			}
			b.WriteString("</url>\n")
		}
	}
	b.WriteString("</urlset>\n")
	return b.String()
}

func renderPage(c *Content, in Input, pages []Page, pg Page, loc, base string) string {
	up := "../"
	if pg.Slug != "" {
		up = "../../"
	}
	return renderPageUp(c, in, pages, pg, loc, base, up)
}

// renderPageUp renders pg with links relative to a page "up" levels deep
// ("" for the site root).
func renderPageUp(c *Content, in Input, pages []Page, pg Page, loc, base, up string) string {
	p := &page{loc: loc, def: in.Default, up: up}
	dir := Locales[loc]
	title := p.t(pg.Title)
	siteTitle := p.t(c.Site.Title)
	desc := p.t(pg.Description)
	if desc == "" {
		desc = p.t(c.Site.Tagline)
	}
	b := &p.b
	fmt.Fprintf(b, "<!doctype html>\n<html lang=\"%s\" dir=\"%s\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n", loc, dir)
	if pg.Slug == "" {
		fmt.Fprintf(b, "<title>%s</title>\n", esc(siteTitle))
	} else {
		fmt.Fprintf(b, "<title>%s — %s</title>\n", esc(title), esc(siteTitle))
	}
	if desc != "" {
		fmt.Fprintf(b, "<meta name=\"description\" content=\"%s\">\n", esc(desc))
	}
	fmt.Fprintf(b, "<meta property=\"og:title\" content=\"%s\">\n", esc(title))
	if base != "" {
		fmt.Fprintf(b, "<link rel=\"canonical\" href=\"%s%s\">\n", esc(base), pagePath(loc, pg.Slug))
	}
	locs := append([]string(nil), in.Locales...)
	sort.Strings(locs)
	for _, alt := range locs {
		fmt.Fprintf(b, "<link rel=\"alternate\" hreflang=\"%s\" href=\"%s%s\">\n", alt, esc(base), pagePath(alt, pg.Slug))
	}
	fmt.Fprintf(b, "<link rel=\"alternate\" hreflang=\"x-default\" href=\"%s%s\">\n", esc(base), pagePath(in.Default, pg.Slug))
	accent := c.Site.Accent
	if accent == "" {
		accent = "#2563eb"
	}
	mark := firstRune(siteTitle)
	fmt.Fprintf(b, "<meta name=\"theme-color\" content=\"%s\">\n<meta property=\"og:site_name\" content=\"%s\">\n<meta property=\"og:type\" content=\"%s\">\n<meta property=\"og:locale\" content=\"%s\">\n<meta name=\"twitter:card\" content=\"summary_large_image\">\n", esc(accent), esc(siteTitle), ogType(pg), loc)
	if desc != "" {
		fmt.Fprintf(b, "<meta property=\"og:description\" content=\"%s\">\n", esc(desc))
	}
	if pg.Image != "" && base != "" {
		fmt.Fprintf(b, "<meta property=\"og:image\" content=\"%s/media/%s\">\n", esc(base), esc(pg.Image))
	}
	fmt.Fprintf(b, "<link rel=\"icon\" href=\"%s\">\n", faviconURI(mark, accent))
	fmt.Fprintf(b, "<link rel=\"stylesheet\" href=\"%sassets/site.css\">\n</head>\n", p.up)
	fmt.Fprintf(b, "<body class=\"t-%s\">\n<a class=\"skip\" href=\"#main\">%s</a>\n<header class=\"top\"><div class=\"wrap bar\"><a class=\"brand\" href=\"%s\"><span class=\"mark\" aria-hidden=\"true\">%s</span>%s</a>", in.Template, esc(skipText(loc)), p.href(pagePath(loc, "")), esc(mark), esc(siteTitle))
	// Navigation.
	{
		b.WriteString("<nav>")
		for _, np := range pages {
			if np.Hidden || np.Slug == "" || np.Kind == "post" {
				continue
			}
			cur := ""
			if np.Slug == pg.Slug {
				cur = ` aria-current="page"`
			}
			fmt.Fprintf(b, "<a href=\"%s\"%s>%s</a>", p.href(pagePath(loc, np.Slug)), cur, esc(p.t(np.Title)))
		}
		b.WriteString("</nav>")
	}
	if len(locs) > 1 {
		b.WriteString("<span class=\"langs\">")
		for _, alt := range locs {
			if alt == loc {
				continue
			}
			fmt.Fprintf(b, "<a href=\"%s\" hreflang=\"%s\" lang=\"%s\">%s</a>", p.href(pagePath(alt, pg.Slug)), alt, alt, strings.ToUpper(alt))
		}
		b.WriteString("</span>")
	}
	b.WriteString("</div></header>\n")
	b.WriteString("<main class=\"wrap\" id=\"main\">\n")
	if pg.Slug != "" || len(pg.Blocks) == 0 || pg.Blocks[0].Type != "hero" {
		fmt.Fprintf(b, "<h1>%s</h1>\n", esc(title))
		if pg.Kind == "post" && pg.Date != "" {
			fmt.Fprintf(b, "<p class=\"date\"><time datetime=\"%s\">%s</time></p>\n", pg.Date, esc(formatDate(loc, pg.Date)))
		}
		if pg.Image != "" {
			b.WriteString("<p class=\"cover\">" + p.img(pg.Image, title) + "</p>\n")
		}
	}
	for _, bl := range pg.Blocks {
		renderBlock(p, bl, pages, loc)
	}
	b.WriteString("</main>\n")
	if in.Template == "documentation" {
		b.WriteString("</div>\n")
	}
	b.WriteString("<footer class=\"foot\"><div class=\"wrap footgrid\">")
	fmt.Fprintf(b, "<div><strong class=\"fbrand\">%s</strong>%s</div>", esc(siteTitle), paragraphs(p.t(c.Site.Tagline)))
	b.WriteString("<nav aria-label=\"footer\">")
	for _, np := range pages {
		if np.Hidden || np.Slug == "" || np.Kind == "post" {
			continue
		}
		fmt.Fprintf(b, "<a href=\"%s\">%s</a>", p.href(pagePath(loc, np.Slug)), esc(p.t(np.Title)))
	}
	b.WriteString("</nav></div>")
	if f := p.t(c.Site.Footer); f != "" {
		fmt.Fprintf(b, "<div class=\"wrap fsmall\">%s</div>", paragraphs(f))
	}
	b.WriteString("</footer>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

func (p *page) img(name, alt string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("<img src=\"%smedia/%s\" alt=\"%s\" loading=\"lazy\">", p.up, esc(name), esc(alt))
}

func link(href, label, class string) string {
	u, ok := SafeURL(href)
	if !ok || u == "" || label == "" {
		return ""
	}
	return fmt.Sprintf("<a class=\"%s\" href=\"%s\">%s</a>", class, esc(u), esc(label))
}

func renderBlock(p *page, bl Block, pages []Page, loc string) {
	b := &p.b
	h, txt, label := p.t(bl.Heading), p.t(bl.Text), p.t(bl.Label)
	switch bl.Type {
	case "hero":
		cls := "hero"
		if bl.Image != "" {
			cls += " has-img"
		}
		fmt.Fprintf(b, "<section class=\"%s\"><div class=\"hero-copy\">", cls)
		if h != "" {
			fmt.Fprintf(b, "<h1>%s</h1>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		b.WriteString(p.link(bl.Href, label, "button"))
		b.WriteString("</div>")
		b.WriteString(p.img(bl.Image, h))
		b.WriteString("</section>\n")
	case "text":
		b.WriteString("<section class=\"text\">")
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		b.WriteString(p.img(bl.Image, h))
		b.WriteString("</section>\n")
	case "features", "gallery", "links":
		fmt.Fprintf(b, "<section class=\"%s\">", bl.Type)
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		b.WriteString("<ul class=\"grid\">")
		for _, it := range bl.Items {
			t := p.t(it.Title)
			b.WriteString("<li>")
			b.WriteString(p.img(it.Image, t))
			if t != "" {
				if u, ok := SafeURL(it.Href); ok && u != "" {
					fmt.Fprintf(b, "<h3><a href=\"%s\">%s</a></h3>", esc(u), esc(t))
				} else {
					fmt.Fprintf(b, "<h3>%s</h3>", esc(t))
				}
			}
			b.WriteString(paragraphs(p.t(it.Text)))
			b.WriteString("</li>")
		}
		b.WriteString("</ul></section>\n")
	case "cta":
		b.WriteString("<section class=\"cta\">")
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		b.WriteString(p.link(bl.Href, label, "button"))
		b.WriteString("</section>\n")
	case "faq":
		b.WriteString("<section class=\"faq\">")
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		for _, it := range bl.Items {
			fmt.Fprintf(b, "<details><summary>%s</summary>%s</details>", esc(p.t(it.Title)), paragraphs(p.t(it.Text)))
		}
		b.WriteString("</section>\n")
	case "quote":
		fmt.Fprintf(b, "<figure class=\"quote\"><blockquote>%s</blockquote>", paragraphs(txt))
		if h != "" {
			fmt.Fprintf(b, "<figcaption>%s</figcaption>", esc(h))
		}
		b.WriteString("</figure>\n")
	case "stats", "steps", "team", "pricing", "timeline":
		fmt.Fprintf(b, "<section class=\"%s\">", bl.Type)
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		tag := "ul"
		if bl.Type == "steps" || bl.Type == "timeline" {
			tag = "ol"
		}
		fmt.Fprintf(b, "<%s class=\"grid\">", tag)
		for _, it := range bl.Items {
			t := p.t(it.Title)
			b.WriteString("<li>")
			b.WriteString(p.img(it.Image, t))
			switch bl.Type {
			case "stats":
				fmt.Fprintf(b, "<span class=\"num\">%s</span>", esc(t))
			case "team":
				fmt.Fprintf(b, "<span class=\"avatar\" aria-hidden=\"true\">%s</span><h3>%s</h3>", esc(firstRune(t)), esc(t))
			default:
				if t != "" {
					fmt.Fprintf(b, "<h3>%s</h3>", esc(t))
				}
			}
			b.WriteString(paragraphs(p.t(it.Text)))
			if bl.Type == "pricing" {
				b.WriteString(p.link(it.Href, label, "button"))
			}
			b.WriteString("</li>")
		}
		fmt.Fprintf(b, "</%s></section>\n", tag)
	case "contact":
		b.WriteString("<section class=\"contact\">")
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString(paragraphs(txt))
		b.WriteString("<dl>")
		for _, it := range bl.Items {
			fmt.Fprintf(b, "<dt>%s</dt><dd>%s</dd>", esc(p.t(it.Title)), inline(p.t(it.Text)))
		}
		b.WriteString("</dl></section>\n")
	case "posts":
		b.WriteString("<section class=\"posts\">")
		if h != "" {
			fmt.Fprintf(b, "<h2>%s</h2>", esc(h))
		}
		b.WriteString("<ul>")
		for _, pp := range pages {
			if pp.Kind != "post" || pp.Hidden {
				continue
			}
			fmt.Fprintf(b, "<li>%s<a href=\"%s\">%s</a>", p.img(pp.Image, p.t(pp.Title)), p.href(pagePath(loc, pp.Slug)), esc(p.t(pp.Title)))
			if pp.Date != "" {
				fmt.Fprintf(b, "<time datetime=\"%s\">%s</time>", pp.Date, esc(formatDate(loc, pp.Date)))
			}
			if d := p.t(pp.Description); d != "" {
				fmt.Fprintf(b, "<p>%s</p>", esc(d))
			}
			b.WriteString("</li>")
		}
		b.WriteString("</ul></section>\n")
	}
}

func siteCSS(template, accent string) string {
	base := `:root{--accent:` + accent + `;--fg:#111827;--muted:#4b5563;--bg:#ffffff;--soft:#f3f4f6;--radius:14px}
@media (prefers-color-scheme:dark){:root{--fg:#f3f4f6;--muted:#9ca3af;--bg:#0b0f17;--soft:#161b26}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Vazirmatn,Tahoma,sans-serif;color:var(--fg);background:var(--bg);line-height:1.65}
.wrap{max-width:1080px;margin-inline:auto;padding-inline:16px}
.top{border-bottom:1px solid var(--soft)}.bar{display:flex;flex-wrap:wrap;gap:16px;align-items:center;min-height:60px}
.brand{font-weight:700;color:var(--fg);text-decoration:none;margin-inline-end:auto}
nav{display:flex;flex-wrap:wrap;gap:12px}nav a,.langs a{color:var(--muted);text-decoration:none}nav a[aria-current]{color:var(--accent);font-weight:600}
.langs{display:flex;gap:8px}
a{color:var(--accent)}img{max-width:100%;height:auto;border-radius:var(--radius)}
main{padding-block:32px}h1{font-size:clamp(1.8rem,4vw,2.8rem);line-height:1.2}h2{margin-top:2.2rem}
section{margin-block:28px}.hero{padding-block:32px}.hero p{font-size:1.15rem;color:var(--muted)}
.button{display:inline-block;background:var(--accent);color:#fff;padding:10px 18px;border-radius:999px;text-decoration:none;font-weight:600;margin-block:8px}
.grid{list-style:none;padding:0;display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.grid li{background:var(--soft);border-radius:var(--radius);padding:16px}.grid h3{margin-top:0}
.cta{background:var(--soft);border-radius:var(--radius);padding:24px;text-align:center}
.faq details{border-bottom:1px solid var(--soft);padding-block:10px}.faq summary{cursor:pointer;font-weight:600}
.quote blockquote{font-size:1.2rem;margin:0;border-inline-start:4px solid var(--accent);padding-inline-start:16px}
.posts ul{list-style:none;padding:0}.posts li{padding-block:10px;border-bottom:1px solid var(--soft)}.date,time{color:var(--muted)}
.foot{border-top:1px solid var(--soft);padding-block:24px;color:var(--muted);font-size:.9rem}
.skip{position:absolute;inset-inline-start:-999px;top:8px;background:var(--accent);color:#fff;padding:8px 14px;border-radius:8px;z-index:9}.skip:focus{inset-inline-start:8px}
.mark{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:9px;background:var(--accent);color:#fff;font-weight:700;margin-inline-end:10px;vertical-align:middle}
.hero.has-img{display:grid;gap:28px;align-items:center;grid-template-columns:1.1fr 1fr}.hero.has-img img{width:100%}
@media (max-width:760px){.hero.has-img{grid-template-columns:1fr}}
.stats .grid{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));text-align:center}.num{display:block;font-size:2.2rem;font-weight:800;color:var(--accent);line-height:1.2}
.steps .grid,.timeline .grid{counter-reset:s}.steps li,.timeline li{counter-increment:s;position:relative}.steps li::before{content:counter(s);display:inline-grid;place-items:center;width:30px;height:30px;border-radius:50%;background:var(--accent);color:#fff;font-weight:700;margin-bottom:8px}
.team .avatar{display:inline-grid;place-items:center;width:56px;height:56px;border-radius:50%;background:var(--accent);color:#fff;font-size:1.4rem;font-weight:700;margin-bottom:8px}
.pricing .grid{grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}.pricing li{border:1px solid var(--soft);background:transparent;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.contact dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 20px}.contact dt{font-weight:600}.contact dd{margin:0}
.cover img{width:100%;max-height:420px;object-fit:cover}.posts li img{width:100%;max-height:220px;object-fit:cover;margin-bottom:8px}
.t-blog .posts ul{display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}.posts time{display:block;font-size:.9rem;margin-block:4px}.t-blog .posts li{border:1px solid var(--soft);border-radius:var(--radius);padding:14px}
.footgrid{display:flex;flex-wrap:wrap;justify-content:space-between;gap:24px}.foot nav{flex-direction:column}.fbrand{display:block;color:var(--fg)}.fsmall{margin-top:16px;font-size:.85rem}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
`
	extra := map[string]string{
		"corporate":    ".t-corporate .hero{border-radius:var(--radius);background:var(--soft);padding:40px}",
		"portfolio":    ".t-portfolio .gallery .grid{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}.t-portfolio .gallery li{padding:0;overflow:hidden}.t-portfolio .gallery h3,.t-portfolio .gallery p{padding-inline:16px}",
		"blog":         ".t-blog main{max-width:760px}",
		"app_showcase": ".t-app_showcase .hero{display:grid;gap:24px;align-items:center}.t-app_showcase .hero img{max-height:520px;width:auto;justify-self:center}",
	}[template]
	return base + extra + "\n"
}

// notFoundPage renders a self-contained, styled 404 page. It uses inline CSS
// and a root-absolute home link so it displays correctly no matter which path
// Nginx serves it for (error_page keeps the original request URI).
func notFoundPage(c *Content, in Input, accent string) string {
	loc, def := in.Default, in.Default
	dir := Locales[loc]
	title := L(c.Site.Title).mustGet(loc, def)
	heading, _ := L{"en": "Page not found", "fa": "صفحه پیدا نشد", "ar": "الصفحة غير موجودة", "de": "Seite nicht gefunden", "fr": "Page introuvable", "es": "Página no encontrada", "tr": "Sayfa bulunamadı"}.Get(loc, "en")
	msg, _ := L{"en": "The page you are looking for does not exist or has moved.", "fa": "صفحه‌ای که دنبالش هستید وجود ندارد یا جابه‌جا شده است.", "ar": "الصفحة التي تبحث عنها غير موجودة أو تم نقلها.", "de": "Die gesuchte Seite existiert nicht oder wurde verschoben.", "fr": "La page que vous cherchez n'existe pas ou a été déplacée.", "es": "La página que buscas no existe o se ha movido.", "tr": "Aradığınız sayfa yok veya taşınmış."}.Get(loc, "en")
	home, _ := L{"en": "Go to homepage", "fa": "رفتن به خانه", "ar": "الذهاب إلى الصفحة الرئيسية", "de": "Zur Startseite", "fr": "Aller à l'accueil", "es": "Ir al inicio", "tr": "Ana sayfaya git"}.Get(loc, "en")
	var b strings.Builder
	fmt.Fprintf(&b, "<!doctype html>\n<html lang=\"%s\" dir=\"%s\">\n<head>\n<meta charset=\"utf-8\">\n", loc, dir)
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"robots\" content=\"noindex\">\n")
	fmt.Fprintf(&b, "<title>404 — %s</title>\n", esc(title))
	fmt.Fprintf(&b, "<style>:root{--a:%s}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f9;color:#1b1d21;font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,'Vazirmatn',sans-serif;padding:24px}main{max-width:32rem;text-align:center}.code{font-size:clamp(4rem,18vw,8rem);font-weight:800;line-height:1;color:var(--a);letter-spacing:-.04em}h1{font-size:1.5rem;margin:.5rem 0}p{color:#5b6068;margin:0 0 1.5rem}a.btn{display:inline-block;background:var(--a);color:#fff;text-decoration:none;padding:.65rem 1.25rem;border-radius:.6rem;font-weight:600}a.btn:hover{filter:brightness(.95)}.site{margin-top:2rem;color:#8a9099;font-size:.85rem}@media(prefers-color-scheme:dark){body{background:#0f1115;color:#e9ebef}p{color:#9aa0a8}}</style>\n", accent)
	b.WriteString("</head>\n<body>\n<main>\n")
	fmt.Fprintf(&b, "<div class=\"code\">404</div>\n<h1>%s</h1>\n<p>%s</p>\n", esc(heading), esc(msg))
	fmt.Fprintf(&b, "<a class=\"btn\" href=\"/\">%s</a>\n", esc(home))
	fmt.Fprintf(&b, "<div class=\"site\">%s</div>\n", esc(title))
	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String()
}

func firstRune(s string) string {
	for _, r := range strings.TrimSpace(s) {
		return strings.ToUpper(string(r))
	}
	return "N"
}

func ogType(pg Page) string {
	if pg.Kind == "post" {
		return "article"
	}
	return "website"
}

func skipText(loc string) string {
	v, _ := L{"en": "Skip to content", "fa": "پرش به محتوا"}.Get(loc, "en")
	return v
}

// faviconURI is an inline SVG icon (the site's initial on its accent colour),
// so every site has a favicon without an extra file or request.
func faviconURI(mark, accent string) string {
	svg := "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='" + accent + "'/><text x='32' y='44' font-size='34' font-family='sans-serif' font-weight='700' text-anchor='middle' fill='#fff'>" + html.EscapeString(mark) + "</text></svg>"
	return "data:image/svg+xml," + strings.ReplaceAll(url.QueryEscape(svg), "+", "%20")
}

// link renders an anchor; "page:<slug>" targets another page of this site in
// the current locale (relative, so it works under any base path).
func (p *page) link(href, label, class string) string {
	if strings.HasPrefix(href, "page:") && label != "" {
		slug := strings.TrimPrefix(href, "page:")
		return fmt.Sprintf("<a class=\"%s\" href=\"%s\">%s</a>", class, esc(p.href(pagePath(p.loc, slug))), esc(label))
	}
	return link(href, label, class)
}

var (
	enMonths = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
	faMonths = []string{"فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"}
)

// formatDate renders YYYY-MM-DD for readers of loc: Persian readers get the
// Solar Hijri calendar with Persian digits, everyone else an English date.
func formatDate(loc, iso string) string {
	var y, m, d int
	if _, err := fmt.Sscanf(iso, "%d-%d-%d", &y, &m, &d); err != nil || m < 1 || m > 12 || d < 1 || d > 31 {
		return iso
	}
	if loc != "fa" {
		return fmt.Sprintf("%d %s %d", d, enMonths[m-1], y)
	}
	jy, jm, jd := toJalali(y, m, d)
	return persianDigits(fmt.Sprint(jd)) + " " + faMonths[jm-1] + " " + persianDigits(fmt.Sprint(jy))
}

func persianDigits(s string) string {
	return strings.NewReplacer("0", "۰", "1", "۱", "2", "۲", "3", "۳", "4", "۴", "5", "۵", "6", "۶", "7", "۷", "8", "۸", "9", "۹").Replace(s)
}

// toJalali converts a Gregorian date to the Solar Hijri calendar.
func toJalali(gy, gm, gd int) (int, int, int) {
	cum := [12]int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	gy2 := gy
	if gm > 2 {
		gy2++
	}
	days := 355666 + 365*gy + (gy2+3)/4 - (gy2+99)/100 + (gy2+399)/400 + gd + cum[gm-1]
	jy := -1595 + 33*(days/12053)
	days %= 12053
	jy += 4 * (days / 1461)
	days %= 1461
	if days > 365 {
		jy += (days - 1) / 365
		days = (days - 1) % 365
	}
	if days < 186 {
		return jy, 1 + days/31, 1 + days%31
	}
	return jy, 7 + (days-186)/30, 1 + (days-186)%30
}
