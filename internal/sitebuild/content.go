// Package sitebuild renders structured template websites into static files
// (MASTER_SPEC §6.3). Output is deterministic: the same content and media
// always produce byte-identical files. User text is always HTML-escaped;
// the only markup accepted is **bold** and [label](url) with vetted URLs.
// Nothing executes server-side; generated pages contain no scripts.
package sitebuild

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Templates are the supported structured templates.
var Templates = []string{"landing", "corporate", "portfolio", "documentation", "blog", "app_showcase"}

// Locales supported for path-based localisation, with their direction.
var Locales = map[string]string{"en": "ltr", "fa": "rtl", "ar": "rtl", "de": "ltr", "fr": "ltr", "es": "ltr", "tr": "ltr"}

// L is localised text: locale → text.
type L map[string]string

// Get returns the text for loc, falling back to def.
func (l L) Get(loc, def string) (string, bool) {
	if v := strings.TrimSpace(l[loc]); v != "" {
		return v, true
	}
	return strings.TrimSpace(l[def]), false
}

// Content is a template website's source document.
type Content struct {
	Site  Site   `json:"site"`
	Pages []Page `json:"pages"`
}

// Site holds site-wide settings.
type Site struct {
	Title   L      `json:"title"`
	Tagline L      `json:"tagline,omitempty"`
	Footer  L      `json:"footer,omitempty"`
	BaseURL string `json:"base_url,omitempty"` // https://example.com (canonical URLs, sitemap)
	Accent  string `json:"accent,omitempty"`   // #RRGGBB
}

// Page is one page (or blog post / documentation page).
type Page struct {
	Slug        string  `json:"slug"`           // "" = home
	Kind        string  `json:"kind,omitempty"` // page | post | doc
	Title       L       `json:"title"`
	Description L       `json:"description,omitempty"`
	Date        string  `json:"date,omitempty"` // YYYY-MM-DD (posts)
	Blocks      []Block `json:"blocks"`
	Hidden      bool    `json:"hidden,omitempty"` // not in navigation
}

// Block is one content block.
type Block struct {
	Type    string `json:"type"` // hero | text | features | gallery | cta | faq | quote | links | posts
	Heading L      `json:"heading,omitempty"`
	Text    L      `json:"text,omitempty"`
	Label   L      `json:"label,omitempty"`
	Href    string `json:"href,omitempty"`
	Image   string `json:"image,omitempty"` // media file name
	Items   []Item `json:"items,omitempty"`
}

// Item is an entry of a list block.
type Item struct {
	Title L      `json:"title,omitempty"`
	Text  L      `json:"text,omitempty"`
	Image string `json:"image,omitempty"`
	Href  string `json:"href,omitempty"`
}

var (
	slugRe     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	accentRe   = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	basePathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
	mediaRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}\.(png|jpg|jpeg|gif|webp|avif)$`)
)

var blockTypes = map[string]bool{"hero": true, "text": true, "features": true, "gallery": true, "cta": true, "faq": true, "quote": true, "links": true, "posts": true}

// Limits keep documents and builds bounded.
const (
	MaxPages     = 200
	MaxBlocks    = 60
	MaxItems     = 60
	MaxTextBytes = 20000
)

// SafeURL accepts http(s), mailto, tel, site-relative and fragment links.
func SafeURL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	if len(s) > 2000 || strings.ContainsAny(s, "\x00\r\n\t<>\"'` \\") {
		return "", false
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") {
		return s, true
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return "", false
		}
		return s, true
	case "mailto", "tel":
		return s, true
	}
	return "", false
}

// Validate checks a document against a template and locales. It returns
// errors (blocking) and warnings (e.g. missing translations).
func Validate(c *Content, template string, locales []string, def string, media map[string]bool) (errs []string, warns []string) {
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) }
	if !contains(Templates, template) {
		add("unknown template %q", template)
	}
	if len(locales) == 0 || !contains(locales, def) {
		add("the default locale must be one of the site locales")
	}
	for _, l := range locales {
		if _, ok := Locales[l]; !ok {
			add("unsupported locale %q", l)
		}
	}
	if c.Site.BaseURL != "" {
		u, err := url.Parse(c.Site.BaseURL)
		if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" || !basePathRe.MatchString(u.Path) || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			add("base URL must look like https://example.com or https://example.com/docs")
		}
	} else {
		warn("no base URL: canonical links and the sitemap need absolute URLs and are omitted")
	}
	if c.Site.Accent != "" && !accentRe.MatchString(c.Site.Accent) {
		add("accent colour must be #RRGGBB")
	}
	text := func(where string, l L, required bool) {
		for k, v := range l {
			if !contains(locales, k) {
				warn("%s: text for locale %q that the site does not publish", where, k)
			}
			if len(v) > MaxTextBytes {
				add("%s: text too long", where)
			}
		}
		if required && strings.TrimSpace(l[def]) == "" {
			add("%s: text in the default locale (%s) is required", where, def)
		}
		for _, loc := range locales {
			if loc != def && strings.TrimSpace(l[def]) != "" && strings.TrimSpace(l[loc]) == "" {
				warn("%s: no %s translation (the %s text is used)", where, loc, def)
			}
		}
		for _, v := range l {
			for _, m := range linkRe.FindAllStringSubmatch(v, -1) {
				if _, ok := SafeURL(m[2]); !ok {
					add("%s: unsafe link %q", where, m[2])
				}
			}
		}
	}
	text("site title", c.Site.Title, true)
	text("tagline", c.Site.Tagline, false)
	text("footer", c.Site.Footer, false)
	if len(c.Pages) == 0 {
		add("at least one page is required")
	}
	if len(c.Pages) > MaxPages {
		add("too many pages (max %d)", MaxPages)
	}
	seen := map[string]bool{}
	home := false
	for i, p := range c.Pages {
		w := fmt.Sprintf("page %d", i+1)
		if p.Slug == "" {
			home = true
		} else if !slugRe.MatchString(p.Slug) || p.Slug == "assets" || p.Slug == "media" || Locales[p.Slug] != "" {
			add("%s: slug %q must be lowercase letters, digits and dashes (and not a reserved name)", w, p.Slug)
		}
		if seen[p.Slug] {
			add("%s: duplicate slug %q", w, p.Slug)
		}
		seen[p.Slug] = true
		switch p.Kind {
		case "", "page", "post", "doc":
		default:
			add("%s: kind must be page, post or doc", w)
		}
		if p.Date != "" && !dateRe.MatchString(p.Date) {
			add("%s: date must be YYYY-MM-DD", w)
		}
		text(w+" title", p.Title, true)
		text(w+" description", p.Description, false)
		if len(p.Blocks) > MaxBlocks {
			add("%s: too many blocks", w)
		}
		for j, b := range p.Blocks {
			bw := fmt.Sprintf("%s block %d", w, j+1)
			if !blockTypes[b.Type] {
				add("%s: unknown block type %q", bw, b.Type)
				continue
			}
			text(bw+" heading", b.Heading, false)
			text(bw+" text", b.Text, false)
			text(bw+" label", b.Label, false)
			if _, ok := SafeURL(b.Href); !ok {
				add("%s: unsafe link %q", bw, b.Href)
			}
			if b.Image != "" && (!mediaRe.MatchString(b.Image) || !media[b.Image]) {
				add("%s: image %q is not in the media library", bw, b.Image)
			}
			if len(b.Items) > MaxItems {
				add("%s: too many items", bw)
			}
			for k, it := range b.Items {
				iw := fmt.Sprintf("%s item %d", bw, k+1)
				text(iw+" title", it.Title, false)
				text(iw+" text", it.Text, false)
				if _, ok := SafeURL(it.Href); !ok {
					add("%s: unsafe link %q", iw, it.Href)
				}
				if it.Image != "" && (!mediaRe.MatchString(it.Image) || !media[it.Image]) {
					add("%s: image %q is not in the media library", iw, it.Image)
				}
			}
		}
	}
	if !home && len(c.Pages) > 0 {
		add("a home page (empty slug) is required")
	}
	return errs, warns
}

// ValidMediaName reports whether a media file name is acceptable.
func ValidMediaName(n string) bool { return mediaRe.MatchString(n) }

// ErrInvalid wraps validation failures.
var ErrInvalid = errors.New("website content is invalid")

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func sortedPages(ps []Page) []Page {
	out := append([]Page(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Slug == "" {
			return true
		}
		if out[j].Slug == "" {
			return false
		}
		return false
	})
	return out
}
