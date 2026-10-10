// Package websites stores websites (MASTER_SPEC §6.3): template drafts and
// uploaded static archives, media, immutable built versions and their
// publication state. Files live under /var/lib/ngm/websites/<site>/:
//
//	media/<name>            uploaded images (template sites)
//	uploads/pending.zip     the latest uploaded archive (static sites)
//	builds/<version>/...    immutable build output (preview + publish source)
//
// Publishing copies a build into the Nginx-readable public tree through the
// helper (see the website.* helper operations).
package websites

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/sitebuild"
	"github.com/ngm-gateway/ngm/internal/sitezip"
	"github.com/ngm-gateway/ngm/internal/store"
)

var (
	ErrNotFound = errors.New("website not found")
	ErrStale    = errors.New("revision changed")
	ErrConflict = errors.New("conflict")
	ErrInUse    = errors.New("website is in use")
)

// ValidationError is a client-safe input problem.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{fmt.Sprintf(f, a...)} }

// Limits.
const (
	MaxMediaBytes      = 5 << 20
	MaxMediaTotal      = 200 << 20
	MaxUploadBytes     = 50 << 20
	MaxContentJSON     = 2 << 20
	KeepVersions       = 10
	MaxSites           = 200
	StatusBuilt        = "built"
	StatusPublished    = "published"
	StatusSuperseded   = "superseded"
	StatusFailed       = "failed"
	KindTemplate       = "template"
	KindStaticZip      = "static_zip"
	pendingUploadName  = "pending.zip"
	versionDirsSubpath = "builds"
)

// Website is a site record.
type Website struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Kind            string             `json:"kind"`
	Template        string             `json:"template,omitempty"`
	DefaultLocale   string             `json:"default_locale"`
	Locales         []string           `json:"locales"`
	ActiveVersionID string             `json:"active_version_id,omitempty"`
	DraftRevision   int64              `json:"draft_revision"`
	Revision        int64              `json:"revision"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
	Content         *sitebuild.Content `json:"content,omitempty"`
	HasUpload       bool               `json:"has_upload"`
}

// Version is an immutable build.
type Version struct {
	ID          string          `json:"id"`
	Number      int64           `json:"number"`
	Status      string          `json:"status"`
	ContentHash string          `json:"content_hash"`
	Size        int64           `json:"size_bytes"`
	Manifest    json.RawMessage `json:"manifest"`
	CreatedBy   string          `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	PublishedAt *time.Time      `json:"published_at,omitempty"`
}

// Media is a media library entry.
type Media struct {
	Name      string    `json:"name"`
	MIME      string    `json:"mime"`
	Size      int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Service manages websites.
type Service struct {
	DB    *store.DB
	Audit *audit.Logger
	Root  string // /var/lib/ngm/websites
}

func (s *Service) dir(id string, parts ...string) string {
	return filepath.Join(append([]string{s.Root, id}, parts...)...)
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor *auth.Principal, action, id string, c map[string]any) error {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: "website", TargetID: id, Result: "success", Context: c, RequestID: auth.RequestIDFrom(ctx)}
	if actor != nil {
		e.ActorKind, e.ActorID = actor.Kind, actor.UserID
	}
	_, err := s.Audit.RecordTx(ctx, tx, e)
	return err
}

var nameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$`)

const cols = "id,name,kind,COALESCE(template,''),default_locale,locales_json,COALESCE(active_version_id,''),draft_revision,revision,created_at,updated_at"

func scan(sc interface{ Scan(...any) error }) (*Website, error) {
	var w Website
	var lj, c, u string
	if err := sc.Scan(&w.ID, &w.Name, &w.Kind, &w.Template, &w.DefaultLocale, &lj, &w.ActiveVersionID, &w.DraftRevision, &w.Revision, &c, &u); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(lj), &w.Locales)
	w.CreatedAt, _ = store.ParseTime(c)
	w.UpdatedAt, _ = store.ParseTime(u)
	return &w, nil
}

// List returns all websites (without content).
func (s *Service) List(ctx context.Context) ([]*Website, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+cols+" FROM websites ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Website{}
	for rows.Next() {
		w, err := scan(rows)
		if err != nil {
			return nil, err
		}
		w.HasUpload = s.hasUpload(w.ID)
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Service) hasUpload(id string) bool {
	_, err := os.Stat(s.dir(id, "uploads", pendingUploadName))
	return err == nil
}

// Get returns a website with its draft content.
func (s *Service) Get(ctx context.Context, id string) (*Website, error) {
	var cj string
	w, err := scan(s.DB.QueryRowContext(ctx, "SELECT "+cols+" FROM websites WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = s.DB.QueryRowContext(ctx, "SELECT content_json FROM websites WHERE id=?", id).Scan(&cj)
	if w.Kind == KindTemplate {
		w.Content = &sitebuild.Content{}
		_ = json.Unmarshal([]byte(cj), w.Content)
	}
	w.HasUpload = s.hasUpload(id)
	return w, nil
}

func checkLocales(def string, locs []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, l := range locs {
		if _, ok := sitebuild.Locales[l]; !ok {
			return nil, invalid("unsupported locale %q", l)
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	if len(out) == 0 || !seen[def] {
		return nil, invalid("the default locale must be one of the locales")
	}
	return out, nil
}

// Create adds a website (template sites start from the template's starter content).
func (s *Service) Create(ctx context.Context, actor *auth.Principal, name, kind, template, def string, locales []string) (*Website, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return nil, invalid("name must be 1–64 letters, digits, spaces, dots, dashes or underscores")
	}
	locs, err := checkLocales(def, locales)
	if err != nil {
		return nil, err
	}
	var content []byte
	var tpl any
	switch kind {
	case KindTemplate:
		ok := false
		for _, t := range sitebuild.Templates {
			ok = ok || t == template
		}
		if !ok {
			return nil, invalid("unknown template %q", template)
		}
		content, _ = json.Marshal(sitebuild.Starter(template))
		tpl = template
	case KindStaticZip:
		content = []byte("{}")
	default:
		return nil, invalid("kind must be template or static_zip")
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM websites").Scan(&n)
	if n >= MaxSites {
		return nil, invalid("too many websites (max %d)", MaxSites)
	}
	id := ids.New()
	lj, _ := json.Marshal(locs)
	now := store.FormatTime(time.Now())
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO websites(id,name,kind,template,default_locale,locales_json,content_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			id, name, kind, tpl, def, string(lj), string(content), now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: a website with this name exists", ErrConflict)
			}
			return err
		}
		return s.auditTx(ctx, tx, actor, "website.create", id, map[string]any{"name": name, "kind": kind, "template": template})
	})
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"media", "uploads", versionDirsSubpath} {
		if err := os.MkdirAll(s.dir(id, d), 0o770); err != nil {
			return nil, err
		}
	}
	return s.Get(ctx, id)
}

// Update changes name and locales.
func (s *Service) Update(ctx context.Context, actor *auth.Principal, id string, rev int64, name, def string, locales []string) (*Website, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return nil, invalid("invalid name")
	}
	locs, err := checkLocales(def, locales)
	if err != nil {
		return nil, err
	}
	lj, _ := json.Marshal(locs)
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE websites SET name=?, default_locale=?, locales_json=?, revision=revision+1, updated_at=? WHERE id=? AND revision=?",
			name, def, string(lj), store.FormatTime(time.Now()), id, rev)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: a website with this name exists", ErrConflict)
			}
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return s.missingOrStale(ctx, tx, id)
		}
		return s.auditTx(ctx, tx, actor, "website.update", id, map[string]any{"locales": locs})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Service) missingOrStale(ctx context.Context, tx *sql.Tx, id string) error {
	var n int
	_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM websites WHERE id=?", id).Scan(&n)
	if n == 0 {
		return ErrNotFound
	}
	return ErrStale
}

// SaveContent stores a template draft (optimistic on draft_revision). It
// returns validation problems for the editor; drafts may be incomplete.
func (s *Service) SaveContent(ctx context.Context, actor *auth.Principal, id string, draftRev int64, raw []byte) (*Website, []string, []string, error) {
	if len(raw) > MaxContentJSON {
		return nil, nil, nil, invalid("content too large")
	}
	w, err := s.Get(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if w.Kind != KindTemplate {
		return nil, nil, nil, invalid("only template websites have editable content")
	}
	var c sitebuild.Content
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, nil, nil, invalid("content is not valid: %v", err)
	}
	norm, _ := json.Marshal(c)
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE websites SET content_json=?, draft_revision=draft_revision+1, updated_at=? WHERE id=? AND draft_revision=?",
			string(norm), store.FormatTime(time.Now()), id, draftRev)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return s.missingOrStale(ctx, tx, id)
		}
		return s.auditTx(ctx, tx, actor, "website.content_save", id, map[string]any{"pages": len(c.Pages)})
	})
	if err != nil {
		return nil, nil, nil, err
	}
	errs, warns := sitebuild.Validate(&c, w.Template, w.Locales, w.DefaultLocale, s.mediaSet(id))
	w, err = s.Get(ctx, id)
	return w, errs, warns, err
}

// ─── media ─────────────────────────────────────────────────────────────────

var imageTypes = []struct {
	mime, ext string
	magic     func([]byte) bool
}{
	{"image/png", ".png", func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) }},
	{"image/jpeg", ".jpg", func(b []byte) bool { return bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}) }},
	{"image/gif", ".gif", func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
	}},
	{"image/webp", ".webp", func(b []byte) bool { return len(b) > 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" }},
	{"image/avif", ".avif", func(b []byte) bool {
		return len(b) > 12 && string(b[4:8]) == "ftyp" && strings.HasPrefix(string(b[8:12]), "avi")
	}},
}

var unsafeChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// MediaName derives a safe library name from an uploaded file name.
func MediaName(orig, ext string) string {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.ReplaceAll(orig, "\\", "/")), filepath.Ext(orig)))
	base = strings.Trim(unsafeChars.ReplaceAllString(base, "-"), "-._")
	if base == "" {
		base = "image"
	}
	if len(base) > 80 {
		base = base[:80]
	}
	return base + ext
}

func (s *Service) mediaSet(id string) map[string]bool {
	out := map[string]bool{}
	es, _ := os.ReadDir(s.dir(id, "media"))
	for _, e := range es {
		if e.Type().IsRegular() && sitebuild.ValidMediaName(e.Name()) {
			out[e.Name()] = true
		}
	}
	return out
}

// AddMedia stores an image after checking its real type (SVG is refused:
// it can carry scripts).
func (s *Service) AddMedia(ctx context.Context, actor *auth.Principal, id, orig string, data []byte) (*Media, error) {
	w, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if w.Kind != KindTemplate {
		return nil, invalid("media libraries belong to template websites; static sites ship their files in the ZIP")
	}
	if len(data) == 0 || len(data) > MaxMediaBytes {
		return nil, invalid("images must be 1 byte – %d MiB", MaxMediaBytes>>20)
	}
	var mime, ext string
	for _, t := range imageTypes {
		if t.magic(data) {
			mime, ext = t.mime, t.ext
			break
		}
	}
	if mime == "" {
		return nil, invalid("only PNG, JPEG, GIF, WebP and AVIF images are accepted (SVG can contain scripts)")
	}
	var total int64
	for n := range s.mediaSet(id) {
		if st, err := os.Stat(s.dir(id, "media", n)); err == nil {
			total += st.Size()
		}
	}
	if total+int64(len(data)) > MaxMediaTotal {
		return nil, invalid("the media library is full (%d MiB)", MaxMediaTotal>>20)
	}
	name := MediaName(orig, ext)
	if _, err := os.Stat(s.dir(id, "media", name)); err == nil {
		name = strings.TrimSuffix(name, ext) + "-" + strings.ToLower(ids.New()[20:]) + ext
	}
	if !sitebuild.ValidMediaName(name) {
		return nil, invalid("invalid media name")
	}
	if err := os.MkdirAll(s.dir(id, "media"), 0o770); err != nil {
		return nil, err
	}
	if err := writeExclusive(s.dir(id, "media", name), data); err != nil {
		return nil, err
	}
	sum := sha256hex(data)
	now := time.Now()
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO website_media(id,website_id,name,mime,size_bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
			ids.New(), id, name, mime, len(data), sum, store.FormatTime(now)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "website.media_add", id, map[string]any{"name": name, "size": len(data)})
	})
	if err != nil {
		_ = os.Remove(s.dir(id, "media", name))
		return nil, err
	}
	return &Media{Name: name, MIME: mime, Size: int64(len(data)), SHA256: sum, CreatedAt: now}, nil
}

// ListMedia lists the library.
func (s *Service) ListMedia(ctx context.Context, id string) ([]Media, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT name,mime,size_bytes,sha256,created_at FROM website_media WHERE website_id=? ORDER BY name", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Media{}
	for rows.Next() {
		var m Media
		var c string
		if err := rows.Scan(&m.Name, &m.MIME, &m.Size, &m.SHA256, &c); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = store.ParseTime(c)
		out = append(out, m)
	}
	return out, rows.Err()
}

// MediaPath returns the file of a library entry (for serving in the editor).
func (s *Service) MediaPath(id, name string) (string, error) {
	if !sitebuild.ValidMediaName(name) {
		return "", ErrNotFound
	}
	p := s.dir(id, "media", name)
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return "", ErrNotFound
	}
	return p, nil
}

// DeleteMedia removes an entry (published versions keep their own copy).
func (s *Service) DeleteMedia(ctx context.Context, actor *auth.Principal, id, name string) error {
	p, err := s.MediaPath(id, name)
	if err != nil {
		return err
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM website_media WHERE website_id=? AND name=?", id, name); err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return s.auditTx(ctx, tx, actor, "website.media_delete", id, map[string]any{"name": name})
	})
}

// SaveUpload stores an uploaded static-site archive (validated at build time
// by the worker, never extracted by the API).
func (s *Service) SaveUpload(ctx context.Context, actor *auth.Principal, id string, r io.Reader) (int64, error) {
	w, err := s.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	if w.Kind != KindStaticZip {
		return 0, invalid("this website is built from a template, not from an uploaded archive")
	}
	if err := os.MkdirAll(s.dir(id, "uploads"), 0o770); err != nil {
		return 0, err
	}
	final := s.dir(id, "uploads", pendingUploadName)
	tmp := final + "." + ids.New() + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxUploadBytes+1))
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if n > MaxUploadBytes {
		_ = os.Remove(tmp)
		return 0, invalid("archive larger than %d MiB", MaxUploadBytes>>20)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	_, _ = s.Audit.Record(ctx, audit.Event{ActorKind: "user", ActorID: actorID(actor), Action: "website.upload", TargetKind: "website", TargetID: id, Result: "success",
		Context: map[string]any{"bytes": n}})
	return n, nil
}

func actorID(a *auth.Principal) string {
	if a == nil {
		return ""
	}
	return a.UserID
}

// ─── versions ──────────────────────────────────────────────────────────────

const vcols = "id,number,status,COALESCE(content_hash,''),size_bytes,manifest_json,COALESCE(created_by,''),created_at,published_at"

func scanVersion(sc interface{ Scan(...any) error }) (*Version, error) {
	var v Version
	var c string
	var p sql.NullString
	var m string
	if err := sc.Scan(&v.ID, &v.Number, &v.Status, &v.ContentHash, &v.Size, &m, &v.CreatedBy, &c, &p); err != nil {
		return nil, err
	}
	v.Manifest = json.RawMessage(m)
	v.CreatedAt, _ = store.ParseTime(c)
	if p.Valid {
		t, _ := store.ParseTime(p.String)
		v.PublishedAt = &t
	}
	return &v, nil
}

// Versions lists builds, newest first.
func (s *Service) Versions(ctx context.Context, id string) ([]*Version, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+vcols+" FROM website_versions WHERE website_id=? ORDER BY number DESC", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVersion loads one version of a site.
func (s *Service) GetVersion(ctx context.Context, id, vid string) (*Version, error) {
	v, err := scanVersion(s.DB.QueryRowContext(ctx, "SELECT "+vcols+" FROM website_versions WHERE website_id=? AND id=?", id, vid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// BuildDir is where a version's files live.
func (s *Service) BuildDir(id, vid string) string { return s.dir(id, versionDirsSubpath, vid) }

// BuildResult describes a new version.
type BuildResult struct {
	Version  *Version `json:"version"`
	Warnings []string `json:"warnings"`
	Reused   bool     `json:"reused"` // identical content was already built
}

// Build creates an immutable version from the current draft (template) or
// pending upload (static archive). Identical content reuses the version.
func (s *Service) Build(ctx context.Context, id, actor, jobID string) (*BuildResult, error) {
	w, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	vid := ids.New()
	dest := s.BuildDir(id, vid)
	if err := os.MkdirAll(filepath.Dir(dest), 0o770); err != nil {
		return nil, err
	}
	var hash string
	var size int64
	var manifest any
	var warns []string
	switch w.Kind {
	case KindTemplate:
		media := map[string][]byte{}
		used := usedMedia(w.Content)
		for n := range used {
			p, err := s.MediaPath(id, n)
			if err != nil {
				return nil, invalid("image %q is not in the media library", n)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			media[n] = b
		}
		out, err := sitebuild.Build(sitebuild.Input{Content: w.Content, Template: w.Template, Locales: w.Locales, Default: w.DefaultLocale, Media: media})
		if err != nil {
			return nil, invalid("%v", err)
		}
		if err := writeTree(dest, out.Files); err != nil {
			_ = os.RemoveAll(dest)
			return nil, err
		}
		hash, size, warns = out.Hash, out.Size, out.Warnings
		manifest = fileList(out.Files)
	case KindStaticZip:
		p := s.dir(id, "uploads", pendingUploadName)
		f, err := os.Open(p)
		if err != nil {
			return nil, invalid("upload a ZIP archive first")
		}
		st, _ := f.Stat()
		res, err := sitezip.Extract(f, st.Size(), dest, sitezip.DefaultLimits)
		f.Close()
		if err != nil {
			return nil, invalid("%v", err)
		}
		hash, size, warns, manifest = res.Hash, res.Total, res.Warnings, res.Files
	}
	// Identical content → reuse the existing version (deterministic builds).
	var existing string
	_ = s.DB.QueryRowContext(ctx, "SELECT id FROM website_versions WHERE website_id=? AND content_hash=? AND status<>'failed' ORDER BY number DESC LIMIT 1", id, hash).Scan(&existing)
	if existing != "" {
		if _, err := os.Stat(s.BuildDir(id, existing)); err == nil {
			_ = os.RemoveAll(dest)
			v, err := s.GetVersion(ctx, id, existing)
			return &BuildResult{Version: v, Warnings: warns, Reused: true}, err
		}
	}
	mj, _ := json.Marshal(manifest)
	var by any
	if actor != "" {
		by = actor
	}
	now := store.FormatTime(time.Now())
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(number),0)+1 FROM website_versions WHERE website_id=?", id).Scan(&n); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO website_versions(id,website_id,number,status,content_hash,created_by,created_at,updated_at,source_json,manifest_json,size_bytes,job_id)
			VALUES(?,?,?,'built',?,?,?,?,'{}',?,?,?)`, vid, id, n, hash, by, now, now, string(mj), size, jobID)
		return err
	})
	if err != nil {
		_ = os.RemoveAll(dest)
		return nil, err
	}
	v, err := s.GetVersion(ctx, id, vid)
	return &BuildResult{Version: v, Warnings: warns}, err
}

// MarkPublished records the active version (previous published → superseded).
func (s *Service) MarkPublished(ctx context.Context, id, vid string) error {
	now := store.FormatTime(time.Now())
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE website_versions SET status='superseded', updated_at=? WHERE website_id=? AND status='published' AND id<>?", now, id, vid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE website_versions SET status='published', published_at=?, updated_at=? WHERE website_id=? AND id=?", now, now, id, vid); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE websites SET active_version_id=?, updated_at=? WHERE id=?", vid, now, id)
		return err
	})
}

// Prune removes old unpublished build directories and records, keeping the
// newest KeepVersions plus anything in keep.
func (s *Service) Prune(ctx context.Context, id string, keep map[string]bool) ([]string, error) {
	vs, err := s.Versions(ctx, id)
	if err != nil {
		return nil, err
	}
	var removed []string
	for i, v := range vs {
		if i < KeepVersions || keep[v.ID] || v.Status == StatusPublished {
			continue
		}
		_ = os.RemoveAll(s.BuildDir(id, v.ID))
		if _, err := s.DB.ExecContext(ctx, "DELETE FROM website_versions WHERE id=?", v.ID); err == nil {
			removed = append(removed, v.ID)
		}
	}
	return removed, nil
}

// InUse lists routes that serve the website.
func (s *Service) InUse(ctx context.Context, id string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT name FROM routes WHERE destination_kind='website' AND destination_id=?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if gwstore.GetFallback(ctx, s.DB).WebsiteID == id {
		out = append(out, "(fallback website)")
	}
	return out, nil
}

// DeleteRecord removes the DB record and local files (published files are
// removed by the helper first).
func (s *Service) DeleteRecord(ctx context.Context, actor *auth.Principal, id string) error {
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM websites WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "website.delete", id, nil)
	})
	if err == nil {
		_ = os.RemoveAll(s.dir(id))
	}
	return err
}

func usedMedia(c *sitebuild.Content) map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	for _, p := range c.Pages {
		for _, b := range p.Blocks {
			if b.Image != "" {
				out[b.Image] = true
			}
			for _, it := range b.Items {
				if it.Image != "" {
					out[it.Image] = true
				}
			}
		}
	}
	return out
}

type fileEntry struct {
	Path   string `json:"path"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func fileList(files map[string][]byte) []fileEntry {
	out := make([]fileEntry, 0, len(files))
	for p, b := range files {
		out = append(out, fileEntry{Path: p, Size: len(b), SHA256: sha256hex(b)})
	}
	sortEntries(out)
	return out
}

func writeTree(dest string, files map[string][]byte) error {
	if err := os.Mkdir(dest, 0o750); err != nil {
		return err
	}
	for rel, b := range files {
		p := filepath.Join(dest, filepath.FromSlash(rel))
		if !strings.HasPrefix(p, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("path %q escapes the build directory", rel)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := writeExclusive(p, b); err != nil {
			return err
		}
	}
	return nil
}

func writeExclusive(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
