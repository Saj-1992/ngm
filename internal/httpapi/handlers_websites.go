package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/sitebuild"
	"github.com/ngm-gateway/ngm/internal/websites"
)

// Must match deploy.KindSite*.
const (
	jobKindSiteBuild   = "website.build"
	jobKindSitePublish = "website.publish"
	jobKindSiteDelete  = "website.delete"
)

func (s *Server) registerWebsiteRoutes() {
	s.handle("GET", "/api/v1/websites/templates", "websites.read", s.websiteTemplates)
	s.handle("GET", "/api/v1/websites", "websites.read", s.listWebsites)
	s.handle("POST", "/api/v1/websites", "websites.write", s.createWebsite)
	s.handle("GET", "/api/v1/websites/{id}", "websites.read", s.getWebsite)
	s.handle("PATCH", "/api/v1/websites/{id}", "websites.write", s.patchWebsite)
	s.handle("DELETE", "/api/v1/websites/{id}", "websites.write", s.deleteWebsite)
	s.handle("PUT", "/api/v1/websites/{id}/content", "websites.write", s.putWebsiteContent)
	s.handle("GET", "/api/v1/websites/{id}/media", "websites.read", s.listWebsiteMedia)
	s.handle("POST", "/api/v1/websites/{id}/media", "websites.write", s.addWebsiteMedia)
	s.handle("GET", "/api/v1/websites/{id}/media/{name}", "websites.read", s.getWebsiteMedia)
	s.handle("DELETE", "/api/v1/websites/{id}/media/{name}", "websites.write", s.deleteWebsiteMedia)
	s.handle("POST", "/api/v1/websites/{id}/upload", "websites.write", s.uploadWebsite)
	s.handle("POST", "/api/v1/websites/{id}/build", "websites.write", s.buildWebsite)
	s.handle("GET", "/api/v1/websites/{id}/versions", "websites.read", s.websiteVersions)
	s.handle("POST", "/api/v1/websites/{id}/publish", "websites.write", s.publishWebsite)
	s.handle("POST", "/api/v1/websites/{id}/versions/{vid}/preview", "websites.read", s.previewLink)
	// Public route: authorised by the signed, expiring token in the path
	// (sandboxed previews have an opaque origin and carry no cookies).
	s.handle("GET", "/api/v1/preview/{id}/{vid}/{token}/{path...}", "", s.previewWebsite)
}

func (s *Server) sites() *websites.Service {
	return &websites.Service{DB: s.d.DB, Audit: s.d.Audit, Root: s.d.Config.Paths.Websites}
}

func mapSiteError(err error) error {
	var ve *websites.ValidationError
	switch {
	case errors.As(err, &ve):
		return apierr.BadRequest(ve.Msg)
	case errors.Is(err, websites.ErrNotFound):
		return apierr.NotFound("website")
	case errors.Is(err, websites.ErrStale):
		return apierr.PreconditionFailed()
	case errors.Is(err, websites.ErrConflict), errors.Is(err, websites.ErrInUse):
		return apierr.Conflict(err.Error())
	}
	return err
}

func (s *Server) websiteTemplates(w http.ResponseWriter, r *http.Request) error {
	return writeJSON(w, http.StatusOK, map[string]any{"templates": sitebuild.Templates, "locales": sitebuild.Locales})
}

func (s *Server) listWebsites(w http.ResponseWriter, r *http.Request) error {
	items, err := s.sites().List(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type websiteIn struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	Template      string   `json:"template"`
	DefaultLocale string   `json:"default_locale"`
	Locales       []string `json:"locales"`
}

func (s *Server) createWebsite(w http.ResponseWriter, r *http.Request) error {
	var in websiteIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	site, err := s.sites().Create(r.Context(), PrincipalFrom(r.Context()), in.Name, in.Kind, in.Template, in.DefaultLocale, in.Locales)
	if err != nil {
		return mapSiteError(err)
	}
	return writeEntity(w, http.StatusCreated, site.Revision, site)
}

func (s *Server) getWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	site, err := s.sites().Get(r.Context(), id)
	if err != nil {
		return mapSiteError(err)
	}
	var errs, warns []string
	if site.Content != nil {
		media := map[string]bool{}
		ms, _ := s.sites().ListMedia(r.Context(), id)
		for _, m := range ms {
			media[m.Name] = true
		}
		errs, warns = sitebuild.Validate(site.Content, site.Template, site.Locales, site.DefaultLocale, media)
	}
	used, _ := s.sites().InUse(r.Context(), id)
	w.Header().Set("ETag", ETag(site.Revision))
	return writeJSON(w, http.StatusOK, map[string]any{"website": site, "errors": nonNil(errs), "warnings": nonNil(warns), "routes": nonNil(used)})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) patchWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in websiteIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	site, err := s.sites().Update(r.Context(), PrincipalFrom(r.Context()), id, rev, in.Name, in.DefaultLocale, in.Locales)
	if err != nil {
		return mapSiteError(err)
	}
	return writeEntity(w, http.StatusOK, site.Revision, site)
}

func (s *Server) deleteWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if _, err := s.sites().Get(r.Context(), id); err != nil {
		return mapSiteError(err)
	}
	if used, _ := s.sites().InUse(r.Context(), id); len(used) > 0 {
		return apierr.Conflict("routes still serve this website: " + strings.Join(used, ", "))
	}
	return s.submitJob(w, r, jobKindSiteDelete, []string{"website-publish"}, map[string]string{"website_id": id})
}

func (s *Server) putWebsiteContent(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	}
	dr, err := strconv.ParseInt(r.Header.Get("X-Draft-Revision"), 10, 64)
	if err != nil || dr < 1 {
		return apierr.New(http.StatusPreconditionRequired, "precondition_required", "X-Draft-Revision header required")
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "content too large")
		}
		return err
	}
	site, errs, warns, err := s.sites().SaveContent(r.Context(), PrincipalFrom(r.Context()), id, dr, raw)
	if err != nil {
		return mapSiteError(err)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"website": site, "errors": nonNil(errs), "warnings": nonNil(warns)})
}

func (s *Server) listWebsiteMedia(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	ms, err := s.sites().ListMedia(r.Context(), id)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": ms})
}

// addWebsiteMedia takes the raw image as the body (?name=original-file-name).
func (s *Server) addWebsiteMedia(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "image larger than 5 MiB")
		}
		return err
	}
	m, err := s.sites().AddMedia(r.Context(), PrincipalFrom(r.Context()), id, r.URL.Query().Get("name"), data)
	if err != nil {
		return mapSiteError(err)
	}
	return writeJSON(w, http.StatusCreated, m)
}

func (s *Server) getWebsiteMedia(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	p, err := s.sites().MediaPath(id, r.PathValue("name"))
	if err != nil {
		return mapSiteError(err)
	}
	ct := mime.TypeByExtension(filepath.Ext(p))
	if !strings.HasPrefix(ct, "image/") {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=60")
	http.ServeFile(w, r, p)
	return nil
}

func (s *Server) deleteWebsiteMedia(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.sites().DeleteMedia(r.Context(), PrincipalFrom(r.Context()), id, r.PathValue("name")); err != nil {
		return mapSiteError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// uploadWebsite stores a ZIP (application/zip body). The archive is only
// validated and extracted by the worker during the build job.
func (s *Server) uploadWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	ct := r.Header.Get("Content-Type")
	if ct != "application/zip" && ct != "application/x-zip-compressed" && ct != "application/octet-stream" {
		return apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "upload the archive as application/zip")
	}
	n, err := s.sites().SaveUpload(r.Context(), PrincipalFrom(r.Context()), id, r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "archive larger than 50 MiB")
		}
		return mapSiteError(err)
	}
	return writeJSON(w, http.StatusCreated, map[string]any{"bytes": n, "note": "the archive is validated when you build"})
}

func (s *Server) buildWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if _, err := s.sites().Get(r.Context(), id); err != nil {
		return mapSiteError(err)
	}
	return s.submitJob(w, r, jobKindSiteBuild, []string{"website-publish"}, map[string]string{"website_id": id})
}

func (s *Server) websiteVersions(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	vs, err := s.sites().Versions(r.Context(), id)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": vs})
}

type publishIn struct {
	VersionID string `json:"version_id"`
}

func (s *Server) publishWebsite(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in publishIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if !ids.Valid(in.VersionID) {
		return apierr.BadRequest("invalid version_id")
	}
	if _, err := s.sites().GetVersion(r.Context(), id, in.VersionID); err != nil {
		return mapSiteError(err)
	}
	return s.submitJob(w, r, jobKindSitePublish, []string{"website-publish"}, map[string]string{"website_id": id, "version_id": in.VersionID})
}

// previewCSP isolates previewed content: "sandbox" gives the document an
// opaque origin (no access to NGM cookies, storage or same-origin API
// calls) even when the URL is opened directly; scripts of uploaded static
// sites may run inside that sandbox but cannot reach NGM.
const previewCSP = "sandbox allow-scripts allow-popups; default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'none'; form-action 'none'; base-uri 'self'; frame-ancestors 'self'"

const previewTTL = 30 * time.Minute

func (s *Server) previewToken(site, vid string, exp time.Time) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(exp.Unix()))
	m := hmac.New(sha256.New, s.previewKey)
	m.Write([]byte("ngm-preview|" + site + "|" + vid + "|"))
	m.Write(b[:])
	return base64.RawURLEncoding.EncodeToString(append(b[:], m.Sum(nil)[:16]...))
}

func (s *Server) checkPreviewToken(site, vid, tok string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 24 {
		return false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	if time.Now().After(exp) || exp.Sub(time.Now()) > previewTTL+time.Minute {
		return false
	}
	return hmac.Equal([]byte(s.previewToken(site, vid, exp)), []byte(tok))
}

// previewLink issues a short-lived link to a built version.
func (s *Server) previewLink(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	vid := r.PathValue("vid")
	if !ids.Valid(vid) {
		return apierr.BadRequest("invalid version id")
	}
	if _, err := s.sites().GetVersion(r.Context(), id, vid); err != nil {
		return mapSiteError(err)
	}
	exp := time.Now().Add(previewTTL)
	u := "/api/v1/preview/" + id + "/" + vid + "/" + s.previewToken(id, vid, exp) + "/"
	return writeJSON(w, http.StatusOK, map[string]any{"url": u, "expires_at": exp.UTC()})
}

func (s *Server) previewWebsite(w http.ResponseWriter, r *http.Request) error {
	id, vid := r.PathValue("id"), r.PathValue("vid")
	if !ids.Valid(id) || !ids.Valid(vid) || !s.checkPreviewToken(id, vid, r.PathValue("token")) {
		return apierr.NotFound("preview")
	}
	if _, err := s.sites().GetVersion(r.Context(), id, vid); err != nil {
		return mapSiteError(err)
	}
	rel := path.Clean("/" + r.PathValue("path"))
	if strings.Contains(rel, "\x00") {
		return apierr.NotFound("file")
	}
	root := s.sites().BuildDir(id, vid)
	p := filepath.Join(root, filepath.FromSlash(rel))
	if p != root && !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		return apierr.NotFound("file")
	}
	st, err := os.Lstat(p)
	if err == nil && st.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
			return nil
		}
		p = filepath.Join(p, "index.html")
		st, err = os.Lstat(p)
	}
	if err != nil || !st.Mode().IsRegular() {
		return apierr.NotFound("file")
	}
	h := w.Header()
	h.Set("Content-Security-Policy", previewCSP)
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	ct := mime.TypeByExtension(filepath.Ext(p))
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	f, err := os.Open(p)
	if err != nil {
		return apierr.NotFound("file")
	}
	defer f.Close()
	http.ServeContent(w, r, "", st.ModTime(), f)
	return nil
}
