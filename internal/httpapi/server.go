// Package httpapi implements the /api/v1 REST surface (MASTER_SPEC §12).
//
// Request handlers in this package never execute system commands; mutations
// are submitted as jobs and carried out by ngm-ops/ngm-helper. This is
// enforced by TestNoExecInAPIDependencyGraph.
package httpapi

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/sse"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// RouteInfo describes a registered API route (used by the contract test).
type RouteInfo struct {
	Method     string
	Path       string // OpenAPI-style path, e.g. /api/v1/jobs/{id}
	Permission string // "" means public
}

// Deps are the server's collaborators.
type Deps struct {
	Log    *slog.Logger
	DB     *store.DB
	Jobs   *jobs.Journal
	Locks  *locks.Manager
	Broker *sse.Broker
	Audit  *audit.Logger
	Config config.Config
	Auth   *auth.Service
	Vault  *vault.Vault
	GW     *gwstore.Service
	UI     fs.FS // built SPA (may be nil or lack index.html)
	// LogIndexPath overrides the log index location (tests).
	LogIndexPath string
	// Now is the clock (tests); defaults to time.Now.
	Now func() time.Time
}

// Server is the API HTTP handler.
type Server struct {
	d       Deps
	mux     *http.ServeMux
	routes  []RouteInfo
	handler http.Handler
	limiter *rateLimiter
	// previewKey signs short-lived website preview links (per process).
	previewKey []byte
	// logIndex is the read-only log index handle (opened lazily) and the
	// file it was opened on (a rebuilt index is detected and reopened).
	logIndex     *sql.DB
	logIndexFile os.FileInfo
}

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

// New builds the server and registers all routes.
func New(d Deps) *Server {
	if d.Log == nil {
		d.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{d: d, mux: http.NewServeMux(), limiter: newRateLimiter(30, 120), previewKey: make([]byte, 32)}
	_, _ = rand.Read(s.previewKey)
	s.registerRoutes()
	s.mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, RequestID(r.Context()), apierr.NotFound("endpoint"))
	}))
	s.mux.Handle("/", s.uiHandler())
	s.handler = chain(s.mux,
		withBasePath(d.Config.API.PublicPath),
		withRequestID,
		withRecover(d.Log),
		withSecurityHeaders,
		maxBody(1<<20),
		originGuard(s.allowedOrigins),
		s.authenticate,
		s.rateLimit,
	)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Routes returns registered API routes sorted by path then method.
func (s *Server) Routes() []RouteInfo {
	out := append([]RouteInfo(nil), s.routes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func (s *Server) allowedOrigins(r *http.Request) []string {
	var o []string
	if s.d.Config.API.PublicOrigin != "" {
		o = append(o, strings.ToLower(s.d.Config.API.PublicOrigin))
	}
	// Local/SSH-tunnel bootstrap origins.
	if isDirectLoopback(r) {
		o = append(o, "http://"+strings.ToLower(r.Host))
	}
	return o
}

// handle registers an API route. perm == "" marks a public endpoint; every
// other route requires an authenticated principal holding perm (deny by default).
func (s *Server) handle(method, p, perm string, h handlerFunc) {
	s.routes = append(s.routes, RouteInfo{Method: method, Path: p, Permission: perm})
	s.mux.Handle(method+" "+p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.authorize(r, perm); err != nil {
			apierr.Write(w, RequestID(r.Context()), err)
			return
		}
		if err := mapAuthError(mapGWError(h(w, r))); err != nil {
			var ae *apierr.Error
			if !errors.As(err, &ae) {
				s.d.Log.Error("handler error", "request_id", RequestID(r.Context()), "method", method, "path", p, "err", err)
			}
			apierr.Write(w, RequestID(r.Context()), err)
		}
	}))
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// decodeJSON strictly decodes a JSON request body.
func decodeJSON(r *http.Request, v any) error {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		}
		return apierr.BadRequest("malformed JSON body")
	}
	if dec.More() {
		return apierr.BadRequest("trailing data after JSON body")
	}
	return nil
}

// ETag renders the strong entity tag for a revision.
func ETag(rev int64) string { return `"r` + strconv.FormatInt(rev, 10) + `"` }

// RequireIfMatch enforces optimistic concurrency for a mutation of a resource
// currently at rev: missing header → 428, mismatch → 412.
func RequireIfMatch(r *http.Request, rev int64) error {
	im := r.Header.Get("If-Match")
	if im == "" {
		return apierr.PreconditionRequired()
	}
	if im != ETag(rev) {
		return apierr.PreconditionFailed().WithDetails(map[string]any{"current_etag": ETag(rev)})
	}
	return nil
}

// pageLimit parses ?limit= within [1,200], default 50.
func pageLimit(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 200 {
		return 0, apierr.BadRequest("limit must be an integer between 1 and 200")
	}
	return n, nil
}

func (s *Server) uiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apierr.Write(w, RequestID(r.Context()), apierr.New(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed"))
			return
		}
		if s.d.UI == nil {
			apierr.Write(w, RequestID(r.Context()), apierr.Unavailable("control center UI is not built into this binary"))
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "index.html" {
			s.serveIndex(w, r)
			return
		}
		if f, err := s.d.UI.Open(name); err == nil {
			st, _ := f.Stat()
			f.Close()
			if st != nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, s.d.UI, name)
				return
			}
		}
		// SPA fallback for client-side routes (only extensionless paths).
		if path.Ext(name) != "" {
			apierr.Write(w, RequestID(r.Context()), apierr.NotFound("file"))
			return
		}
		if _, err := fs.Stat(s.d.UI, "index.html"); err != nil {
			apierr.Write(w, RequestID(r.Context()), apierr.Unavailable("control center UI is not built into this binary"))
			return
		}
		s.serveIndex(w, r)
	})
}

// noncePlaceholder is replaced in index.html with a per-response CSP nonce.
const noncePlaceholder = "__NGM_CSP_NONCE__"

// basePlaceholder is replaced with the Control Center base path ("/" or
// "/<public_path>/") so the SPA resolves assets and API calls under its mount.
const basePlaceholder = "__NGM_BASE__"

// serveIndex renders the SPA shell with a fresh nonce. The nonce is allowed
// for <style> elements only (style-src); scripts stay strictly self-hosted.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(s.d.UI, "index.html")
	if err != nil {
		apierr.Write(w, RequestID(r.Context()), apierr.Unavailable("control center UI is not built into this binary"))
		return
	}
	var nb [16]byte
	_, _ = rand.Read(nb[:])
	nonce := base64.StdEncoding.EncodeToString(nb[:])
	h := w.Header()
	h.Set("Content-Security-Policy", strings.Replace(contentSecurityPolicy, "style-src 'self'", "style-src 'self' 'nonce-"+nonce+"'", 1))
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		b = bytes.ReplaceAll(b, []byte(noncePlaceholder), []byte(nonce))
		b = bytes.ReplaceAll(b, []byte(basePlaceholder), []byte(BasePath(r.Context())))
		_, _ = w.Write(b)
	}
}
