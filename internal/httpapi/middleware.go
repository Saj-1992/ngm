package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/ngm-gateway/ngm/internal/apierr"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyPrincipal
	keyBasePath
)

// BasePath returns the URL base the Control Center is served under for this
// request ("/" at the root, or "/<public_path>/" when reached through Nginx).
func BasePath(ctx context.Context) string {
	if s, ok := ctx.Value(keyBasePath).(string); ok && s != "" {
		return s
	}
	return "/"
}

// withBasePath strips the configured public path prefix from the request and
// records the base, so the same handlers serve both the loopback/tunnel root
// and the published "/<public_path>/" mount.
func withBasePath(public string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if public == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := "/"
			if r.URL.Path == public {
				http.Redirect(w, r, public+"/", http.StatusMovedPermanently)
				return
			}
			if rest, ok := strings.CutPrefix(r.URL.Path, public+"/"); ok {
				r.URL.Path = "/" + rest
				base = public + "/"
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyBasePath, base)))
		})
	}
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// RequestID returns the request ID bound to ctx.
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !requestIDPattern.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyRequestID, id)))
	})
}

func withRecover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					// Stack goes to the server log only, never to the client.
					log.Error("panic in handler", "request_id", RequestID(r.Context()), "panic", v, "stack", string(debug.Stack()))
					apierr.Write(w, RequestID(r.Context()), apierr.Internal())
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// contentSecurityPolicy is strict: no inline script, no third-party origins.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originGuard rejects cross-site unsafe requests. Browsers send Origin on
// unsafe requests and Sec-Fetch-Site on all modern requests; if either says
// cross-site, refuse. Bearer-token requests (non-browser) carry neither and
// are handled by token scopes in the auth layer. The double-submit CSRF
// token check is added with cookie sessions (Phase 2).
func originGuard(allowedOrigins func(r *http.Request) []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isUnsafe(r.Method) {
				if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
					apierr.Write(w, RequestID(r.Context()), apierr.CSRF())
					return
				}
				if o := r.Header.Get("Origin"); o != "" {
					if !originAllowed(o, allowedOrigins(r)) {
						apierr.Write(w, RequestID(r.Context()), apierr.CSRF())
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(o string, allowed []string) bool {
	if o == "null" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	norm := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, a := range allowed {
		if strings.EqualFold(a, norm) {
			return true
		}
	}
	return false
}

// maxBody bounds request bodies: n for JSON endpoints, larger fixed
// limits only for the website upload endpoints.
func maxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, bodyLimit(r, n))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bodyLimit(r *http.Request, def int64) int64 {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		return def
	}
	p := r.URL.Path
	if !strings.HasPrefix(p, "/api/v1/websites/") {
		return def
	}
	switch {
	case strings.HasSuffix(p, "/upload"):
		return 50<<20 + 1<<10
	case strings.HasSuffix(p, "/media"):
		return 5<<20 + 1<<10
	case strings.HasSuffix(p, "/content"):
		return 2<<20 + 1<<10
	}
	return def
}

// isDirectLoopback reports whether r arrived straight from a loopback peer and
// was not relayed by a proxy. Nginx's management vhost always sets
// X-Forwarded-For and X-NGM-Proxied, so proxied traffic is never "direct".
func isDirectLoopback(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" ||
		r.Header.Get("X-Real-IP") != "" || r.Header.Get("X-NGM-Proxied") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
