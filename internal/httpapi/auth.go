package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/auth"
)

// Principal is the authenticated caller (see auth.Principal).
type Principal = auth.Principal

const (
	sessionCookie = "ngm_session"
	csrfCookie    = "ngm_csrf"
	csrfHeader    = "X-CSRF-Token"
)

// Pseudo-permissions for routes that need a session but no RBAC permission.
const (
	permAnySession = "@session" // any user session, any stage
	permEnroll     = "@enroll"  // session in mfa_enroll stage
	permPending    = "@pending" // session in pending_mfa stage
	permActiveUser = "@active"  // active interactive user session
)

// PrincipalFrom returns the principal bound to ctx (nil if none).
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(keyPrincipal).(*Principal)
	return p
}

// clientIP is the peer address, or the X-Real-IP set by NGM's own Nginx
// management vhost when the request was relayed.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !isDirectLoopback(r) {
		if v := r.Header.Get("X-Real-IP"); net.ParseIP(v) != nil {
			return v
		}
	}
	return host
}

func clientInfo(r *http.Request) auth.ClientInfo {
	return auth.ClientInfo{IP: clientIP(r), UserAgent: r.UserAgent(), Secure: !isDirectLoopback(r)}
}

// authenticate resolves (in order) a bearer token, a session cookie, or — only
// while no user exists yet — a direct-loopback bootstrap principal with
// read-only access. Cookie-authenticated unsafe requests must carry a valid
// double-submit CSRF token.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithRequestID(r.Context(), RequestID(r.Context()))
		var p *Principal
		var err error
		if h := r.Header.Get("Authorization"); h != "" {
			tok, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				apierr.Write(w, RequestID(ctx), apierr.Unauthenticated())
				return
			}
			if p, err = s.d.Auth.AuthenticateToken(ctx, strings.TrimSpace(tok)); err != nil {
				apierr.Write(w, RequestID(ctx), apierr.Unauthenticated())
				return
			}
		} else if c, cerr := r.Cookie(sessionCookie); cerr == nil && c.Value != "" {
			p, err = s.d.Auth.AuthenticateSession(ctx, c.Value)
			if errors.Is(err, auth.ErrSessionInvalid) {
				clearSessionCookies(w, r)
				p = nil
			} else if err != nil {
				apierr.Write(w, RequestID(ctx), err)
				return
			}
			if p != nil && isUnsafe(r.Method) && !s.d.Auth.CheckCSRF(ctx, p.SessionID, r.Header.Get(csrfHeader)) {
				apierr.Write(w, RequestID(ctx), apierr.CSRF())
				return
			}
		}
		if p == nil && isDirectLoopback(r) && s.bootstrapOpen(ctx) {
			p = &Principal{Kind: "local", Username: "local-bootstrap", Stage: "active",
				Global: map[string]bool{"system.read": true, "jobs.read": true, "events.read": true}}
		}
		if p != nil {
			ctx = context.WithValue(ctx, keyPrincipal, p)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bootstrapOpen reports whether no user exists yet (first-run window).
func (s *Server) bootstrapOpen(ctx context.Context) bool {
	n, err := s.d.Auth.UserCount(ctx)
	return err == nil && n == 0
}

func setSessionCookies(w http.ResponseWriter, r *http.Request, iss *auth.SessionIssue) {
	secure := !isDirectLoopback(r)
	maxAge := int(time.Until(iss.ExpiresAt).Seconds())
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: iss.Token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
	// Readable by the SPA so it can echo it in X-CSRF-Token (double submit).
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: iss.CSRF, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := !isDirectLoopback(r)
	for _, n := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", HttpOnly: n == sessionCookie, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}

// authorize enforces a route's permission requirement.
func (s *Server) authorize(r *http.Request, perm string) error {
	if perm == "" {
		return nil
	}
	p := PrincipalFrom(r.Context())
	if p == nil {
		return apierr.Unauthenticated()
	}
	switch perm {
	case permAnySession:
		if p.Kind != "user" {
			return apierr.Unauthenticated()
		}
		return nil
	case permEnroll, permPending:
		want := map[string]string{permEnroll: "mfa_enroll", permPending: "pending_mfa"}[perm]
		if p.Kind != "user" || p.Stage != want {
			return apierr.New(http.StatusConflict, "wrong_session_stage", "not allowed in the current sign-in stage")
		}
		return nil
	case permActiveUser:
		if p.Kind != "user" || !p.Active() {
			return mfaRequired(p)
		}
		return nil
	}
	if !p.Active() {
		return mfaRequired(p)
	}
	if !p.Can(perm) {
		return apierr.Forbidden()
	}
	if auth.StepUp[perm] && !p.StepUpFresh(time.Now()) {
		return apierr.New(http.StatusForbidden, "step_up_required", "recent two-factor verification required").
			WithDetails(map[string]any{"window_seconds": int(auth.StepUpWindow.Seconds())})
	}
	return nil
}

func mfaRequired(p *Principal) error {
	if p != nil && p.Kind == "user" {
		return apierr.New(http.StatusUnauthorized, "mfa_required", "two-factor authentication required").
			WithDetails(map[string]any{"stage": p.Stage})
	}
	return apierr.Unauthenticated()
}

// mapAuthError converts auth errors into client-safe API errors.
func mapAuthError(err error) error {
	var te *auth.ThrottledError
	var we *auth.ErrWeakPassword
	switch {
	case err == nil:
		return nil
	case errors.As(err, &te):
		e := apierr.RateLimited()
		return e.WithDetails(map[string]any{"retry_after_seconds": int(time.Until(te.Until).Seconds()) + 1})
	case errors.As(err, &we):
		return apierr.BadRequest(we.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		return apierr.New(http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
	case errors.Is(err, auth.ErrInvalidCode):
		return apierr.New(http.StatusUnauthorized, "invalid_code", "invalid or already used verification code")
	case errors.Is(err, auth.ErrWrongStage):
		return apierr.New(http.StatusConflict, "wrong_session_stage", "not allowed in the current sign-in stage")
	case errors.Is(err, auth.ErrNotFound):
		return apierr.NotFound("resource")
	case errors.Is(err, auth.ErrStale):
		return apierr.PreconditionFailed()
	case errors.Is(err, auth.ErrEscalation):
		return apierr.New(http.StatusForbidden, "privilege_escalation", err.Error())
	case errors.Is(err, auth.ErrLastOwner), errors.Is(err, auth.ErrBuiltinRole), errors.Is(err, auth.ErrConflict), errors.Is(err, auth.ErrAlreadyInitialized):
		return apierr.Conflict(err.Error())
	case errors.Is(err, auth.ErrSessionInvalid):
		return apierr.Unauthenticated()
	}
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae
	}
	// Validation errors from the auth package are plain errors with
	// client-safe messages; anything else is internal.
	if isValidationMessage(err) {
		return apierr.BadRequest(err.Error())
	}
	return err
}

func isValidationMessage(err error) bool {
	m := err.Error()
	for _, k := range []string{"username must", "locale must", "display name", "status must", "unknown role", "unknown scope", "unknown permission",
		"grants", "scope_id", "scope_kind", "role name", "description", "permission \"", "token name", "at least one", "lifetime", "requires interactive"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

// ─── per-caller rate limiting (NGM-API-003) ────────────────────────────────

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu    sync.Mutex
	b     map[string]*bucket
	rate  float64 // tokens per second
	burst float64
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{b: map[string]*bucket{}, rate: rate, burst: burst}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.b) > 10000 { // bound memory: drop idle buckets
		for k, v := range l.b {
			if now.Sub(v.last) > time.Minute {
				delete(l.b, k)
			}
		}
	}
	bk := l.b[key]
	if bk == nil {
		bk = &bucket{tokens: l.burst, last: now}
		l.b[key] = bk
	}
	bk.tokens = min(l.burst, bk.tokens+now.Sub(bk.last).Seconds()*l.rate)
	bk.last = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/events" {
			key := "ip:" + clientIP(r)
			if p := PrincipalFrom(r.Context()); p != nil && p.UserID != "" {
				key = "user:" + p.UserID
			}
			if !s.limiter.allow(key, time.Now()) {
				w.Header().Set("Retry-After", "1")
				apierr.Write(w, RequestID(r.Context()), apierr.RateLimited())
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
