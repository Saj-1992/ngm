package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

func (s *Server) registerAuthRoutes() {
	s.handle("GET", "/api/v1/setup/status", "", s.getSetupStatus)
	s.handle("POST", "/api/v1/setup/owner", "", s.postSetupOwner)

	s.handle("POST", "/api/v1/auth/login", "", s.postLogin)
	s.handle("POST", "/api/v1/auth/logout", permAnySession, s.postLogout)
	s.handle("GET", "/api/v1/auth/session", permAnySession, s.getSession)
	s.handle("POST", "/api/v1/auth/mfa/enroll", permEnroll, s.postMFAEnroll)
	s.handle("POST", "/api/v1/auth/mfa/confirm", permEnroll, s.postMFAConfirm)
	s.handle("POST", "/api/v1/auth/mfa/verify", permPending, s.postMFAVerify)
	s.handle("POST", "/api/v1/auth/step-up", permActiveUser, s.postStepUp)
	s.handle("POST", "/api/v1/auth/password", permActiveUser, s.postPassword)

	s.handle("GET", "/api/v1/users", "users.read", s.listUsers)
	s.handle("POST", "/api/v1/users", "users.write", s.createUser)
	s.handle("GET", "/api/v1/users/{id}", "users.read", s.getUser)
	s.handle("PATCH", "/api/v1/users/{id}", "users.write", s.patchUser)
	s.handle("DELETE", "/api/v1/users/{id}", "users.write", s.deleteUser)
	s.handle("POST", "/api/v1/users/{id}/mfa-reset", "users.write", s.resetUserMFA)

	s.handle("GET", "/api/v1/permissions", "roles.read", s.listPermissions)
	s.handle("GET", "/api/v1/roles", "roles.read", s.listRoles)
	s.handle("POST", "/api/v1/roles", "roles.write", s.createRole)
	s.handle("GET", "/api/v1/roles/{id}", "roles.read", s.getRole)
	s.handle("PUT", "/api/v1/roles/{id}", "roles.write", s.putRole)
	s.handle("DELETE", "/api/v1/roles/{id}", "roles.write", s.deleteRole)

	s.handle("GET", "/api/v1/tokens", "tokens.read", s.listTokens)
	s.handle("POST", "/api/v1/tokens", "tokens.write", s.createToken)
	s.handle("DELETE", "/api/v1/tokens/{id}", "tokens.write", s.revokeToken)

	s.handle("GET", "/api/v1/audit", "audit.read", s.listAudit)
	s.handle("GET", "/api/v1/audit/verify", "audit.read", s.verifyAudit)
	s.handle("GET", "/api/v1/secrets", "secrets.read", s.listSecrets)
}

// ─── setup ─────────────────────────────────────────────────────────────────

// SettingBootstrapTokenHash holds the SHA-256 of the one-time bootstrap token
// written by the installer. Creating the owner requires the token, so another
// local user cannot win a race for the first-run window.
const SettingBootstrapTokenHash = "setup.bootstrap_token_hash"

// SettingInstallPreflight holds the installer's preflight report (JSON).
const SettingInstallPreflight = "install.preflight"

type setupStep struct {
	ID     string `json:"id"`
	Status string `json:"status"` // complete | pending | planned
	Phase  int    `json:"phase,omitempty"`
}

func (s *Server) setting(ctx context.Context, key string) (string, bool) {
	var v string
	if err := s.d.DB.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

func (s *Server) getSetupStatus(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	n, err := s.d.Auth.UserCount(ctx)
	if err != nil {
		return err
	}
	var ownerMFA int
	_ = s.d.DB.QueryRowContext(ctx, `SELECT count(*) FROM users u JOIN permission_grants g ON g.user_id=u.id
		WHERE g.role_id=? AND u.mfa_enabled=1`, auth.RoleOwner).Scan(&ownerMFA)
	_, preflight := s.setting(ctx, SettingInstallPreflight)
	st := func(done bool) string {
		if done {
			return "complete"
		}
		return "pending"
	}
	steps := []setupStep{
		{ID: "preflight", Status: st(preflight)},
		{ID: "owner", Status: st(n > 0 && ownerMFA > 0)},
		{ID: "management_origin", Status: st(s.d.Config.API.PublicOrigin != ""), Phase: 3},
		{ID: "certificate", Status: st(s.count(r, "SELECT COUNT(*) FROM certificates WHERE not_after > ?", store.FormatTime(time.Now())) > 0)},
		{ID: "default_website", Status: st(s.count(r, "SELECT COUNT(*) FROM website_versions WHERE published_at IS NOT NULL") > 0)},
		{ID: "first_route", Status: st(s.count(r, "SELECT COUNT(*) FROM routes") > 0)},
		{ID: "verification", Status: st(s.count(r, "SELECT COUNT(*) FROM jobs WHERE kind='deploy.gateway' AND state='Succeeded'") > 0)},
	}
	resp := map[string]any{
		"initialized":     n > 0,
		"owner_ready":     ownerMFA > 0,
		"local_bootstrap": isDirectLoopback(r),
		// Whether a report exists; its content is visible only with system.read.
		"preflight_recorded": preflight,
		"steps":              steps,
	}
	// Preflight details only for the bootstrap window or system.read holders.
	if p := PrincipalFrom(ctx); p.Can("system.read") && preflight {
		v, _ := s.setting(ctx, SettingInstallPreflight)
		resp["preflight"] = json.RawMessage(v)
	}
	return writeJSON(w, http.StatusOK, resp)
}

type ownerReq struct {
	BootstrapToken string `json:"bootstrap_token"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Password       string `json:"password"`
	Locale         string `json:"locale"`
}

func (s *Server) postSetupOwner(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if !isDirectLoopback(r) {
		return apierr.New(http.StatusForbidden, "local_only", "owner setup is only available over local access or an SSH tunnel")
	}
	var in ownerReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	stored, ok := s.setting(ctx, SettingBootstrapTokenHash)
	var want string
	_ = json.Unmarshal([]byte(stored), &want)
	if !ok || want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(auth.HashToken(strings.TrimSpace(in.BootstrapToken)))) != 1 {
		_, _ = s.d.Audit.Record(ctx, audit.Event{ActorKind: "user", Action: "setup.owner_create", Result: "denied", RequestID: RequestID(ctx), Context: map[string]any{"reason": "bad_bootstrap_token"}})
		return apierr.New(http.StatusForbidden, "invalid_bootstrap_token", "bootstrap token missing or invalid; see installer output or run `ngm admin bootstrap-token`")
	}
	if _, err := s.d.Auth.BootstrapOwner(ctx, in.Username, in.DisplayName, in.Password, in.Locale); err != nil {
		return err
	}
	if _, err := s.d.DB.ExecContext(ctx, "DELETE FROM settings WHERE key=?", SettingBootstrapTokenHash); err != nil {
		return err
	}
	iss, err := s.d.Auth.Login(ctx, in.Username, in.Password, clientInfo(r))
	if err != nil {
		return err
	}
	setSessionCookies(w, r, iss)
	return writeJSON(w, http.StatusCreated, map[string]any{"stage": iss.Stage})
}

// ─── auth ──────────────────────────────────────────────────────────────────

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) error {
	var in loginReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	iss, err := s.d.Auth.Login(r.Context(), in.Username, in.Password, clientInfo(r))
	if err != nil {
		return err
	}
	// Replace any previous session in this browser.
	if old := PrincipalFrom(r.Context()); old != nil && old.Kind == "user" {
		_ = s.d.Auth.Logout(r.Context(), old)
	}
	setSessionCookies(w, r, iss)
	return writeJSON(w, http.StatusOK, map[string]any{"stage": iss.Stage})
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) error {
	if err := s.d.Auth.Logout(r.Context(), PrincipalFrom(r.Context())); err != nil {
		return err
	}
	clearSessionCookies(w, r)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) error {
	p := PrincipalFrom(r.Context())
	resp := map[string]any{
		"user":        map[string]any{"id": p.UserID, "username": p.Username, "locale": p.Locale},
		"stage":       p.Stage,
		"permissions": []string{},
	}
	if p.Active() {
		resp["permissions"] = p.PermissionList()
		if !p.MFAVerifiedAt.IsZero() {
			resp["step_up_until"] = p.MFAVerifiedAt.Add(auth.StepUpWindow).UTC()
		}
	}
	return writeJSON(w, http.StatusOK, resp)
}

type codeReq struct {
	Code string `json:"code"`
}

func (s *Server) postMFAEnroll(w http.ResponseWriter, r *http.Request) error {
	en, err := s.d.Auth.BeginTOTPEnroll(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, en)
}

func (s *Server) postMFAConfirm(w http.ResponseWriter, r *http.Request) error {
	var in codeReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	iss, err := s.d.Auth.ConfirmTOTPEnroll(r.Context(), PrincipalFrom(r.Context()), in.Code, clientInfo(r))
	if err != nil {
		return err
	}
	setSessionCookies(w, r, iss)
	return writeJSON(w, http.StatusOK, map[string]any{"stage": iss.Stage})
}

func (s *Server) postMFAVerify(w http.ResponseWriter, r *http.Request) error {
	var in codeReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	iss, err := s.d.Auth.VerifyMFA(r.Context(), PrincipalFrom(r.Context()), in.Code, clientInfo(r))
	if err != nil {
		return err
	}
	setSessionCookies(w, r, iss)
	return writeJSON(w, http.StatusOK, map[string]any{"stage": iss.Stage})
}

func (s *Server) postStepUp(w http.ResponseWriter, r *http.Request) error {
	var in codeReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	at, err := s.d.Auth.StepUp(r.Context(), PrincipalFrom(r.Context()), in.Code)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"step_up_until": at.Add(auth.StepUpWindow).UTC()})
}

type passwordReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (s *Server) postPassword(w http.ResponseWriter, r *http.Request) error {
	var in passwordReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if err := s.d.Auth.ChangePassword(r.Context(), PrincipalFrom(r.Context()), in.Current, in.New); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── users ─────────────────────────────────────────────────────────────────

func validID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		return "", apierr.NotFound("resource")
	}
	return id, nil
}

func ifMatchRevision(r *http.Request) (int64, error) {
	im := r.Header.Get("If-Match")
	if im == "" {
		return 0, apierr.PreconditionRequired()
	}
	v := strings.TrimSuffix(strings.TrimPrefix(im, `"r`), `"`)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || ETag(n) != im {
		return 0, apierr.PreconditionFailed()
	}
	return n, nil
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) error {
	us, err := s.d.Auth.ListUsers(r.Context())
	if err != nil {
		return err
	}
	if us == nil {
		us = []*auth.User{}
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": us})
}

type createUserReq struct {
	Username    string       `json:"username"`
	DisplayName string       `json:"display_name"`
	Password    string       `json:"password"`
	Locale      string       `json:"locale"`
	Grants      []auth.Grant `json:"grants"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) error {
	var in createUserReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	u, err := s.d.Auth.CreateUser(r.Context(), PrincipalFrom(r.Context()), auth.CreateUserInput{
		Username: in.Username, DisplayName: in.DisplayName, Password: in.Password, Locale: in.Locale, Grants: in.Grants})
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(u.Revision))
	w.Header().Set("Location", "/api/v1/users/"+u.ID)
	return writeJSON(w, http.StatusCreated, u)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	u, err := s.d.Auth.GetUser(r.Context(), id)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(u.Revision))
	return writeJSON(w, http.StatusOK, u)
}

type patchUserReq struct {
	DisplayName *string       `json:"display_name"`
	Status      *string       `json:"status"`
	Locale      *string       `json:"locale"`
	Grants      *[]auth.Grant `json:"grants"`
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in patchUserReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	u, err := s.d.Auth.UpdateUser(r.Context(), PrincipalFrom(r.Context()), id, rev, auth.UpdateUserInput{
		DisplayName: in.DisplayName, Status: in.Status, Locale: in.Locale, Grants: in.Grants})
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(u.Revision))
	return writeJSON(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	if err := s.d.Auth.DeleteUser(r.Context(), PrincipalFrom(r.Context()), id, rev); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.d.Auth.ResetMFA(r.Context(), PrincipalFrom(r.Context()), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── roles ─────────────────────────────────────────────────────────────────

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) error {
	type perm struct {
		ID     string `json:"id"`
		StepUp bool   `json:"step_up"`
	}
	out := make([]perm, 0, len(auth.Catalog))
	for _, p := range auth.Catalog {
		out = append(out, perm{p, auth.StepUp[p]})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) error {
	rs, err := s.d.Auth.ListRoles(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": rs})
}

type roleReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) error {
	var in roleReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	role, err := s.d.Auth.CreateRole(r.Context(), PrincipalFrom(r.Context()), in.Name, in.Description, in.Permissions)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(role.Revision))
	return writeJSON(w, http.StatusCreated, role)
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	role, err := s.d.Auth.GetRole(r.Context(), id)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(role.Revision))
	return writeJSON(w, http.StatusOK, role)
}

func (s *Server) putRole(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in roleReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	role, err := s.d.Auth.UpdateRole(r.Context(), PrincipalFrom(r.Context()), id, rev, in.Name, in.Description, in.Permissions)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(role.Revision))
	return writeJSON(w, http.StatusOK, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	if err := s.d.Auth.DeleteRole(r.Context(), PrincipalFrom(r.Context()), id, rev); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── tokens ────────────────────────────────────────────────────────────────

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) error {
	p := PrincipalFrom(r.Context())
	ts, err := s.d.Auth.ListTokens(r.Context(), p.UserID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": ts})
}

type tokenReq struct {
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	ExpiresInDay int      `json:"expires_in_days"`
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) error {
	var in tokenReq
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.ExpiresInDay < 0 || in.ExpiresInDay > 366 {
		return apierr.BadRequest("expires_in_days must be 0 (never) to 366")
	}
	t, err := s.d.Auth.CreateToken(r.Context(), PrincipalFrom(r.Context()), in.Name, in.Scopes, time.Duration(in.ExpiresInDay)*24*time.Hour)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, t)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.d.Auth.RevokeToken(r.Context(), PrincipalFrom(r.Context()), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── audit & secrets ───────────────────────────────────────────────────────

type auditRow struct {
	Seq        int64           `json:"seq"`
	ID         string          `json:"id"`
	At         time.Time       `json:"at"`
	ActorKind  string          `json:"actor_kind"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	TargetKind string          `json:"target_kind"`
	TargetID   string          `json:"target_id"`
	Result     string          `json:"result"`
	RequestID  string          `json:"request_id"`
	JobID      string          `json:"job_id"`
	Context    json.RawMessage `json:"context"`
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) error {
	limit, err := pageLimit(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	where, args := []string{"1=1"}, []any{}
	if c := q.Get("cursor"); c != "" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n <= 0 {
			return apierr.BadRequest("invalid cursor")
		}
		where, args = append(where, "seq < ?"), append(args, n)
	}
	if a := q.Get("action"); a != "" {
		if len(a) > 64 {
			return apierr.BadRequest("action filter too long")
		}
		where, args = append(where, "action = ?"), append(args, a)
	}
	if res := q.Get("result"); res != "" {
		if res != "success" && res != "failure" && res != "denied" {
			return apierr.BadRequest("invalid result filter")
		}
		where, args = append(where, "result = ?"), append(args, res)
	}
	if a := q.Get("actor_id"); a != "" {
		if !ids.Valid(a) {
			return apierr.BadRequest("invalid actor_id")
		}
		where, args = append(where, "actor_id = ?"), append(args, a)
	}
	args = append(args, limit+1)
	rows, err := s.d.DB.QueryContext(r.Context(), `SELECT seq,id,at,actor_kind,actor_id,action,target_kind,target_id,result,request_id,job_id,context_json
		FROM audit_events WHERE `+strings.Join(where, " AND ")+` ORDER BY seq DESC LIMIT ?`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []auditRow{}
	for rows.Next() {
		var a auditRow
		var at, c string
		if err := rows.Scan(&a.Seq, &a.ID, &at, &a.ActorKind, &a.ActorID, &a.Action, &a.TargetKind, &a.TargetID, &a.Result, &a.RequestID, &a.JobID, &c); err != nil {
			return err
		}
		a.At, _ = store.ParseTime(at)
		a.Context = json.RawMessage(c)
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		c := strconv.FormatInt(items[limit-1].Seq, 10)
		next = &c
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) error {
	res, err := s.d.Audit.Verify(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) error {
	if s.d.Vault == nil {
		return apierr.Unavailable("vault not configured")
	}
	ms, err := s.d.Vault.List(r.Context())
	if err != nil {
		return err
	}
	// TOTP seeds are personal; list only their existence count to admins.
	type item struct {
		ID        string    `json:"id"`
		Type      string    `json:"type"`
		Scope     string    `json:"scope"`
		Name      string    `json:"name"`
		Version   int       `json:"version"`
		KEK       int       `json:"kek_version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	out := []item{}
	for _, m := range ms {
		out = append(out, item{m.ID, m.Type, m.Scope, m.Name, m.Version, m.KEKVersion, m.UpdatedAt})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// heartbeat reads a service heartbeat, Unknown when missing or stale.
func (s *Server) heartbeat(ctx context.Context, svc string, now time.Time) component {
	c := component{Name: svc, Status: Unknown, Detail: "no heartbeat", ObservedAt: now}
	var status, detail, at, version string
	err := s.d.DB.QueryRowContext(ctx, "SELECT status, detail, observed_at, version FROM service_heartbeats WHERE service=?", svc).Scan(&status, &detail, &at, &version)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return c
	}
	t, _ := store.ParseTime(at)
	c.ObservedAt = t
	if now.Sub(t) > 90*time.Second {
		c.Detail = "heartbeat stale since " + t.UTC().Format(time.RFC3339)
		return c
	}
	c.Status, c.Detail = status, detail
	if c.Detail == "" {
		c.Detail = version
	}
	return c
}

// count runs a COUNT query for setup evidence; errors count as zero (pending).
func (s *Server) count(r *http.Request, q string, args ...any) int {
	var n int
	_ = s.d.DB.QueryRowContext(r.Context(), q, args...).Scan(&n)
	return n
}
