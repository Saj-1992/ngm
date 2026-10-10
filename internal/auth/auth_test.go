package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

var fastArgon = Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type env struct {
	s   *Service
	clk *clock
	al  *audit.Logger
}

func newEnv(t *testing.T) *env {
	db := storetest.New(t)
	kr := vault.NewKeyring()
	k := make([]byte, 32)
	rand.Read(k)
	kr.Add(1, k)
	v := vault.New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Argon2 = fastArgon
	al := audit.New(db)
	s := NewService(db, v, al, p)
	clk := &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	s.SetClock(clk.now)
	if err := s.EnsureBuiltins(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &env{s: s, clk: clk, al: al}
}

const goodPW = "Correct-Horse-9-Battery"

var ci = ClientInfo{IP: "203.0.113.7", UserAgent: "test", Secure: true}

// fullLogin bootstraps (if needed) and returns an active principal + TOTP secret.
func (e *env) owner(t *testing.T) (*Principal, string) {
	ctx := context.Background()
	if _, err := e.s.BootstrapOwner(ctx, "owner", "Owner", goodPW, "fa"); err != nil {
		t.Fatal(err)
	}
	return e.loginEnroll(t, "owner", goodPW)
}

func (e *env) loginEnroll(t *testing.T, user, pw string) (*Principal, string) {
	ctx := context.Background()
	iss, err := e.s.Login(ctx, user, pw, ci)
	if err != nil || iss.Stage != "mfa_enroll" {
		t.Fatalf("login: %+v %v", iss, err)
	}
	p, _ := e.s.AuthenticateSession(ctx, iss.Token)
	en, err := e.s.BeginTOTPEnroll(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := TOTPCode(en.Secret, e.clk.t)
	iss2, err := e.s.ConfirmTOTPEnroll(ctx, p, code, ci)
	if err != nil || iss2.Stage != "active" {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := e.s.AuthenticateSession(ctx, iss.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("pre-MFA session token still valid after rotation")
	}
	ap, err := e.s.AuthenticateSession(ctx, iss2.Token)
	if err != nil {
		t.Fatal(err)
	}
	e.clk.advance(31 * time.Second) // next TOTP step for subsequent codes
	return ap, en.Secret
}

// ── primitives ──────────────────────────────────────────────────────────────

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword(goodPW, fastArgon)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("%s %v", h, err)
	}
	if ok, _ := VerifyPassword(goodPW, h); !ok {
		t.Fatal("correct password rejected")
	}
	if ok, _ := VerifyPassword(goodPW+"x", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword(goodPW, fastArgon)
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=8192,t=1,p=1$AA$AA", "$argon2id$v=19$m=1,t=1,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := VerifyPassword("x", bad); err == nil {
			t.Errorf("accepted malformed hash %q", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, pw := range []string{"short", "password1234", "aaaaaaaaaaaaaaaa", "alllowercase12", "owner-Secret-99"} {
		if err := CheckPasswordPolicy(pw, "owner"); err == nil {
			t.Errorf("accepted %q", pw)
		}
	}
	for _, pw := range []string{goodPW, "correct horse battery staple", "رمز-عبور-بسیار-امن-۱۴۰۵"} {
		if err := CheckPasswordPolicy(pw, "admin"); err != nil {
			t.Errorf("rejected %q: %v", pw, err)
		}
	}
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"}
	for ts, want := range vectors {
		got, _ := TOTPCode(secret, time.Unix(ts, 0))
		if got != want {
			t.Errorf("T=%d got %s want %s", ts, got, want)
		}
	}
	now := time.Unix(1111111111, 0)
	step, ok := VerifyTOTP(secret, "050471", now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTP(secret, "050471", now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", now, 0); ok {
		t.Fatal("wrong code accepted")
	}
	if _, ok := VerifyTOTP(secret, "05047a", now, 0); ok {
		t.Fatal("non-digit accepted")
	}
	// ±1 step skew accepted, ±2 rejected.
	prev, _ := TOTPCode(secret, now.Add(-30*time.Second))
	if _, ok := VerifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("previous step rejected")
	}
	old, _ := TOTPCode(secret, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(secret, old, now, 0); ok {
		t.Fatal("stale code accepted")
	}
}

// ── login, MFA, sessions ───────────────────────────────────────────────────

func TestBootstrapOnlyOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.s.BootstrapOwner(ctx, "owner", "", goodPW, "en"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.BootstrapOwner(ctx, "second", "", goodPW, "en"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second bootstrap: %v", err)
	}
}

func TestFullLoginFlowAndStages(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p, secret := e.owner(t)
	if !p.Can("owner.transfer") || p.Stage != "active" {
		t.Fatalf("owner principal %+v", p)
	}
	// Second login → pending_mfa; no permissions until MFA.
	iss, err := e.s.Login(ctx, "OWNER", goodPW, ci)
	if err != nil || iss.Stage != "pending_mfa" {
		t.Fatalf("%+v %v", iss, err)
	}
	pp, _ := e.s.AuthenticateSession(ctx, iss.Token)
	if pp.Can("system.read") || pp.Active() {
		t.Fatal("pending session has permissions")
	}
	if _, err := e.s.BeginTOTPEnroll(ctx, pp); !errors.Is(err, ErrWrongStage) {
		t.Fatal("pending_mfa session could replace TOTP enrolment")
	}
	if _, err := e.s.VerifyMFA(ctx, pp, "123456", ci); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("bad code: %v", err)
	}
	code, _ := TOTPCode(secret, e.clk.t)
	act, err := e.s.VerifyMFA(ctx, pp, code, ci)
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := e.s.AuthenticateSession(ctx, act.Token)
	if !ap.Can("system.read") || !ap.StepUpFresh(e.clk.t) {
		t.Fatal("active session lacks permissions or fresh MFA")
	}
	// Same code cannot be replayed for step-up.
	if _, err := e.s.StepUp(ctx, ap, code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay step-up: %v", err)
	}
	e.clk.advance(6 * time.Minute)
	ap, _ = e.s.AuthenticateSession(ctx, act.Token)
	if ap.StepUpFresh(e.clk.t) {
		t.Fatal("step-up window did not expire")
	}
	code2, _ := TOTPCode(secret, e.clk.t)
	if _, err := e.s.StepUp(ctx, ap, code2); err != nil {
		t.Fatal(err)
	}
	ap, _ = e.s.AuthenticateSession(ctx, act.Token)
	if !ap.StepUpFresh(e.clk.t) {
		t.Fatal("step-up not recorded")
	}
	// CSRF.
	if !e.s.CheckCSRF(ctx, ap.SessionID, act.CSRF) || e.s.CheckCSRF(ctx, ap.SessionID, iss.CSRF) || e.s.CheckCSRF(ctx, ap.SessionID, "") {
		t.Fatal("csrf check wrong")
	}
	// Idle expiry.
	e.clk.advance(31 * time.Minute)
	if _, err := e.s.AuthenticateSession(ctx, act.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("idle session still valid")
	}
}

func TestAbsoluteExpiryAndLogout(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, secret := e.owner(t)
	iss, _ := e.s.Login(ctx, "owner", goodPW, ci)
	pp, _ := e.s.AuthenticateSession(ctx, iss.Token)
	code, _ := TOTPCode(secret, e.clk.t)
	act, _ := e.s.VerifyMFA(ctx, pp, code, ci)
	for i := 0; i < 25; i++ { // keep active past 12h with activity
		e.clk.advance(29 * time.Minute)
		if _, err := e.s.AuthenticateSession(ctx, act.Token); err != nil {
			if i < 24 {
				t.Fatalf("expired early at %d: %v", i, err)
			}
		}
	}
	if _, err := e.s.AuthenticateSession(ctx, act.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("session outlived absolute timeout")
	}
	iss2, _ := e.s.Login(ctx, "owner", goodPW, ci)
	p2, _ := e.s.AuthenticateSession(ctx, iss2.Token)
	e.s.Logout(ctx, p2)
	if _, err := e.s.AuthenticateSession(ctx, iss2.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("logged-out session valid")
	}
}

func TestThrottlingAndNoEnumeration(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.s.BootstrapOwner(ctx, "owner", "", goodPW, "en")
	for i := 0; i < 5; i++ {
		if _, err := e.s.Login(ctx, "owner", "wrong-password-123", ci); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := e.s.Login(ctx, "owner", goodPW, ci)
	var te *ThrottledError
	if !errors.As(err, &te) {
		t.Fatalf("correct password during lockout: %v", err)
	}
	// Unknown user yields the same error as a wrong password.
	_, err = e.s.Login(ctx, "nobody", goodPW, ClientInfo{IP: "198.51.100.1"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	e.clk.advance(16 * time.Minute)
	if _, err := e.s.Login(ctx, "owner", goodPW, ci); err != nil {
		t.Fatalf("after lock expiry: %v", err)
	}
	// Per-IP bucket: many usernames from one IP.
	ip := ClientInfo{IP: "192.0.2.50"}
	for i := 0; i < 20; i++ {
		e.s.Login(ctx, "user"+string(rune('a'+i)), "wrong-password-123", ip)
	}
	if _, err := e.s.Login(ctx, "owner", goodPW, ip); !errors.As(err, &te) {
		t.Fatalf("ip lockout not applied: %v", err)
	}
}

func TestDisabledUserCannotLogin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, _ := e.owner(t)
	u, err := e.s.CreateUser(ctx, owner, CreateUserInput{Username: "ops1", Password: goodPW, Grants: []Grant{{RoleID: RoleOperator}}})
	if err != nil {
		t.Fatal(err)
	}
	st := "disabled"
	if _, err := e.s.UpdateUser(ctx, owner, u.ID, u.Revision, UpdateUserInput{Status: &st}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Login(ctx, "ops1", goodPW, ci); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled user login: %v", err)
	}
}

// ── RBAC ───────────────────────────────────────────────────────────────────

func TestRBACEscalationAndOwnerProtection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, _ := e.owner(t)
	adm, err := e.s.CreateUser(ctx, owner, CreateUserInput{Username: "admin1", Password: goodPW, Grants: []Grant{{RoleID: RoleAdmin}}})
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := e.loginEnroll(t, "admin1", goodPW)
	if ap.Can("owner.transfer") || !ap.Can("users.write") {
		t.Fatal("admin permissions wrong")
	}
	// Admin cannot create an Owner.
	if _, err := e.s.CreateUser(ctx, ap, CreateUserInput{Username: "evil", Password: goodPW, Grants: []Grant{{RoleID: RoleOwner}}}); !errors.Is(err, ErrEscalation) {
		t.Fatalf("admin created owner: %v", err)
	}
	// Admin cannot modify the owner.
	ou, _ := e.s.GetUser(ctx, owner.UserID)
	st := "disabled"
	if _, err := e.s.UpdateUser(ctx, ap, ou.ID, ou.Revision, UpdateUserInput{Status: &st}); !errors.Is(err, ErrEscalation) {
		t.Fatalf("admin disabled owner: %v", err)
	}
	// Admin cannot create a custom role with owner-only permissions.
	if _, err := e.s.CreateRole(ctx, ap, "x", "", []string{"system.purge"}); err == nil {
		t.Fatal("custom role with reserved perm")
	}
	// Last owner protection.
	if _, err := e.s.UpdateUser(ctx, owner, ou.ID, ou.Revision, UpdateUserInput{Grants: &[]Grant{{RoleID: RoleAdmin}}}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demoted last owner: %v", err)
	}
	// Stale revision.
	if _, err := e.s.UpdateUser(ctx, owner, adm.ID, adm.Revision+5, UpdateUserInput{Status: &st}); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	// Built-ins immutable.
	if _, err := e.s.UpdateRole(ctx, owner, RoleViewer, 1, "Viewer", "", []string{"system.read"}); !errors.Is(err, ErrBuiltinRole) {
		t.Fatal("builtin role edited")
	}
}

func TestScopedGrant(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, _ := e.owner(t)
	r, err := e.s.CreateRole(ctx, owner, "Site editor", "", []string{"websites.read", "websites.write"})
	if err != nil {
		t.Fatal(err)
	}
	site := "01J9ZZZZZZZZZZZZZZZZZZZZZZ"
	if _, err := e.s.CreateUser(ctx, owner, CreateUserInput{Username: "editor", Password: goodPW, Grants: []Grant{{RoleID: r.ID, ScopeKind: "website", ScopeID: site}}}); err != nil {
		t.Fatal(err)
	}
	p, _ := e.loginEnroll(t, "editor", goodPW)
	if p.Can("websites.write") {
		t.Fatal("scoped grant leaked to global")
	}
	if !p.CanOn("websites.write", "website:"+site) || p.CanOn("websites.write", "website:01J9AAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("scoped grant evaluation wrong")
	}
}

func TestPrivilegeChangeRevokesSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, _ := e.owner(t)
	u, err := e.s.CreateUser(ctx, owner, CreateUserInput{Username: "op1", Password: goodPW, Grants: []Grant{{RoleID: RoleOperator}}})
	if err != nil {
		t.Fatal(err)
	}
	op, _ := e.loginEnroll(t, "op1", goodPW)
	_ = op
	u, _ = e.s.GetUser(ctx, u.ID)
	if _, err := e.s.UpdateUser(ctx, owner, u.ID, u.Revision, UpdateUserInput{Grants: &[]Grant{{RoleID: RoleViewer}}}); err != nil {
		t.Fatal(err)
	}
	var n int
	e.s.db.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", u.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d sessions survived a privilege change", n)
	}
}

// ── tokens ─────────────────────────────────────────────────────────────────

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, _ := e.owner(t)
	if _, err := e.s.CreateToken(ctx, owner, "ci", []string{"firewall.write"}, 0); err == nil {
		t.Fatal("step-up scope granted to token")
	}
	ct, err := e.s.CreateToken(ctx, owner, "ci", []string{"jobs.read", "system.read"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct.Token, "ngm_") {
		t.Fatal(ct.Token)
	}
	var stored int
	e.s.db.QueryRowContext(ctx, "SELECT count(*) FROM api_tokens WHERE token_hash=?", ct.Token).Scan(&stored)
	if stored != 0 {
		t.Fatal("plaintext token stored")
	}
	p, err := e.s.AuthenticateToken(ctx, ct.Token)
	if err != nil || !p.Can("jobs.read") || p.Can("users.read") || p.StepUpFresh(e.clk.t) {
		t.Fatalf("token principal %+v %v", p, err)
	}
	if _, err := e.s.AuthenticateToken(ctx, ct.Token+"x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	list, _ := e.s.ListTokens(ctx, owner.UserID)
	if len(list) != 1 || list[0].Prefix == "" {
		t.Fatalf("%+v", list)
	}
	e.clk.advance(25 * time.Hour)
	if _, err := e.s.AuthenticateToken(ctx, ct.Token); err == nil {
		t.Fatal("expired token accepted")
	}
	ct2, _ := e.s.CreateToken(ctx, owner, "b", []string{"jobs.read"}, 0)
	e.s.RevokeToken(ctx, owner, ct2.ID)
	if _, err := e.s.AuthenticateToken(ctx, ct2.Token); err == nil {
		t.Fatal("revoked token accepted")
	}
}

func TestAdminResetForcesReenrolment(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.owner(t)
	newPW := "Brand-New-Passw0rd!"
	if err := e.s.AdminReset(ctx, "owner", newPW); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Login(ctx, "owner", goodPW, ci); err == nil {
		t.Fatal("old password works after reset")
	}
	iss, err := e.s.Login(ctx, "owner", newPW, ci)
	if err != nil || iss.Stage != "mfa_enroll" {
		t.Fatalf("after reset: %+v %v", iss, err)
	}
	r, _ := e.al.Verify(ctx)
	if !r.OK || r.Events < 5 {
		t.Fatalf("audit chain %+v", r)
	}
}

func TestEnrollIsIdempotentWhilePending(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.s.BootstrapOwner(ctx, "owner", "", goodPW, "en")
	iss, _ := e.s.Login(ctx, "owner", goodPW, ci)
	p, _ := e.s.AuthenticateSession(ctx, iss.Token)
	a, err := e.s.BeginTOTPEnroll(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.s.BeginTOTPEnroll(ctx, p)
	if a.Secret != b.Secret {
		t.Fatal("second enroll call replaced the pending secret")
	}
	code, _ := TOTPCode(a.Secret, e.clk.t)
	if _, err := e.s.ConfirmTOTPEnroll(ctx, p, code, ci); err != nil {
		t.Fatal(err)
	}
}
