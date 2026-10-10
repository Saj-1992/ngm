package auth

import "time"

// Principal is an authenticated caller.
type Principal struct {
	Kind      string // user (session) | token | local
	UserID    string
	Username  string
	SessionID string
	TokenID   string
	Stage     string // session stage: active | pending_mfa | mfa_enroll
	// Global permissions apply to every resource.
	Global map[string]bool
	// Scoped permissions apply to one resource scope, e.g. "website:<id>".
	Scoped        map[string]map[string]bool
	MFAVerifiedAt time.Time
	Locale        string
}

// StepUpWindow is how long an MFA verification authorises critical actions.
const StepUpWindow = 5 * time.Minute

// Active reports whether the principal has completed authentication.
func (p *Principal) Active() bool { return p != nil && (p.Kind != "user" || p.Stage == "active") }

// Can reports whether p holds perm globally.
func (p *Principal) Can(perm string) bool {
	if !p.Active() {
		return false
	}
	return p.Global[perm]
}

// CanOn reports whether p holds perm globally or for scope.
func (p *Principal) CanOn(perm, scope string) bool {
	if p.Can(perm) {
		return true
	}
	if !p.Active() {
		return false
	}
	return p.Scoped[scope][perm]
}

// CanSeeScope reports whether p may observe events/resources of scope.
func (p *Principal) CanSeeScope(scope string) bool {
	if !p.Active() {
		return false
	}
	if p.Global["events.read"] {
		return true
	}
	_, ok := p.Scoped[scope]
	return ok
}

// StepUpFresh reports whether a second factor was verified recently enough to
// authorise a critical action. Tokens and local principals never qualify.
func (p *Principal) StepUpFresh(now time.Time) bool {
	if p == nil || p.Kind != "user" || p.MFAVerifiedAt.IsZero() {
		return false
	}
	return now.Sub(p.MFAVerifiedAt) <= StepUpWindow
}

// PermissionList returns the global permissions, sorted.
func (p *Principal) PermissionList() []string {
	var out []string
	for k, v := range p.Global {
		if v {
			out = append(out, k)
		}
	}
	return sorted(out)
}
