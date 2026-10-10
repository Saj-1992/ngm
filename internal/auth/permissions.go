package auth

import "sort"

// Permission catalog (API_CONTRACT.md RBAC). Deny by default: a permission not
// granted is denied.
var Catalog = []string{
	"system.read", "jobs.read", "events.read", "audit.read", "settings.read", "settings.write",
	"users.read", "users.write", "roles.read", "roles.write", "tokens.read", "tokens.write",
	"secrets.read", "secrets.write",
	"gateway.read", "gateway.write", "deploy.apply",
	"websites.read", "websites.write", "domains.read", "domains.write",
	"certificates.read", "certificates.write",
	"firewall.read", "firewall.write",
	"backups.read", "backups.create", "backups.restore", "recovery.read", "recovery.write",
	"updates.read", "updates.install",
	"logs.read", "monitoring.read", "alerts.write", "topology.read", "performance.read", "performance.write",
	"owner.transfer", "system.purge",
}

var catalogSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range Catalog {
		m[p] = true
	}
	return m
}()

// KnownPermission reports whether p is in the catalog.
func KnownPermission(p string) bool { return catalogSet[p] }

// StepUp lists permissions whose use requires a recent MFA verification
// (MASTER_SPEC §11 "step-up MFA for critical actions"). API tokens can never
// exercise them because a token cannot present a fresh second factor.
var StepUp = map[string]bool{
	"users.write": true, "roles.write": true, "tokens.write": true, "secrets.write": true,
	"firewall.write": true, "backups.restore": true, "recovery.write": true, "updates.install": true,
	"settings.write": true, "owner.transfer": true, "system.purge": true,
}

// Built-in role IDs (fixed so that references are stable across installs).
const (
	RoleOwner    = "00000000000000000000000001"
	RoleAdmin    = "00000000000000000000000002"
	RoleOperator = "00000000000000000000000003"
	RoleViewer   = "00000000000000000000000004"
)

// BuiltinRole describes an immutable built-in role.
type BuiltinRole struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

func readAll() []string {
	var out []string
	for _, p := range Catalog {
		if len(p) > 5 && p[len(p)-5:] == ".read" {
			out = append(out, p)
		}
	}
	return out
}

func without(all []string, drop ...string) []string {
	d := map[string]bool{}
	for _, x := range drop {
		d[x] = true
	}
	var out []string
	for _, p := range all {
		if !d[p] {
			out = append(out, p)
		}
	}
	return out
}

// Builtins are re-asserted at every startup; their permissions cannot be edited.
var Builtins = []BuiltinRole{
	{RoleOwner, "Owner", "Full control including ownership transfer and purge", append([]string(nil), Catalog...)},
	{RoleAdmin, "Admin", "Full administration except ownership transfer and purge", without(Catalog, "owner.transfer", "system.purge")},
	{RoleOperator, "Operator", "Day-to-day gateway, website and certificate changes", append(without(readAll(), "audit.read", "secrets.read", "users.read", "roles.read"),
		"gateway.write", "deploy.apply", "websites.write", "domains.write", "certificates.write", "backups.create", "alerts.write")},
	{RoleViewer, "Viewer", "Read-only access to non-sensitive state", without(readAll(), "audit.read", "secrets.read", "users.read", "roles.read", "tokens.read")},
}

// IsBuiltinRole reports whether id is a built-in role.
func IsBuiltinRole(id string) bool {
	for _, b := range Builtins {
		if b.ID == id {
			return true
		}
	}
	return false
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
