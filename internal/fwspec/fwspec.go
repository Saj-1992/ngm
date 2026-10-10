// Package fwspec defines NGM-owned UFW rules. It has no dependencies so the
// API can validate rules without linking privileged code.
package fwspec

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

// Rule is a typed UFW rule owned by NGM. Commands are built only from these
// validated fields; nothing is passed through as text.
type Rule struct {
	Key    string `json:"key"`    // stable id, emitted as comment "ngm:<key>"
	Action string `json:"action"` // allow | deny | limit
	Proto  string `json:"proto"`  // tcp | udp | any
	Port   int    `json:"port"`
	Source string `json:"source"` // "any" or IP/CIDR
}

// SSHGuardKey marks the rule NGM adds to keep SSH reachable.
const SSHGuardKey = "ssh-guard"

var fwKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate checks a rule's fields.
func (r Rule) Validate() error {
	if !fwKeyRe.MatchString(r.Key) {
		return fmt.Errorf("invalid rule key %q", r.Key)
	}
	switch r.Action {
	case "allow", "deny", "limit":
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	switch r.Proto {
	case "tcp", "udp", "any":
	default:
		return fmt.Errorf("invalid proto %q", r.Proto)
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("invalid port %d", r.Port)
	}
	if r.Source != "any" {
		if _, err := netip.ParsePrefix(r.Source); err != nil {
			if _, err2 := netip.ParseAddr(r.Source); err2 != nil {
				return fmt.Errorf("invalid source %q", r.Source)
			}
		}
	}
	return nil
}

// Args renders the ufw arguments (without comment) from validated fields.
func (r Rule) Args() []string {
	a := []string{r.Action}
	if r.Proto != "any" {
		a = append(a, "proto", r.Proto)
	}
	return append(a, "from", r.Source, "to", "any", "port", strconv.Itoa(r.Port))
}
