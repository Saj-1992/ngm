// Package config loads NGM configuration and defines canonical paths (MASTER_SPEC §4).
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DefaultPath is the canonical configuration file location.
const DefaultPath = "/etc/ngm/ngm.json"

// Paths are the canonical filesystem locations.
type Paths struct {
	Releases   string `json:"releases"`    // /opt/ngm/releases
	Current    string `json:"current"`     // /opt/ngm/current
	ConfigDir  string `json:"config_dir"`  // /etc/ngm
	KeysDir    string `json:"keys_dir"`    // /etc/ngm/keys
	StateDir   string `json:"state_dir"`   // /var/lib/ngm
	Websites   string `json:"websites"`    // /var/lib/ngm/websites
	Backups    string `json:"backups"`     // /var/lib/ngm/backups
	Generation string `json:"generations"` // /var/lib/ngm/generations
	LogDir     string `json:"log_dir"`     // /var/log/ngm
	RunDir     string `json:"run_dir"`     // /run/ngm
	NginxOwned string `json:"nginx_owned"` // /etc/nginx/ngm (NGM-owned include tree)
}

// DefaultPaths returns canonical production paths.
func DefaultPaths() Paths {
	return Paths{
		Releases:   "/opt/ngm/releases",
		Current:    "/opt/ngm/current",
		ConfigDir:  "/etc/ngm",
		KeysDir:    "/etc/ngm/keys",
		StateDir:   "/var/lib/ngm",
		Websites:   "/var/lib/ngm/websites",
		Backups:    "/var/lib/ngm/backups",
		Generation: "/var/lib/ngm/generations",
		LogDir:     "/var/log/ngm",
		RunDir:     "/run/ngm",
		NginxOwned: "/etc/nginx/ngm",
	}
}

// RootedPaths places every path under root (development and tests).
func RootedPaths(root string) Paths {
	p := DefaultPaths()
	for _, f := range []*string{&p.Releases, &p.Current, &p.ConfigDir, &p.KeysDir, &p.StateDir, &p.Websites, &p.Backups, &p.Generation, &p.LogDir, &p.RunDir, &p.NginxOwned} {
		*f = filepath.Join(root, filepath.FromSlash(*f))
	}
	return p
}

// Config is the on-disk configuration.
type Config struct {
	API struct {
		Listen string `json:"listen"` // default 127.0.0.1:9999; must be loopback
		// PublicOrigin is the HTTPS management origin, e.g. https://ngm.example.com
		// or https://ngm.example.com:9443. Empty during bootstrap (local/SSH-tunnel
		// access only).
		PublicOrigin string `json:"public_origin"`
		// PublicPath mounts the Control Center under a base path when published,
		// e.g. "/a1b2c3d4". Empty means the root. Requests arriving with this
		// prefix (through Nginx) are served the same as bare requests (SSH tunnel);
		// the SPA is told its base so assets and API calls resolve under the path.
		PublicPath string `json:"public_path,omitempty"`
	} `json:"api"`
	Paths   Paths `json:"paths"`
	Monitor struct {
		// DNSResolvers overrides /etc/resolv.conf for DNS evidence (IP addresses).
		DNSResolvers []string `json:"dns_resolvers,omitempty"`
	} `json:"monitor"`
	// DevMode relaxes nothing security-relevant; it only enables dev fixtures
	// that are visibly labelled (MASTER_SPEC §0).
	DevMode bool `json:"dev_mode"`
}

// Default returns the default configuration.
func Default() Config {
	var c Config
	c.API.Listen = "127.0.0.1:9999"
	c.Paths = DefaultPaths()
	return c
}

// DBPath is the main SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.Paths.StateDir, "ngm.db") }

// Load reads path, applying defaults for missing fields. A missing file yields
// defaults; unknown fields are rejected.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, c.Validate()
	}
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, c.Validate()
}

// Validate enforces configuration invariants.
func (c *Config) Validate() error {
	if err := ValidateLoopbackListen(c.API.Listen); err != nil {
		return fmt.Errorf("api.listen: %w", err)
	}
	if c.API.PublicOrigin != "" {
		if err := validateOrigin(c.API.PublicOrigin); err != nil {
			return fmt.Errorf("api.public_origin: %w", err)
		}
	}
	if err := ValidatePublicPath(c.API.PublicPath); err != nil {
		return fmt.Errorf("api.public_path: %w", err)
	}
	for _, r := range c.Monitor.DNSResolvers {
		if _, err := netip.ParseAddr(r); err != nil {
			return fmt.Errorf("monitor.dns_resolvers: %q is not an IP address", r)
		}
	}
	return nil
}

// ValidateLoopbackListen requires host:port with a loopback IP. The API is
// never exposed directly; Nginx fronts it over HTTPS (MASTER_SPEC §3).
func ValidateLoopbackListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("host must be a literal loopback IP, got %q", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback bind %s", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("bad port %q", port)
	}
	return nil
}

var publicPathSeg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,62}$`)

// ValidatePublicPath checks the Control Center base path. Empty is valid
// (root). Otherwise it is "/seg" or "/seg/seg", no trailing slash, each
// segment a bounded safe token, and not a path NGM reserves.
func ValidatePublicPath(p string) error {
	if p == "" {
		return nil
	}
	if p[0] != '/' || strings.HasSuffix(p, "/") {
		return errors.New(`must start with "/" and have no trailing slash`)
	}
	segs := strings.Split(p[1:], "/")
	if len(segs) > 4 {
		return errors.New("too many path segments")
	}
	for _, s := range segs {
		if !publicPathSeg.MatchString(s) {
			return fmt.Errorf("invalid path segment %q", s)
		}
	}
	switch segs[0] {
	case "api", "assets", ".well-known":
		return fmt.Errorf("%q is reserved", "/"+segs[0])
	}
	return nil
}

func validateOrigin(o string) error {
	const pfx = "https://"
	if len(o) <= len(pfx) || o[:len(pfx)] != pfx {
		return errors.New("must be an https:// origin")
	}
	rest := o[len(pfx):]
	for _, ch := range rest {
		if ch == '/' || ch == '?' || ch == '#' || ch == '@' {
			return errors.New("origin must not include path, query, fragment or userinfo")
		}
	}
	return nil
}
