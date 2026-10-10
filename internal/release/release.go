// Package release defines signed release manifests (MASTER_SPEC §16).
//
// A release directory holds manifest.json, manifest.sig (base64 Ed25519
// signature over the exact manifest bytes) and one binary per architecture.
// Verification trusts only public keys pinned into the binary (trusted/*.pub);
// keys fetched next to the artifacts are never trusted. Every failure is fatal.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schema is the manifest format version.
const Schema = 1

//go:embed trusted/*.pub
var trustedFS embed.FS

// Artifact is one per-architecture binary.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest describes one immutable release.
type Manifest struct {
	Schema     int        `json:"schema"`
	Product    string     `json:"product"`
	Version    string     `json:"version"`
	Channel    string     `json:"channel"` // stable | beta | development
	Commit     string     `json:"commit"`
	Date       time.Time  `json:"date"`
	KeyID      string     `json:"key_id"`
	Supported  []string   `json:"supported_os"` // e.g. ubuntu-22.04
	DBSchema   int        `json:"db_schema"`    // number of migrations shipped
	APIVersion string     `json:"api_version"`
	Requires   Requires   `json:"requires"`
	Artifacts  []Artifact `json:"artifacts"`
}

// Requires lists runtime expectations checked by the installer preflight.
type Requires struct {
	NginxModules []string `json:"nginx_modules"`
	Packages     []string `json:"packages"`
}

// Errors returned by verification (all fail closed).
var (
	ErrSignature = errors.New("release signature is not valid for any pinned publisher key")
	ErrUntrusted = errors.New("manifest is signed by a key that is not pinned in this build")
	ErrDigest    = errors.New("artifact digest does not match the signed manifest")
)

var (
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	fileRe    = regexp.MustCompile(`^ngm-linux-(amd64|arm64)$`)
	keyIDRe   = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
)

// Key is a pinned publisher key.
type Key struct {
	ID       string
	Channels []string // channels this key may sign
	Pub      ed25519.PublicKey
}

// Trusted returns the pinned keys. A file name is "<id>.pub"; a key whose id
// starts with "dev-" may sign only the development channel.
func Trusted() ([]Key, error) {
	ents, err := trustedFS.ReadDir("trusted")
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, e := range ents {
		b, _ := trustedFS.ReadFile("trusted/" + e.Name())
		pub, err := ParsePublicKey(b)
		if err != nil {
			return nil, fmt.Errorf("pinned key %s: %w", e.Name(), err)
		}
		id := strings.TrimSuffix(e.Name(), ".pub")
		ch := []string{"stable", "beta"}
		if strings.HasPrefix(id, "dev-") {
			ch = []string{"development"}
		}
		out = append(out, Key{ID: id, Channels: ch, Pub: pub})
	}
	return out, nil
}

// ParsePublicKey reads a PEM "PUBLIC KEY" (PKIX) Ed25519 key, the format
// `openssl pkeyutl -verify` accepts, so the shell installer and Go agree.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return pk, nil
}

// Verify checks the signature over raw against the pinned keys and returns
// the parsed manifest. The signature must come from a key pinned for the
// manifest's channel.
func Verify(raw, sigB64 []byte, keys []Key) (*Manifest, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	var signer *Key
	for i := range keys {
		if ed25519.Verify(keys[i].Pub, raw, sig) {
			signer = &keys[i]
			break
		}
	}
	if signer == nil {
		return nil, ErrSignature
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.KeyID != signer.ID {
		return nil, fmt.Errorf("%w (manifest names %q, signature is from %q)", ErrUntrusted, m.KeyID, signer.ID)
	}
	if !contains(signer.Channels, m.Channel) {
		return nil, fmt.Errorf("%w: key %s may not sign the %s channel", ErrUntrusted, signer.ID, m.Channel)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	switch {
	case m.Schema != Schema:
		return fmt.Errorf("manifest schema %d is not supported", m.Schema)
	case m.Product != "ngm":
		return errors.New("manifest is not for NGM")
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("invalid version %q", m.Version)
	case !contains([]string{"stable", "beta", "development"}, m.Channel):
		return fmt.Errorf("invalid channel %q", m.Channel)
	case !keyIDRe.MatchString(m.KeyID):
		return errors.New("invalid key id")
	case len(m.Artifacts) == 0:
		return errors.New("manifest lists no artifacts")
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if a.OS != "linux" || !fileRe.MatchString(a.File) || a.File != "ngm-linux-"+a.Arch || seen[a.Arch] || len(a.SHA256) != 64 || a.Size <= 0 {
			return fmt.Errorf("invalid artifact entry %q", a.File)
		}
		seen[a.Arch] = true
	}
	return nil
}

// ArtifactFor returns the entry for goarch (default: the running arch).
func (m *Manifest) ArtifactFor(goarch string) (*Artifact, error) {
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	for i := range m.Artifacts {
		if m.Artifacts[i].Arch == goarch {
			return &m.Artifacts[i], nil
		}
	}
	return nil, fmt.Errorf("release %s has no linux/%s artifact", m.Version, goarch)
}

// CheckFile verifies size and SHA-256 of path against a.
func CheckFile(path string, a *Artifact) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%w: %s", ErrDigest, a.File)
	}
	return nil
}

// LoadDir reads and verifies <dir>/manifest.json + manifest.sig.
func LoadDir(dir string, keys []Key) (*Manifest, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	m, err := Verify(raw, sig, keys)
	return m, raw, err
}

// Build hashes the binaries in dir and returns an unsigned manifest.
func Build(dir string, m Manifest) ([]byte, error) {
	m.Schema, m.Product = Schema, "ngm"
	m.Artifacts = nil
	for _, arch := range []string{"amd64", "arm64"} {
		p := filepath.Join(dir, "ngm-linux-"+arch)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		m.Artifacts = append(m.Artifacts, Artifact{OS: "linux", Arch: arch, File: "ngm-linux-" + arch, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Arch < m.Artifacts[j].Arch })
	if err := m.validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	return append(b, '\n'), err
}

// Sign returns the base64 signature line for raw.
func Sign(priv ed25519.PrivateKey, raw []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)) + "\n")
}

// ParsePrivateKey reads a PEM "PRIVATE KEY" (PKCS#8) Ed25519 key.
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return pk, nil
}

// MarshalKeys encodes a key pair as PEM (private PKCS#8, public PKIX).
func MarshalKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) (privPEM, pubPEM []byte, err error) {
	pb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	ub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pb}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ub}), nil
}

// CompareVersions orders semantic versions (pre-release < release).
func CompareVersions(a, b string) int {
	split := func(v string) ([3]int, string) {
		var n [3]int
		core, pre, _ := strings.Cut(v, "-")
		for i, p := range strings.SplitN(core, ".", 3) {
			fmt.Sscanf(p, "%d", &n[i])
		}
		return n, pre
	}
	na, pa := split(a)
	nb, pb := split(b)
	for i := 0; i < 3; i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return comparePre(pa, pb)
}

// comparePre orders pre-release labels by semver rules: dot-separated
// identifiers, numeric ones compared numerically (rc.9 < rc.10) and below
// alphanumeric ones; a shorter list of equal identifiers sorts first.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, xerr := strconv.Atoi(as[i])
		y, yerr := strconv.Atoi(bs[i])
		switch {
		case xerr == nil && yerr == nil:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		case as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
