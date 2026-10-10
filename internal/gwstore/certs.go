package gwstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Cert is the client-safe certificate view (never includes the key).
type Cert struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Source      string    `json:"source"`
	SANs        []string  `json:"sans"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Status      string    `json:"status"`
	HasKey      bool      `json:"has_key"`
	Revision    int64     `json:"revision"`
	// ACME holds the automation state (directory, names, last attempt/error).
	ACME json.RawMessage `json:"acme,omitempty"`
}

func keyRef(id string) vault.Ref { return vault.Ref{Type: "tls_key", Scope: "cert:" + id, Name: "key"} }

// keyRefV addresses one key version ("" = the legacy single key).
func keyRefV(id, keyID string) vault.Ref {
	if keyID == "" {
		return keyRef(id)
	}
	return vault.Ref{Type: "tls_key", Scope: "cert:" + id, Name: "key-" + keyID}
}

// KeyFileID is the deployed key file name (without .key) for a key version.
func KeyFileID(certID, keyID string) string {
	if keyID == "" {
		return certID
	}
	return keyID
}

const certCols = "id,name,source,sans_json,issuer,COALESCE(not_before,''),COALESCE(not_after,''),COALESCE(fingerprint_sha256,''),status,key_secret_id IS NOT NULL,revision,acme_json"

func scanCert(sc interface{ Scan(...any) error }, now time.Time) (*Cert, error) {
	var c Cert
	var sans, nb, na, aj string
	var hk int
	if err := sc.Scan(&c.ID, &c.Name, &c.Source, &sans, &c.Issuer, &nb, &na, &c.Fingerprint, &c.Status, &hk, &c.Revision, &aj); err != nil {
		return nil, err
	}
	if c.Source == "acme" && aj != "" && aj != "{}" {
		c.ACME = json.RawMessage(aj)
	}
	_ = json.Unmarshal([]byte(sans), &c.SANs)
	c.NotBefore, _ = store.ParseTime(nb)
	c.NotAfter, _ = store.ParseTime(na)
	c.HasKey = hk == 1
	// Status is derived from evidence at read time.
	switch {
	case !c.NotAfter.IsZero() && !now.Before(c.NotAfter):
		c.Status = "expired"
	case !c.NotAfter.IsZero() && c.NotAfter.Sub(now) < 14*24*time.Hour:
		c.Status = "expiring"
	}
	return &c, nil
}

// ListCertificates returns all certificates.
func (s *Service) ListCertificates(ctx context.Context) ([]*Cert, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+certCols+" FROM certificates ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Cert{}
	for rows.Next() {
		c, err := scanCert(rows, s.now())
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCertificate loads one certificate.
func (s *Service) GetCertificate(ctx context.Context, id string) (*Cert, error) {
	c, err := scanCert(s.db.QueryRowContext(ctx, "SELECT "+certCols+" FROM certificates WHERE id=?", id), s.now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ParsedCert is a validated certificate + key pair.
type ParsedCert struct {
	ChainPEM string
	KeyPEM   []byte
	Leaf     *x509.Certificate
}

// ParseCertAndKey validates PEM input: at least one certificate, a private
// key matching the leaf, and a well-formed chain order.
func ParseCertAndKey(certPEM, keyPEM string) (*ParsedCert, error) {
	if len(certPEM) > 64<<10 || len(keyPEM) > 16<<10 {
		return nil, invalid("certificate or key too large")
	}
	var certs []*x509.Certificate
	var chain strings.Builder
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, invalid("certificate input must contain only CERTIFICATE blocks")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, invalid("cannot parse certificate: %v", err)
		}
		certs = append(certs, c)
		_ = pem.Encode(&chain, b)
	}
	if len(certs) == 0 {
		return nil, invalid("no PEM certificate found")
	}
	for i := 1; i < len(certs); i++ {
		if err := certs[i-1].CheckSignatureFrom(certs[i]); err != nil {
			return nil, invalid("chain order invalid: certificate %d is not signed by certificate %d", i, i+1)
		}
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, invalid("no PEM private key found")
	}
	var key crypto.PrivateKey
	var err error
	switch kb.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	default:
		return nil, invalid("unsupported private key type %q (encrypted keys are not supported)", kb.Type)
	}
	if err != nil {
		return nil, invalid("cannot parse private key")
	}
	pub, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, invalid("unsupported private key")
	}
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := pub.Public().(eq); !ok || !e.Equal(certs[0].PublicKey) {
		return nil, invalid("private key does not match the certificate")
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, invalid("unsupported key algorithm")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, invalid("cannot encode private key")
	}
	kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return &ParsedCert{ChainPEM: chain.String(), KeyPEM: kp, Leaf: certs[0]}, nil
}

func sansOf(c *x509.Certificate) []string {
	out := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// ImportCertificate stores an uploaded certificate (key goes to the vault).
func (s *Service) ImportCertificate(ctx context.Context, actor *auth.Principal, name, certPEM, keyPEM, source string) (*Cert, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	pc, err := ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	defer clear(pc.KeyPEM)
	if !s.now().Before(pc.Leaf.NotAfter) {
		return nil, invalid("certificate expired on %s", pc.Leaf.NotAfter.Format("2006-01-02"))
	}
	if len(pc.Leaf.DNSNames) == 0 {
		return nil, invalid("certificate has no DNS subjectAltName")
	}
	fp := sha256.Sum256(pc.Leaf.Raw)
	sans, _ := json.Marshal(sansOf(pc.Leaf))
	id, keyID := ids.New(), ids.New()
	now := store.FormatTime(s.now())
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO certificates(id,name,source,sans_json,not_before,not_after,fingerprint_sha256,status,cert_pem,issuer,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,'valid',?,?,?,?)`, id, strings.TrimSpace(name), source, string(sans), store.FormatTime(pc.Leaf.NotBefore), store.FormatTime(pc.Leaf.NotAfter),
			hex.EncodeToString(fp[:]), pc.ChainPEM, pc.Leaf.Issuer.CommonName, now, now); err != nil {
			return uniqueErr(err, "a certificate with this name exists")
		}
		sid, err := s.vault.PutTx(ctx, tx, keyRefV(id, keyID), pc.KeyPEM)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE certificates SET key_secret_id=?, key_id=? WHERE id=?", sid, keyID, id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "certificate.import", "certificate", id, map[string]any{"name": name, "sans": sansOf(pc.Leaf), "source": source})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "certificate", id)
	return s.GetCertificate(ctx, id)
}

// GenerateSelfSigned creates a self-signed ECDSA P-256 certificate for hosts.
func (s *Service) GenerateSelfSigned(ctx context.Context, actor *auth.Principal, name string, hostsIn []string, days int) (*Cert, error) {
	if days < 1 || days > 825 {
		return nil, invalid("validity must be 1–825 days")
	}
	var hosts []string
	for _, h := range hostsIn {
		h = strings.ToLower(strings.TrimSpace(h))
		if strings.HasPrefix(h, "*.") {
			if !gateway.ValidHostname(h[2:]) {
				return nil, invalid("invalid host %q", h)
			}
		} else if !gateway.ValidHostname(h) {
			return nil, invalid("invalid host %q", h)
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 || len(hosts) > 100 {
		return nil, invalid("1–100 host names required")
	}
	certPEM, keyPEM, err := SelfSigned(hosts, time.Duration(days)*24*time.Hour, s.now())
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	return s.ImportCertificate(ctx, actor, name, certPEM, string(keyPEM), "self_signed")
}

// SelfSigned returns a PEM certificate and PKCS#8 key.
func SelfSigned(hosts []string, validity time.Duration, now time.Time) (string, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: hosts[0], Organization: []string{"NGM self-signed"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(validity), DNSNames: hosts,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

// DeleteCertificate deletes an unused certificate and its key.
func (s *Service) DeleteCertificate(ctx context.Context, actor *auth.Principal, id string, rev int64) error {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkRev(ctx, tx, "certificates", id, rev); err != nil {
			return err
		}
		var n int
		_ = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE certificate_id=?", id).Scan(&n)
		if n > 0 {
			return fmt.Errorf("%w: %d route(s) use this certificate", ErrInUse, n)
		}
		if GetFallback(ctx, tx).CertificateID == id {
			return fmt.Errorf("%w: this certificate serves the fallback website", ErrInUse)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE certificates SET key_secret_id=NULL WHERE id=?", id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM vault_secrets WHERE type='tls_key' AND scope=?", "cert:"+id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM certificates WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "certificate.delete", "certificate", id, nil)
	})
	if err == nil {
		s.changed(ctx, "certificate", id)
	}
	return err
}

// CertMat is deployable certificate material.
type CertMat struct {
	Chains  map[string]string // certificate id → PEM chain (public)
	KeyFile map[string]string // certificate id → key file id (KeyFileID)
	Keys    map[string][]byte // key file id → PEM private key (secret)
}

// Clear wipes the private keys.
func (m *CertMat) Clear() {
	if m == nil {
		return
	}
	for _, k := range m.Keys {
		clear(k)
	}
}

// CertMaterial returns the current chain and key version of each certificate.
// Callers must Clear the result and never log keys.
func (s *Service) CertMaterial(ctx context.Context, ids []string) (*CertMat, error) {
	m := &CertMat{Chains: map[string]string{}, KeyFile: map[string]string{}, Keys: map[string][]byte{}}
	for _, id := range ids {
		var pemS, keyID string
		if err := s.db.QueryRowContext(ctx, "SELECT cert_pem, key_id FROM certificates WHERE id=?", id).Scan(&pemS, &keyID); err != nil {
			m.Clear()
			return nil, fmt.Errorf("certificate %s: %w", id, err)
		}
		k, err := s.vault.Get(ctx, keyRefV(id, keyID))
		if err != nil {
			m.Clear()
			return nil, fmt.Errorf("certificate %s key: %w", id, err)
		}
		f := KeyFileID(id, keyID)
		m.Chains[id], m.KeyFile[id], m.Keys[f] = pemS, f, k
	}
	return m, nil
}

// KeyVersions returns exactly the requested key versions (certificate id →
// key file id), e.g. to re-stage an older generation after renewal.
func (s *Service) KeyVersions(ctx context.Context, want map[string]string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for certID, fileID := range want {
		keyID := fileID
		if fileID == certID {
			keyID = ""
		}
		k, err := s.vault.Get(ctx, keyRefV(certID, keyID))
		if err != nil {
			for _, v := range out {
				clear(v)
			}
			return nil, fmt.Errorf("certificate %s key version %s: %w", certID, fileID, err)
		}
		out[fileID] = k
	}
	return out, nil
}

// CurrentKeyFiles maps every certificate to its current key file id.
func (s *Service) CurrentKeyFiles(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, key_id FROM certificates")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, k string
		if err := rows.Scan(&id, &k); err != nil {
			return nil, err
		}
		out[id] = KeyFileID(id, k)
	}
	return out, rows.Err()
}

// PruneKeyVersions deletes key versions that are neither current nor in keep
// (key file ids referenced by retained generations).
func (s *Service) PruneKeyVersions(ctx context.Context, keep map[string]bool) (int, error) {
	cur, err := s.CurrentKeyFiles(ctx)
	if err != nil {
		return 0, err
	}
	for _, f := range cur {
		keep[f] = true
	}
	rows, err := s.db.QueryContext(ctx, "SELECT scope, name FROM vault_secrets WHERE type='tls_key'")
	if err != nil {
		return 0, err
	}
	type ref struct{ scope, name string }
	var drop []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.scope, &r.name); err != nil {
			rows.Close()
			return 0, err
		}
		certID := strings.TrimPrefix(r.scope, "cert:")
		f := certID
		if strings.HasPrefix(r.name, "key-") {
			f = strings.TrimPrefix(r.name, "key-")
		}
		if !keep[f] {
			drop = append(drop, r)
		}
	}
	rows.Close()
	for _, r := range drop {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM vault_secrets WHERE type='tls_key' AND scope=? AND name=? AND id NOT IN (SELECT key_secret_id FROM certificates WHERE key_secret_id IS NOT NULL)", r.scope, r.name); err != nil {
			return 0, err
		}
	}
	return len(drop), nil
}

// ReplaceCertificate installs a new certificate + key version for an
// existing certificate (ACME renewal, manual re-import). The previous key
// version is kept for generations that still use it.
func (s *Service) ReplaceCertificate(ctx context.Context, actor *auth.Principal, id, certPEM, keyPEM string) (*Cert, error) {
	pc, err := ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	defer clear(pc.KeyPEM)
	if !s.now().Before(pc.Leaf.NotAfter) {
		return nil, invalid("certificate expired on %s", pc.Leaf.NotAfter.Format("2006-01-02"))
	}
	old, err := s.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	// The new certificate must still cover every name the old one covered,
	// so no route loses a valid certificate silently.
	have := map[string]bool{}
	for _, n := range sansOf(pc.Leaf) {
		have[strings.ToLower(n)] = true
	}
	for _, n := range old.SANs {
		if !have[strings.ToLower(n)] {
			return nil, invalid("replacement certificate does not cover %s", n)
		}
	}
	fp := sha256.Sum256(pc.Leaf.Raw)
	sans, _ := json.Marshal(sansOf(pc.Leaf))
	keyID := ids.New()
	now := store.FormatTime(s.now())
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		sid, err := s.vault.PutTx(ctx, tx, keyRefV(id, keyID), pc.KeyPEM)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET sans_json=?, not_before=?, not_after=?, fingerprint_sha256=?, status='valid', cert_pem=?, issuer=?,
			key_secret_id=?, key_id=?, revision=revision+1, updated_at=? WHERE id=?`, string(sans), store.FormatTime(pc.Leaf.NotBefore), store.FormatTime(pc.Leaf.NotAfter),
			hex.EncodeToString(fp[:]), pc.ChainPEM, pc.Leaf.Issuer.CommonName, sid, keyID, now, id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "certificate.replace", "certificate", id, map[string]any{"not_after": pc.Leaf.NotAfter, "fingerprint": hex.EncodeToString(fp[:])})
	})
	if err != nil {
		return nil, err
	}
	s.changed(ctx, "certificate", id)
	return s.GetCertificate(ctx, id)
}
