// Package certauto issues and renews certificates through ACME (RFC 8555)
// with the HTTP-01 challenge served by NGM's own Nginx (MASTER_SPEC §6.2).
// Only HTTP-01 is implemented; wildcard names (which need DNS-01) are
// refused rather than promised.
package certauto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Known ACME directories. Staging certificates are not trusted by browsers.
var Directories = map[string]string{
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
}

// CADomain is the CAA issuer domain for the known directories.
const CADomain = "letsencrypt.org"

// Client is the subset of *acme.Client used here (fakes in tests).
type Client interface {
	Register(ctx context.Context, acct *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	GetReg(ctx context.Context, url string) (*acme.Account, error)
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	HTTP01ChallengeResponse(token string) (string, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error)
}

// Challenges publishes HTTP-01 responses (the helper in production).
type Challenges interface {
	Put(ctx context.Context, token, keyAuth string) error
	Clear(ctx context.Context, token string) error
}

// SelfCheck fetches http://<name>/.well-known/acme-challenge/<token> the way
// the CA will, before the CA is asked to validate (saves CA rate limits).
type SelfCheck func(ctx context.Context, name, token, want string) error

// Issuer runs orders.
type Issuer struct {
	DB    *store.DB
	Vault *vault.Vault
	// NewClient builds an ACME client for a directory and account key.
	NewClient func(directory string, key crypto.Signer) Client
	Check     SelfCheck
	Logf      func(string, ...any)
	pub       Challenges
}

func (is *Issuer) logf(f string, a ...any) {
	if is.Logf != nil {
		is.Logf(f, a...)
	}
}

// DefaultClient returns a real ACME client.
func DefaultClient(directory string, key crypto.Signer) Client {
	return &acme.Client{Key: key, DirectoryURL: directory, UserAgent: "ngm"}
}

// HTTPSelfCheck is the default SelfCheck (plain HTTP on port 80, no redirects).
func HTTPSelfCheck(ctx context.Context, name, token, want string) error {
	cl := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+name+"/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("self-check %s: %w", name, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != want {
		return fmt.Errorf("self-check %s: HTTP %d (does %s resolve to this server, with an NGM HTTP listener on port 80 deployed?)", name, resp.StatusCode, name)
	}
	return nil
}

// ValidateIdentifiers checks names for HTTP-01.
func ValidateIdentifiers(names []string) ([]string, error) {
	if len(names) == 0 || len(names) > 50 {
		return nil, errors.New("1–50 names required")
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if strings.HasPrefix(n, "*.") {
			return nil, fmt.Errorf("%s: wildcard names need the DNS-01 challenge, which NGM does not implement", n)
		}
		if !validName(n) {
			return nil, fmt.Errorf("invalid name %q", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func validName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func accountRef(id string) vault.Ref {
	return vault.Ref{Type: "acme_account", Scope: "acme:" + id, Name: "key"}
}

// account returns (and registers on first use) the account for directory.
func (is *Issuer) account(ctx context.Context, directory, email string) (Client, error) {
	var id, url string
	err := is.DB.QueryRowContext(ctx, "SELECT id, account_url FROM acme_accounts WHERE directory_url=?", directory).Scan(&id, &url)
	if err == nil {
		raw, err := is.Vault.Get(ctx, accountRef(id))
		if err != nil {
			return nil, fmt.Errorf("ACME account key: %w", err)
		}
		defer clear(raw)
		k, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, err
		}
		cl := is.NewClient(directory, k)
		if _, err := cl.GetReg(ctx, url); err != nil {
			return nil, fmt.Errorf("ACME account lookup: %w", err)
		}
		return cl, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cl := is.NewClient(directory, k)
	acct := &acme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	reg, err := cl.Register(ctx, acct, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		reg, err = cl.GetReg(ctx, "")
	}
	if err != nil {
		return nil, fmt.Errorf("ACME registration: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	id = ids.New()
	err = is.DB.Tx(ctx, func(tx *sql.Tx) error {
		sid, err := is.Vault.PutTx(ctx, tx, accountRef(id), der)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO acme_accounts(id,directory_url,email,account_url,key_secret_id,created_at) VALUES(?,?,?,?,?,?)",
			id, directory, email, reg.URI, sid, store.FormatTime(time.Now()))
		return err
	})
	return cl, err
}

// Result is an issued certificate.
type Result struct {
	ChainPEM string
	KeyPEM   []byte
	NotAfter time.Time
}

// Step reports progress (journaled by the caller).
type Step func(name string, evidence any)

// Issue runs one order for names and returns the verified chain and new key.
func (is *Issuer) Issue(ctx context.Context, directory, email string, names []string, step Step) (*Result, error) {
	if step == nil {
		step = func(string, any) {}
	}
	cl, err := is.account(ctx, directory, email)
	if err != nil {
		return nil, err
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, fmt.Errorf("new order: %w", err)
	}
	step("order", map[string]any{"order": order.URI, "status": order.Status, "authorizations": len(order.AuthzURLs)})
	var published []string
	defer func() {
		for _, t := range published {
			_ = is.challenges().Clear(context.WithoutCancel(ctx), t)
		}
	}()
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue // reused authorization
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("%s: the CA offered no http-01 challenge", z.Identifier.Value)
		}
		ka, err := cl.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, err
		}
		if err := is.challenges().Put(ctx, chal.Token, ka); err != nil {
			return nil, fmt.Errorf("publish challenge: %w", err)
		}
		published = append(published, chal.Token)
		if is.Check != nil {
			if err := is.Check(ctx, z.Identifier.Value, chal.Token, ka); err != nil {
				return nil, err // the CA is not contacted for validation
			}
		}
		step("challenge_ready", map[string]any{"name": z.Identifier.Value, "self_check": is.Check != nil})
		if _, err := cl.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return nil, fmt.Errorf("%s: validation failed: %w", z.Identifier.Value, err)
		}
		step("authorized", map[string]any{"name": z.Identifier.Value})
	}
	order, err = cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("order not ready: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	if err != nil {
		return nil, err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	if len(ders) == 0 {
		return nil, errors.New("the CA returned no certificate")
	}
	var chain strings.Builder
	for _, d := range ders {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, err
	}
	// Verify before anything is stored: names, key and validity.
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			return nil, fmt.Errorf("issued certificate does not cover %s", n)
		}
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return nil, errors.New("issued certificate does not match the generated key")
	}
	if time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore.Add(-time.Hour)) {
		return nil, errors.New("issued certificate is not currently valid")
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	step("issued", map[string]any{"not_after": leaf.NotAfter, "issuer": leaf.Issuer.CommonName, "chain_length": len(ders)})
	return &Result{ChainPEM: chain.String(), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), NotAfter: leaf.NotAfter}, nil
}

var noChallenges = errors.New("no challenge publisher configured")

type nopChallenges struct{}

func (nopChallenges) Put(context.Context, string, string) error { return noChallenges }
func (nopChallenges) Clear(context.Context, string) error       { return nil }

// WithChallenges returns a copy of the issuer using c to publish responses.
func (is *Issuer) WithChallenges(c Challenges) *Issuer {
	cp := *is
	cp.pub = c
	return &cp
}

func (is *Issuer) challenges() Challenges {
	if is.pub == nil {
		return nopChallenges{}
	}
	return is.pub
}
