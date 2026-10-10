package certauto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

type fakeCA struct {
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	registered int
	accepted   []string
	failAuthz  bool
	wrongNames bool
}

func newFakeCA(t *testing.T) *fakeCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24 * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &fakeCA{caKey: k, caCert: c}
}

type fakeClient struct {
	ca  *fakeCA
	ids []string
}

func (f *fakeClient) Register(_ context.Context, a *acme.Account, _ func(string) bool) (*acme.Account, error) {
	f.ca.registered++
	return &acme.Account{URI: "https://ca/acct/1"}, nil
}
func (f *fakeClient) GetReg(context.Context, string) (*acme.Account, error) {
	return &acme.Account{URI: "https://ca/acct/1"}, nil
}
func (f *fakeClient) AuthorizeOrder(_ context.Context, id []acme.AuthzID, _ ...acme.OrderOption) (*acme.Order, error) {
	o := &acme.Order{URI: "https://ca/order/1", Status: acme.StatusPending, FinalizeURL: "https://ca/finalize/1"}
	for _, i := range id {
		f.ids = append(f.ids, i.Value)
		o.AuthzURLs = append(o.AuthzURLs, "https://ca/authz/"+i.Value)
	}
	return o, nil
}
func (f *fakeClient) GetAuthorization(_ context.Context, u string) (*acme.Authorization, error) {
	n := strings.TrimPrefix(u, "https://ca/authz/")
	return &acme.Authorization{URI: u, Status: acme.StatusPending, Identifier: acme.AuthzID{Type: "dns", Value: n},
		Challenges: []*acme.Challenge{{Type: "dns-01", Token: "dnsTOKENdnsTOKENdns"}, {Type: "http-01", Token: "TOKEN0123456789" + strings.ReplaceAll(n, ".", "")}}}, nil
}
func (f *fakeClient) HTTP01ChallengeResponse(token string) (string, error) {
	return token + "." + strings.Repeat("T", 43), nil
}
func (f *fakeClient) Accept(_ context.Context, c *acme.Challenge) (*acme.Challenge, error) {
	f.ca.accepted = append(f.ca.accepted, c.Token)
	return c, nil
}
func (f *fakeClient) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	if f.ca.failAuthz {
		return nil, errors.New("urn:ietf:params:acme:error:unauthorized: invalid response")
	}
	return &acme.Authorization{Status: acme.StatusValid}, nil
}
func (f *fakeClient) WaitOrder(_ context.Context, u string) (*acme.Order, error) {
	return &acme.Order{URI: u, Status: acme.StatusReady, FinalizeURL: "https://ca/finalize/1"}, nil
}
func (f *fakeClient) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", err
	}
	names := csr.DNSNames
	if f.ca.wrongNames {
		names = []string{"evil.example.org"}
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, f.ca.caCert, csr.PublicKey, f.ca.caKey)
	return [][]byte{der, f.ca.caCert.Raw}, "https://ca/cert/1", err
}

type memChallenges struct {
	files map[string]string
	puts  int
}

func (m *memChallenges) Put(_ context.Context, tok, ka string) error {
	m.files[tok] = ka
	m.puts++
	return nil
}
func (m *memChallenges) Clear(_ context.Context, tok string) error {
	delete(m.files, tok)
	return nil
}

func setup(t *testing.T) (*Issuer, *fakeCA, *memChallenges) {
	db := storetest.New(t)
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	v := vault.New(db, kr)
	v.Init(context.Background())
	ca := newFakeCA(t)
	ch := &memChallenges{files: map[string]string{}}
	is := &Issuer{DB: db, Vault: v, NewClient: func(string, crypto.Signer) Client { return &fakeClient{ca: ca} }}
	is.Check = func(_ context.Context, name, tok, want string) error {
		if ch.files[tok] != want {
			return errors.New("self-check: challenge not served")
		}
		return nil
	}
	return is.WithChallenges(ch), ca, ch
}

func TestIssueHTTP01(t *testing.T) {
	is, ca, ch := setup(t)
	ctx := context.Background()
	var steps []string
	res, err := is.Issue(ctx, Directories["letsencrypt-staging"], "ops@example.com", []string{"example.com", "www.example.com"}, func(n string, _ any) { steps = append(steps, n) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.ChainPEM, "BEGIN CERTIFICATE") || !strings.Contains(string(res.KeyPEM), "PRIVATE KEY") || res.NotAfter.Before(time.Now()) {
		t.Fatal("result")
	}
	if len(ca.accepted) != 2 || ch.puts != 2 || len(ch.files) != 0 {
		t.Fatalf("challenges accepted=%v puts=%d left=%v", ca.accepted, ch.puts, ch.files)
	}
	if strings.Join(steps, " ") != "order challenge_ready authorized challenge_ready authorized issued" {
		t.Fatalf("steps %v", steps)
	}
	// Second order reuses the stored account.
	if _, err := is.Issue(ctx, Directories["letsencrypt-staging"], "", []string{"example.com"}, nil); err != nil || ca.registered != 1 {
		t.Fatalf("account reuse: %v registered=%d", err, ca.registered)
	}
	var n int
	is.DB.QueryRowContext(ctx, "SELECT count(*) FROM vault_secrets WHERE type='acme_account'").Scan(&n)
	if n != 1 {
		t.Fatalf("account keys in vault: %d", n)
	}
}

func TestIssueFailuresStopSafely(t *testing.T) {
	ctx := context.Background()
	// Self-check fails → the CA is never asked to validate.
	is, ca, ch := setup(t)
	is.Check = func(context.Context, string, string, string) error {
		return errors.New("self-check example.com: HTTP 404")
	}
	if _, err := is.Issue(ctx, "https://ca/dir", "", []string{"example.com"}, nil); err == nil || len(ca.accepted) != 0 || len(ch.files) != 0 {
		t.Fatalf("self-check: %v accepted=%v left=%v", err, ca.accepted, ch.files)
	}
	// CA rejects validation → error, challenge files cleared.
	is, ca, ch = setup(t)
	ca.failAuthz = true
	if _, err := is.Issue(ctx, "https://ca/dir", "", []string{"example.com"}, nil); err == nil || !strings.Contains(err.Error(), "validation failed") || len(ch.files) != 0 {
		t.Fatalf("authz failure: %v left=%v", err, ch.files)
	}
	// Certificate for other names is rejected before it is stored.
	is, ca, _ = setup(t)
	ca.wrongNames = true
	if _, err := is.Issue(ctx, "https://ca/dir", "", []string{"example.com"}, nil); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("wrong names: %v", err)
	}
}

func TestValidateIdentifiers(t *testing.T) {
	if _, err := ValidateIdentifiers([]string{"*.example.com"}); err == nil || !strings.Contains(err.Error(), "DNS-01") {
		t.Fatalf("wildcard: %v", err)
	}
	for _, bad := range [][]string{nil, {"localhost"}, {"exa mple.com"}, {"1.2.3.4x"}} {
		if _, err := ValidateIdentifiers(bad); err == nil && bad != nil {
			if bad[0] != "1.2.3.4x" {
				t.Fatalf("accepted %v", bad)
			}
		}
	}
	got, err := ValidateIdentifiers([]string{"Example.com.", "example.com", "www.example.com"})
	if err != nil || strings.Join(got, ",") != "example.com,www.example.com" {
		t.Fatalf("%v %v", got, err)
	}
}
