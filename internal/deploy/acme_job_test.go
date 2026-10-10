package deploy

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

	"github.com/ngm-gateway/ngm/internal/certauto"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// testCA signs any CSR; it "validates" by reading the fake helper's files.
type testCA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	h      *fakeHelper
	issued int
	life   time.Duration
}

func newTestCA(h *fakeHelper) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: k, cert: c, h: h, life: 90 * 24 * time.Hour}
}

type testClient struct{ ca *testCA }

func (t testClient) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	return &acme.Account{URI: "https://ca/acct"}, nil
}
func (t testClient) GetReg(context.Context, string) (*acme.Account, error) {
	return &acme.Account{URI: "https://ca/acct"}, nil
}
func (t testClient) AuthorizeOrder(_ context.Context, id []acme.AuthzID, _ ...acme.OrderOption) (*acme.Order, error) {
	o := &acme.Order{URI: "https://ca/order", FinalizeURL: "https://ca/fin"}
	for _, i := range id {
		o.AuthzURLs = append(o.AuthzURLs, "https://ca/authz/"+i.Value)
	}
	return o, nil
}
func (t testClient) GetAuthorization(_ context.Context, u string) (*acme.Authorization, error) {
	n := strings.TrimPrefix(u, "https://ca/authz/")
	return &acme.Authorization{URI: u, Identifier: acme.AuthzID{Value: n}, Challenges: []*acme.Challenge{{Type: "http-01", Token: "tok0123456789abcd" + strings.ReplaceAll(n, ".", "")}}}, nil
}
func (t testClient) HTTP01ChallengeResponse(tok string) (string, error) {
	return tok + "." + strings.Repeat("A", 43), nil
}
func (t testClient) Accept(_ context.Context, c *acme.Challenge) (*acme.Challenge, error) {
	t.ca.h.mu.Lock()
	defer t.ca.h.mu.Unlock()
	if t.ca.h.acme[c.Token] == "" {
		return nil, errors.New("challenge not published")
	}
	return c, nil
}
func (t testClient) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusValid}, nil
}
func (t testClient) WaitOrder(_ context.Context, u string) (*acme.Order, error) {
	return &acme.Order{URI: u, FinalizeURL: "https://ca/fin", Status: acme.StatusReady}, nil
}
func (t testClient) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	csr, _ := x509.ParseCertificateRequest(csrDER)
	t.ca.issued++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(t.ca.issued + 1)), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(t.ca.life)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, t.ca.cert, csr.PublicKey, t.ca.key)
	return [][]byte{der, t.ca.cert.Raw}, "", err
}

func acmeEnv(t *testing.T) (*env, *testCA) {
	e := newEnv(t)
	kr := vault.NewKeyring()
	kr.Add(1, make([]byte, 32))
	v := vault.New(e.db, kr)
	ca := newTestCA(e.h)
	e.c.ACME = &certauto.Issuer{DB: e.db, Vault: v, NewClient: func(string, crypto.Signer) certauto.Client { return testClient{ca} }}
	return e, ca
}

func TestACMEIssueRenewAndDeploy(t *testing.T) {
	ctx := context.Background()
	e, ca := acmeEnv(t)
	req := ACMEPayload{Name: "site", Identifiers: []string{"a.example.com"}, Directory: "letsencrypt-staging"}
	// Nothing deployed → HTTP-01 impossible → Blocked before any CA contact.
	if j := e.submit(t, KindACME, req); j.State != jobs.Blocked || !strings.Contains(string(j.Error), "http01_unavailable") || ca.issued != 0 {
		t.Fatalf("no http listener: %s %s", j.State, j.Error)
	}
	// Port 8080 only is not enough.
	e.seed(t, 8080)
	e.submit(t, KindApply, ApplyPayload{})
	if j := e.submit(t, KindACME, req); j.State != jobs.Blocked {
		t.Fatalf("port 8080: %s", j.State)
	}
	if _, err := e.gw.SaveListener(ctx, nil, &gateway.Listener{Name: "web80", Kind: gateway.KindHTTP, Address: "0.0.0.0", Port: 80, Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatalf("apply :80: %s %s", j.State, j.Error)
	}
	// Wildcards are refused (DNS-01 not implemented).
	if j := e.submit(t, KindACME, ACMEPayload{Name: "w", Identifiers: []string{"*.example.com"}, Directory: "letsencrypt-staging"}); j.State != jobs.Blocked {
		t.Fatalf("wildcard: %s", j.State)
	}
	// CAA evidence forbidding the CA blocks issuance.
	reg := &domains.Service{DB: e.db, Audit: e.c.Audit}
	d, _ := reg.Create(ctx, nil, "example.com", "general", "")
	e.db.ExecContext(ctx, `INSERT INTO dns_observations(domain_id,name,rtype,source,values_json,observed_at) VALUES(?,?,?,?,?,?)`,
		d.ID, "example.com", "CAA", "authoritative", `["0 issue \"digicert.com\""]`, store.FormatTime(time.Now()))
	if j := e.submit(t, KindACME, req); j.State != jobs.Blocked || !strings.Contains(string(j.Error), "caa_forbids") || ca.issued != 0 {
		t.Fatalf("caa: %s %s", j.State, j.Error)
	}
	e.db.ExecContext(ctx, `UPDATE dns_observations SET values_json=?`, `["0 issue \"letsencrypt.org\""]`)
	// Issue.
	j := e.submit(t, KindACME, req)
	if j.State != jobs.Succeeded || ca.issued != 1 || len(e.h.acme) != 0 {
		t.Fatalf("issue: %s %s acme left=%v", j.State, j.Error, e.h.acme)
	}
	certs, _ := e.gw.ListCertificates(ctx)
	var cid string
	for _, c := range certs {
		if c.Name == "site" && c.Source == "acme" {
			cid = c.ID
		}
	}
	if cid == "" {
		t.Fatal("acme certificate not stored")
	}
	// Use it on an HTTPS route, deploy, then renew → automatic Safe Apply.
	l443, _ := e.gw.SaveListener(ctx, nil, &gateway.Listener{Name: "tls", Kind: gateway.KindHTTPS, Address: "0.0.0.0", Port: 8443, Enabled: true}, 0)
	ep, _ := e.gw.SaveEndpoint(ctx, nil, &gateway.Endpoint{Name: "app2", Host: "127.0.0.1", Port: 8082, Transport: "http"}, 0)
	if _, err := e.gw.SaveRoute(ctx, nil, &gateway.Route{Name: "tls", ListenerID: l443.ID, Protocol: gateway.ProtoHTTP, DestKind: gateway.DestEndpoint, DestID: ep.ID, CertificateID: cid, Enabled: true,
		Matches: []gateway.Match{{Field: "host", Operator: "exact", Value: "a.example.com"}}}, 0); err != nil {
		t.Fatal(err)
	}
	if j := e.submit(t, KindApply, ApplyPayload{}); j.State != jobs.Succeeded {
		t.Fatalf("deploy tls: %s %s", j.State, j.Error)
	}
	before, _ := e.gw.GetCertificate(ctx, cid)
	j = e.submit(t, KindACME, ACMEPayload{CertificateID: cid})
	if j.State != jobs.Succeeded || !strings.Contains(string(j.Result), "deploy_job") {
		t.Fatalf("renew: %s %s %s", j.State, j.Error, j.Result)
	}
	after, _ := e.gw.GetCertificate(ctx, cid)
	if after.Fingerprint == before.Fingerprint {
		t.Fatal("renewal did not replace the certificate")
	}
	runQueued(t, e) // the queued deployment
	g, _ := e.c.active(ctx)
	if g.Summary.CertFPs[cid] != after.Fingerprint {
		t.Fatal("renewed certificate not deployed")
	}
	st, _ := e.c.acmeState(ctx, cid)
	if st.Renewals != 1 || st.LastError != "" {
		t.Fatalf("acme state %+v", st)
	}
}

func TestACMERenewalScheduler(t *testing.T) {
	ctx := context.Background()
	e, _ := acmeEnv(t)
	if _, err := e.db.ExecContext(ctx, `INSERT INTO certificates(id,name,source,not_after,acme_json,created_at,updated_at) VALUES
		('01J9AAAAAAAAAAAAAAAAAAAAAA','soon','acme',?,'{}','x','x'),
		('01J9BBBBBBBBBBBBBBBBBBBBBB','later','acme',?,'{}','x','x'),
		('01J9CCCCCCCCCCCCCCCCCCCCCC','up','uploaded',?,'{}','x','x')`,
		store.FormatTime(time.Now().Add(10*24*time.Hour)), store.FormatTime(time.Now().Add(80*24*time.Hour)), store.FormatTime(time.Now().Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	n, err := e.c.ScheduleRenewals(ctx)
	if err != nil || n != 1 {
		t.Fatalf("queued %d %v", n, err)
	}
	if n, _ := e.c.ScheduleRenewals(ctx); n != 0 {
		t.Fatal("second run on the same day queued again")
	}
}
