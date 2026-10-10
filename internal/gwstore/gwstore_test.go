package gwstore

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func newSvc(t *testing.T) *Service {
	db := storetest.New(t)
	kr := vault.NewKeyring()
	k := make([]byte, 32)
	rand.Read(k)
	kr.Add(1, k)
	v := vault.New(db, kr)
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return New(db, v, audit.New(db))
}

func TestEndToEndModel(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)
	l, err := s.SaveListener(ctx, nil, &gateway.Listener{Name: "web", Kind: gateway.KindHTTP, Address: "0.0.0.0", Port: 80, Enabled: true}, 0)
	if err != nil || l.Family != "ipv4" || l.Revision != 1 {
		t.Fatalf("%+v %v", l, err)
	}
	e, err := s.SaveEndpoint(ctx, nil, &gateway.Endpoint{Name: "app", Host: "127.0.0.1", Port: 8080, Transport: "http"}, 0)
	if err != nil || e.ConnectTimeoutMS != 5000 {
		t.Fatalf("%+v %v", e, err)
	}
	p, err := s.SavePool(ctx, nil, &gateway.Pool{Name: "app-pool", Strategy: "round_robin", Members: []gateway.PoolMember{{EndpointID: e.ID}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.SaveRoute(ctx, nil, &gateway.Route{Name: "site", ListenerID: l.ID, Protocol: gateway.ProtoHTTP, DestKind: gateway.DestPool, DestID: p.ID, Enabled: true,
		Matches: []gateway.Match{{Field: "host", Operator: "exact", Value: "A.Example.com"}}}, 0)
	if err != nil || r.Matches[0].Value != "a.example.com" {
		t.Fatalf("%+v %v", r, err)
	}
	m, err := s.LoadModel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, issues := gateway.Build(m, gateway.CapsFromVersion("1.24.0", true, true, true), gateway.BuildOptions{APIListen: "127.0.0.1:9999"})
	if gateway.HasErrors(issues) {
		t.Fatalf("%+v", issues)
	}
	if res := gateway.Simulate(plan, gateway.SimInput{Address: "1.2.3.4", Port: 80, Host: "a.example.com"}); res.RouteName != "site" {
		t.Fatalf("%+v", res)
	}
	// Optimistic concurrency.
	r.Name = "site2"
	if _, err := s.SaveRoute(ctx, nil, r, r.Revision+1); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := s.SaveRoute(ctx, nil, r, r.Revision); err != nil {
		t.Fatal(err)
	}
	// In-use protection.
	if err := s.DeleteEndpoint(ctx, nil, e.ID, e.Revision); !errors.Is(err, ErrInUse) {
		t.Fatalf("endpoint in use: %v", err)
	}
	if err := s.DeletePool(ctx, nil, p.ID, p.Revision); !errors.Is(err, ErrInUse) {
		t.Fatalf("pool in use: %v", err)
	}
	if err := s.DeleteListener(ctx, nil, l.ID, l.Revision); !errors.Is(err, ErrInUse) {
		t.Fatalf("listener in use: %v", err)
	}
	// Duplicate bind.
	if _, err := s.SaveListener(ctx, nil, &gateway.Listener{Name: "web2", Kind: gateway.KindHTTP, Address: "0.0.0.0", Port: 80, Enabled: true}, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup bind: %v", err)
	}
}

func TestCertificates(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)
	c, err := s.GenerateSelfSigned(ctx, nil, "test", []string{"a.example.com", "*.example.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasKey || len(c.SANs) != 2 || c.Status != "valid" || len(c.Fingerprint) != 64 {
		t.Fatalf("%+v", c)
	}
	mat, err := s.CertMaterial(ctx, []string{c.ID})
	if err != nil || !strings.Contains(mat.Chains[c.ID], "BEGIN CERTIFICATE") || !strings.Contains(string(mat.Keys[mat.KeyFile[c.ID]]), "PRIVATE KEY") || mat.KeyFile[c.ID] == c.ID {
		t.Fatalf("material: %v", err)
	}
	// Key never stored in the certificates table.
	var pemS string
	s.db.QueryRowContext(ctx, "SELECT cert_pem FROM certificates WHERE id=?", c.ID).Scan(&pemS)
	if strings.Contains(pemS, "PRIVATE") {
		t.Fatal("private key in certificates table")
	}
	// Mismatched key rejected.
	cert2, _, _ := SelfSigned([]string{"b.example.com"}, time.Hour, time.Now())
	_, key3, _ := SelfSigned([]string{"c.example.com"}, time.Hour, time.Now())
	if _, err := s.ImportCertificate(ctx, nil, "bad", cert2, string(key3), "uploaded"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	// Expired rejected.
	old, oldKey, _ := SelfSigned([]string{"d.example.com"}, time.Hour, time.Now().Add(-48*time.Hour))
	if _, err := s.ImportCertificate(ctx, nil, "old", old, string(oldKey), "uploaded"); err == nil {
		t.Fatal("expired cert accepted")
	}
	if _, err := s.GenerateSelfSigned(ctx, nil, "x", []string{"bad host;"}, 30); err == nil {
		t.Fatal("bad host accepted")
	}
	if err := s.DeleteCertificate(ctx, nil, c.ID, c.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertMaterial(ctx, []string{c.ID}); err == nil {
		t.Fatal("material after delete")
	}
}

func TestCertificateKeyVersions(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)
	c, err := s.GenerateSelfSigned(ctx, nil, "site", []string{"a.example.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	m1, _ := s.CertMaterial(ctx, []string{c.ID})
	v1, k1 := m1.KeyFile[c.ID], string(m1.Keys[m1.KeyFile[c.ID]])
	// Renewal must cover the old names.
	narrow, nkey, _ := SelfSigned([]string{"b.example.com"}, 24*time.Hour, time.Now())
	if _, err := s.ReplaceCertificate(ctx, nil, c.ID, narrow, string(nkey)); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("narrow replacement: %v", err)
	}
	cp, kp, _ := SelfSigned([]string{"a.example.com", "www.a.example.com"}, 60*24*time.Hour, time.Now())
	c2, err := s.ReplaceCertificate(ctx, nil, c.ID, cp, string(kp))
	if err != nil || c2.Fingerprint == c.Fingerprint || c2.Revision != c.Revision+1 {
		t.Fatalf("replace: %v %+v", err, c2)
	}
	m2, _ := s.CertMaterial(ctx, []string{c.ID})
	v2 := m2.KeyFile[c.ID]
	if v2 == v1 || string(m2.Keys[v2]) == k1 {
		t.Fatal("renewal reused the key version")
	}
	// The old version stays available for generations built with it.
	old, err := s.KeyVersions(ctx, map[string]string{c.ID: v1})
	if err != nil || string(old[v1]) != k1 {
		t.Fatalf("old key version: %v", err)
	}
	// Pruning keeps referenced + current versions only.
	if n, err := s.PruneKeyVersions(ctx, map[string]bool{v1: true}); err != nil || n != 0 {
		t.Fatalf("prune kept: %d %v", n, err)
	}
	if n, err := s.PruneKeyVersions(ctx, map[string]bool{}); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, err := s.KeyVersions(ctx, map[string]string{c.ID: v1}); err == nil {
		t.Fatal("pruned version still present")
	}
	if _, err := s.KeyVersions(ctx, map[string]string{c.ID: v2}); err != nil {
		t.Fatalf("current version pruned: %v", err)
	}
	// Delete removes every version.
	if err := s.DeleteCertificate(ctx, nil, c.ID, c2.Revision); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM vault_secrets WHERE type='tls_key'").Scan(&n)
	if n != 0 {
		t.Fatalf("%d key versions left after delete", n)
	}
}
