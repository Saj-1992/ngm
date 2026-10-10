package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/auth"
	"github.com/ngm-gateway/ngm/internal/deployspec"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/gwstore"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/monitor"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

func (s *Server) registerGatewayRoutes() {
	if s.d.GW == nil {
		return
	}
	s.handle("GET", "/api/v1/listeners", "gateway.read", s.listListeners)
	s.handle("POST", "/api/v1/listeners", "gateway.write", s.createListener)
	s.handle("GET", "/api/v1/listeners/{id}", "gateway.read", s.getListener)
	s.handle("PUT", "/api/v1/listeners/{id}", "gateway.write", s.putListener)
	s.handle("DELETE", "/api/v1/listeners/{id}", "gateway.write", s.deleteListener)

	s.handle("GET", "/api/v1/backends", "gateway.read", s.listEndpoints)
	s.handle("POST", "/api/v1/backends", "gateway.write", s.createEndpoint)
	s.handle("GET", "/api/v1/backends/{id}", "gateway.read", s.getEndpoint)
	s.handle("PUT", "/api/v1/backends/{id}", "gateway.write", s.putEndpoint)
	s.handle("DELETE", "/api/v1/backends/{id}", "gateway.write", s.deleteEndpoint)

	s.handle("GET", "/api/v1/pools", "gateway.read", s.listPools)
	s.handle("POST", "/api/v1/pools", "gateway.write", s.createPool)
	s.handle("GET", "/api/v1/pools/{id}", "gateway.read", s.getPool)
	s.handle("PUT", "/api/v1/pools/{id}", "gateway.write", s.putPool)
	s.handle("DELETE", "/api/v1/pools/{id}", "gateway.write", s.deletePool)

	s.handle("GET", "/api/v1/routes", "gateway.read", s.listRoutes)
	s.handle("POST", "/api/v1/routes", "gateway.write", s.createRoute)
	s.handle("GET", "/api/v1/routes/{id}", "gateway.read", s.getRoute)
	s.handle("PUT", "/api/v1/routes/{id}", "gateway.write", s.putRoute)
	s.handle("DELETE", "/api/v1/routes/{id}", "gateway.write", s.deleteRoute)

	s.handle("GET", "/api/v1/certificates", "certificates.read", s.listCerts)
	s.handle("POST", "/api/v1/certificates", "certificates.write", s.importCert)
	s.handle("POST", "/api/v1/certificates/self-signed", "certificates.write", s.selfSignedCert)
	s.handle("GET", "/api/v1/certificates/{id}", "certificates.read", s.getCert)
	s.handle("GET", "/api/v1/certificates/{id}/fullchain", "certificates.read", s.downloadFullchain)
	s.handle("GET", "/api/v1/certificates/{id}/privkey", "certificates.write", s.downloadPrivkey)
	s.handle("DELETE", "/api/v1/certificates/{id}", "certificates.write", s.deleteCert)
	s.handle("POST", "/api/v1/certificates/acme", "certificates.write", s.acmeCertificate)
	s.handle("POST", "/api/v1/certificates/{id}/renew", "certificates.write", s.renewCertificate)

	s.handle("GET", "/api/v1/monitoring/backends", "monitoring.read", s.backendHealth)
	s.handle("GET", "/api/v1/gateway/validation", "gateway.read", s.gatewayValidation)
	s.handle("POST", "/api/v1/gateway/simulate", "gateway.read", s.gatewaySimulate)

	s.handle("GET", "/api/v1/deployments", "gateway.read", s.listDeployments)
	s.handle("GET", "/api/v1/deployments/active", "gateway.read", s.activeDeployment)
	s.handle("POST", "/api/v1/deployments", "deploy.apply", s.createDeployment)
	s.handle("POST", "/api/v1/deployments/rollback", "deploy.apply", s.rollbackDeployment)
	s.handle("GET", "/api/v1/gateway/fallback", "gateway.read", s.getFallback)
	s.handle("PUT", "/api/v1/gateway/fallback", "gateway.write", s.putFallback)
}

// mapGWError converts gateway store errors.
func mapGWError(err error) error {
	var ve *gwstore.ValidationError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ve):
		return apierr.BadRequest(ve.Msg)
	case errors.Is(err, gwstore.ErrNotFound):
		return apierr.NotFound("resource")
	case errors.Is(err, gwstore.ErrStale):
		return apierr.PreconditionFailed()
	case errors.Is(err, gwstore.ErrInUse), errors.Is(err, gwstore.ErrConflict):
		return apierr.Conflict(err.Error())
	}
	return err
}

func writeEntity(w http.ResponseWriter, status int, rev int64, v any) error {
	w.Header().Set("ETag", ETag(rev))
	return writeJSON(w, status, v)
}

// ─── listeners ─────────────────────────────────────────────────────────────

func (s *Server) listListeners(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.GW.ListListeners(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

func (s *Server) getListener(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	l, err := s.d.GW.GetListener(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, l.Revision, l)
}

type listenerIn struct {
	Name    string                  `json:"name"`
	Kind    string                  `json:"kind"`
	Address string                  `json:"address"`
	Port    int                     `json:"port"`
	Enabled *bool                   `json:"enabled"`
	Options gateway.ListenerOptions `json:"options"`
}

func (in listenerIn) model(id string) *gateway.Listener {
	en := true
	if in.Enabled != nil {
		en = *in.Enabled
	}
	return &gateway.Listener{ID: id, Name: in.Name, Kind: in.Kind, Address: in.Address, Port: in.Port, Enabled: en, Options: in.Options}
}

func (s *Server) createListener(w http.ResponseWriter, r *http.Request) error {
	var in listenerIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	l, err := s.d.GW.SaveListener(r.Context(), PrincipalFrom(r.Context()), in.model(""), 0)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, l.Revision, l)
}

func (s *Server) putListener(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in listenerIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	l, err := s.d.GW.SaveListener(r.Context(), PrincipalFrom(r.Context()), in.model(id), rev)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, l.Revision, l)
}

func (s *Server) deleteListener(w http.ResponseWriter, r *http.Request) error {
	return s.deleteWith(w, r, s.d.GW.DeleteListener)
}

func (s *Server) deleteWith(w http.ResponseWriter, r *http.Request, fn func(context.Context, *Principal, string, int64) error) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	if err := fn(r.Context(), PrincipalFrom(r.Context()), id, rev); err != nil {
		return mapGWError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── endpoints ─────────────────────────────────────────────────────────────

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.GW.ListEndpoints(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	e, err := s.d.GW.GetEndpoint(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, e.Revision, e)
}

type endpointIn struct {
	Name             string               `json:"name"`
	Host             string               `json:"host"`
	Port             int                  `json:"port"`
	Transport        string               `json:"transport"`
	TLSVerify        *bool                `json:"tls_verify"`
	TLSServerName    string               `json:"tls_server_name"`
	Weight           int                  `json:"weight"`
	Priority         int                  `json:"priority"`
	ConnectTimeoutMS int                  `json:"connect_timeout_ms"`
	ReadTimeoutMS    int                  `json:"read_timeout_ms"`
	WriteTimeoutMS   int                  `json:"write_timeout_ms"`
	Disabled         bool                 `json:"disabled"`
	Health           gateway.HealthPolicy `json:"health"`
}

func (in endpointIn) model(id string) *gateway.Endpoint {
	v := true
	if in.TLSVerify != nil {
		v = *in.TLSVerify
	}
	return &gateway.Endpoint{ID: id, Name: in.Name, Host: in.Host, Port: in.Port, Transport: in.Transport, TLSVerify: v, TLSServerName: in.TLSServerName,
		Weight: in.Weight, Priority: in.Priority, ConnectTimeoutMS: in.ConnectTimeoutMS, ReadTimeoutMS: in.ReadTimeoutMS, WriteTimeoutMS: in.WriteTimeoutMS, Disabled: in.Disabled, Health: in.Health}
}

func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request) error {
	var in endpointIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	e, err := s.d.GW.SaveEndpoint(r.Context(), PrincipalFrom(r.Context()), in.model(""), 0)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, e.Revision, e)
}

func (s *Server) putEndpoint(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in endpointIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	e, err := s.d.GW.SaveEndpoint(r.Context(), PrincipalFrom(r.Context()), in.model(id), rev)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, e.Revision, e)
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) error {
	return s.deleteWith(w, r, s.d.GW.DeleteEndpoint)
}

// ─── pools ─────────────────────────────────────────────────────────────────

func (s *Server) listPools(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.GW.ListPools(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

func (s *Server) getPool(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	p, err := s.d.GW.GetPool(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, p.Revision, p)
}

type poolIn struct {
	Name     string               `json:"name"`
	Strategy string               `json:"strategy"`
	Members  []gateway.PoolMember `json:"members"`
}

func (s *Server) createPool(w http.ResponseWriter, r *http.Request) error {
	var in poolIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	p, err := s.d.GW.SavePool(r.Context(), PrincipalFrom(r.Context()), &gateway.Pool{Name: in.Name, Strategy: in.Strategy, Members: in.Members}, 0)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, p.Revision, p)
}

func (s *Server) putPool(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in poolIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	p, err := s.d.GW.SavePool(r.Context(), PrincipalFrom(r.Context()), &gateway.Pool{ID: id, Name: in.Name, Strategy: in.Strategy, Members: in.Members}, rev)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, p.Revision, p)
}

func (s *Server) deletePool(w http.ResponseWriter, r *http.Request) error {
	return s.deleteWith(w, r, s.d.GW.DeletePool)
}

// ─── routes ────────────────────────────────────────────────────────────────

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.GW.ListRoutes(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

func (s *Server) getRoute(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rt, err := s.d.GW.GetRoute(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, rt.Revision, rt)
}

type routeIn struct {
	Name          string               `json:"name"`
	ListenerID    string               `json:"listener_id"`
	Protocol      string               `json:"protocol"`
	Priority      int                  `json:"priority"`
	DestKind      string               `json:"destination_kind"`
	DestID        string               `json:"destination_id"`
	Fallback      bool                 `json:"is_fallback"`
	CertificateID string               `json:"certificate_id"`
	Matches       []gateway.Match      `json:"matches"`
	Options       gateway.RouteOptions `json:"options"`
	Enabled       *bool                `json:"enabled"`
}

func (in routeIn) model(id string) *gateway.Route {
	en := true
	if in.Enabled != nil {
		en = *in.Enabled
	}
	return &gateway.Route{ID: id, Name: in.Name, ListenerID: in.ListenerID, Protocol: in.Protocol, Priority: in.Priority, DestKind: in.DestKind, DestID: in.DestID,
		Fallback: in.Fallback, CertificateID: in.CertificateID, Matches: in.Matches, Options: in.Options, Enabled: en}
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) error {
	var in routeIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	rt, err := s.d.GW.SaveRoute(r.Context(), PrincipalFrom(r.Context()), in.model(""), 0)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, rt.Revision, rt)
}

func (s *Server) putRoute(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in routeIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	rt, err := s.d.GW.SaveRoute(r.Context(), PrincipalFrom(r.Context()), in.model(id), rev)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, rt.Revision, rt)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) error {
	return s.deleteWith(w, r, s.d.GW.DeleteRoute)
}

// ─── certificates ──────────────────────────────────────────────────────────

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.GW.ListCertificates(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

func (s *Server) getCert(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	c, err := s.d.GW.GetCertificate(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusOK, c.Revision, c)
}

// downloadFullchain serves the certificate + chain as fullchain.pem (public
// material; certificates.read).
func (s *Server) downloadFullchain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	c, err := s.d.GW.GetCertificate(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	mat, err := s.d.GW.CertMaterial(r.Context(), []string{id})
	if err != nil {
		return err
	}
	defer mat.Clear()
	chain := mat.Chains[id]
	if chain == "" {
		return apierr.NotFound("certificate material")
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "certificate.download_fullchain", "certificate", id, map[string]any{"name": c.Name}))
	servePEM(w, "fullchain.pem", []byte(chain))
	return nil
}

// downloadPrivkey serves the private key as privkey.pem. This is the only
// path by which a key leaves the vault: it requires an interactive user (never
// an API token) with a fresh second factor, and every download is audited.
func (s *Server) downloadPrivkey(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	p := PrincipalFrom(r.Context())
	if p.Kind != "user" {
		return apierr.New(http.StatusForbidden, "user_required", "private keys can only be downloaded by an interactive user, not an API token")
	}
	if !p.StepUpFresh(time.Now()) {
		return apierr.New(http.StatusForbidden, "step_up_required", "recent two-factor verification required").
			WithDetails(map[string]any{"window_seconds": int(auth.StepUpWindow.Seconds())})
	}
	c, err := s.d.GW.GetCertificate(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	mat, err := s.d.GW.CertMaterial(r.Context(), []string{id})
	if err != nil {
		return err
	}
	defer mat.Clear()
	kf := mat.KeyFile[id]
	key := mat.Keys[kf]
	if len(key) == 0 {
		return apierr.NotFound("private key")
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "certificate.download_privkey", "certificate", id, map[string]any{"name": c.Name}))
	servePEM(w, "privkey.pem", key)
	return nil
}

// servePEM writes PEM bytes as a download, never cached.
func servePEM(w http.ResponseWriter, filename string, pem []byte) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem)
}

type certIn struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (s *Server) importCert(w http.ResponseWriter, r *http.Request) error {
	var in certIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	c, err := s.d.GW.ImportCertificate(r.Context(), PrincipalFrom(r.Context()), in.Name, in.CertPEM, in.KeyPEM, "uploaded")
	in.KeyPEM = ""
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, c.Revision, c)
}

type selfSignedIn struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Days  int      `json:"days"`
}

func (s *Server) selfSignedCert(w http.ResponseWriter, r *http.Request) error {
	var in selfSignedIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	c, err := s.d.GW.GenerateSelfSigned(r.Context(), PrincipalFrom(r.Context()), in.Name, in.Hosts, in.Days)
	if err != nil {
		return mapGWError(err)
	}
	return writeEntity(w, http.StatusCreated, c.Revision, c)
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) error {
	return s.deleteWith(w, r, s.d.GW.DeleteCertificate)
}

func (s *Server) backendHealth(w http.ResponseWriter, r *http.Request) error {
	eps, err := s.d.GW.ListEndpoints(r.Context())
	if err != nil {
		return err
	}
	hs, err := monitor.Latest(r.Context(), s.d.DB, eps)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": hs})
}

// ─── validation, preview, simulation ───────────────────────────────────────

func (s *Server) caps(ctx context.Context) (gateway.Caps, bool, time.Time) {
	var n observe.Nginx
	at, err := observe.Latest(ctx, s.d.DB, observe.KindNginx, &n)
	if err != nil || !n.Installed {
		return gateway.Caps{}, false, at
	}
	return gateway.CapsFromVersion(n.Version, n.StreamModule, n.SSLPreread, n.HTTPV2), true, at
}

func (s *Server) buildDesired(ctx context.Context) (*gateway.Model, *gateway.Plan, []gateway.Issue, gateway.Caps, error) {
	m, err := s.d.GW.LoadModel(ctx)
	if err != nil {
		return nil, nil, nil, gateway.Caps{}, err
	}
	caps, known, _ := s.caps(ctx)
	reserved := sshPorts(ctx, s.d.DB)
	p, issues := gateway.Build(m, caps, gateway.BuildOptions{ReservedPorts: reserved, APIListen: s.d.Config.API.Listen, ManagementHost: gateway.OriginHost(s.d.Config.API.PublicOrigin), ManagementPath: s.d.Config.API.PublicPath})
	if !known {
		issues = append(issues, gateway.Issue{Severity: "warning", Code: "nginx_unknown", Message: "Nginx capabilities are unknown (no runtime observation); stream features are reported as unavailable"})
	}
	return m, p, issues, caps, nil
}

func sshPorts(ctx context.Context, db *store.DB) []int {
	var raw string
	if err := db.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='install.preflight'").Scan(&raw); err != nil {
		return []int{22}
	}
	var pre struct {
		SSHPorts []string `json:"ssh_ports"`
	}
	_ = json.Unmarshal([]byte(raw), &pre)
	var out []int
	for _, p := range pre.SSHPorts {
		var n int
		for _, c := range p {
			if c < '0' || c > '9' {
				n = -1
				break
			}
			n = n*10 + int(c-'0')
		}
		if n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{22}
	}
	return out
}

func (s *Server) gatewayValidation(w http.ResponseWriter, r *http.Request) error {
	m, p, issues, caps, err := s.buildDesired(r.Context())
	if err != nil {
		return err
	}
	issues = append(issues, s.registryWarnings(r.Context(), m)...)
	resp := map[string]any{"valid": !gateway.HasErrors(issues), "issues": nonNilIssues(issues), "capabilities": caps}
	if !gateway.HasErrors(issues) && r.URL.Query().Get("preview") == "1" {
		pem := map[string]string{}
		for _, id := range gateway.UsedCertIDs(p) {
			pem[id] = "# certificate " + id + " (PEM omitted from preview)\n"
		}
		def := ""
		if !caps.RejectHandshake {
			def = "preview-default"
			pem[def] = "# default certificate\n"
		}
		out, err := gateway.Compile(p, issues, caps, gateway.CompileInput{GenID: "preview", ProbeToken: "redacted", CertPEM: pem, DefaultCertID: def})
		if err == nil {
			files := map[string]string{}
			for n, b := range out.Files {
				if strings.HasPrefix(n, "certs/") {
					continue
				}
				files[n] = string(b)
			}
			resp["preview"] = map[string]any{"files": files, "listens": out.Listens}
		} else {
			resp["preview_error"] = err.Error()
		}
	}
	return writeJSON(w, http.StatusOK, resp)
}

func nonNilIssues(is []gateway.Issue) []gateway.Issue {
	if is == nil {
		return []gateway.Issue{}
	}
	return is
}

type simIn struct {
	gateway.SimInput
	Model string `json:"model"` // desired (default) | active
}

func (s *Server) gatewaySimulate(w http.ResponseWriter, r *http.Request) error {
	var in simIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if len(in.SNI) > 253 || len(in.Host) > 253 || len(in.Path) > 2048 || len(in.ALPN) > 10 {
		return apierr.BadRequest("simulation input too long")
	}
	var p *gateway.Plan
	var issues []gateway.Issue
	switch in.Model {
	case "", "desired":
		var err error
		_, p, issues, _, err = s.buildDesired(r.Context())
		if err != nil {
			return err
		}
	case "active":
		var mj sql.NullString
		err := s.d.DB.QueryRowContext(r.Context(), `SELECT d.model_json FROM active_state a JOIN config_generations g ON g.id=a.generation_id
			JOIN desired_revisions d ON d.id=g.desired_revision_id WHERE a.id=1`).Scan(&mj)
		if err != nil || !mj.Valid {
			return apierr.New(http.StatusConflict, "no_active_generation", "nothing has been deployed yet")
		}
		var m gateway.Model
		if err := json.Unmarshal([]byte(mj.String), &m); err != nil {
			return err
		}
		caps, _, _ := s.caps(r.Context())
		p, issues = gateway.Build(&m, caps, gateway.BuildOptions{APIListen: s.d.Config.API.Listen, ManagementHost: gateway.OriginHost(s.d.Config.API.PublicOrigin), ManagementPath: s.d.Config.API.PublicPath})
	default:
		return apierr.BadRequest("model must be desired or active")
	}
	in.SimInput.FallbackSite = gwstore.GetFallback(r.Context(), s.d.DB).Enabled()
	res := gateway.Simulate(p, in.SimInput)
	return writeJSON(w, http.StatusOK, map[string]any{"result": res, "model_valid": !gateway.HasErrors(issues)})
}

// ─── deployments ───────────────────────────────────────────────────────────

type generationView struct {
	ID          string          `json:"id"`
	Number      int64           `json:"number"`
	Status      string          `json:"status"`
	JobID       string          `json:"job_id,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	ActivatedAt *time.Time      `json:"activated_at,omitempty"`
	Summary     json.RawMessage `json:"summary"`
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.d.DB.QueryContext(r.Context(), `SELECT id,number,status,COALESCE(job_id,''),created_at,activated_at,summary_json FROM config_generations ORDER BY number DESC LIMIT 50`)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []generationView{}
	for rows.Next() {
		var g generationView
		var c string
		var a sql.NullString
		var sum string
		if err := rows.Scan(&g.ID, &g.Number, &g.Status, &g.JobID, &c, &a, &sum); err != nil {
			return err
		}
		g.CreatedAt, _ = store.ParseTime(c)
		if a.Valid {
			t, _ := store.ParseTime(a.String)
			g.ActivatedAt = &t
		}
		g.Summary = json.RawMessage(sum)
		out = append(out, g)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) activeDeployment(w http.ResponseWriter, r *http.Request) error {
	var gid sql.NullString
	var upd string
	_ = s.d.DB.QueryRowContext(r.Context(), "SELECT generation_id, updated_at FROM active_state WHERE id=1").Scan(&gid, &upd)
	resp := map[string]any{"generation_id": nil}
	if gid.Valid {
		resp["generation_id"] = gid.String
		resp["updated_at"] = upd
	}
	return writeJSON(w, http.StatusOK, resp)
}

func (s *Server) submitDeployJob(w http.ResponseWriter, r *http.Request, kind string, payload any) error {
	return s.submitJob(w, r, kind, []string{"gateway-config", "certificate"}, payload)
}

// submitJob queues a durable job (202 + Location), honouring Idempotency-Key.
func (s *Server) submitJob(w http.ResponseWriter, r *http.Request, kind string, lockSet []string, payload any) error {
	key := r.Header.Get("Idempotency-Key")
	if key != "" && (len(key) < 8 || len(key) > 128) {
		return apierr.BadRequest("Idempotency-Key must be 8–128 characters")
	}
	p := PrincipalFrom(r.Context())
	j, created, err := s.d.Jobs.Submit(r.Context(), jobs.SubmitRequest{Kind: kind, ActorID: p.UserID, RequestID: RequestID(r.Context()), IdempotencyKey: key,
		LockSet: lockSet, Payload: payload})
	if err != nil {
		return err
	}
	if created && s.d.Broker != nil {
		_, _ = s.d.Broker.Publish(r.Context(), "job.created", "global", map[string]any{"id": j.ID, "kind": j.Kind})
	}
	w.Header().Set("Location", "/api/v1/jobs/"+j.ID)
	return writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "status": j.State, "replayed": !created})
}

func (s *Server) createDeployment(w http.ResponseWriter, r *http.Request) error {
	var in deployspec.ApplyPayload
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &in); err != nil {
			return err
		}
	}
	// Fail fast on invalid models (the coordinator re-validates under lock).
	_, _, issues, _, err := s.buildDesired(r.Context())
	if err != nil {
		return err
	}
	if gateway.HasErrors(issues) {
		return apierr.New(http.StatusUnprocessableEntity, "validation_failed", "the desired configuration has errors").WithDetails(map[string]any{"issues": issues})
	}
	return s.submitDeployJob(w, r, deployspec.KindApply, in)
}

func (s *Server) rollbackDeployment(w http.ResponseWriter, r *http.Request) error {
	var in deployspec.RollbackPayload
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	var n int
	_ = s.d.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM config_generations WHERE id=? AND status='superseded'", in.GenerationID).Scan(&n)
	if n == 0 {
		return apierr.New(http.StatusConflict, "not_known_good", "only a previously active (superseded) generation can be restored")
	}
	return s.submitDeployJob(w, r, deployspec.KindRollback, in)
}

// registryWarnings flags route host/SNI names outside the Domain Registry
// (warning only: the registry is the source of truth for DNS/ACME, and
// unregistered names get no DNS evidence or certificate automation).
func (s *Server) registryWarnings(ctx context.Context, m *gateway.Model) []gateway.Issue {
	if m == nil {
		return nil
	}
	reg := s.domains()
	seen := map[string]bool{}
	var out []gateway.Issue
	for _, rt := range m.Routes {
		for _, mt := range rt.Matches {
			if (mt.Field != "host" && mt.Field != "sni") || seen[mt.Value] {
				continue
			}
			seen[mt.Value] = true
			if ok, err := reg.Registered(ctx, mt.Value); err == nil && !ok {
				out = append(out, gateway.Issue{Severity: "warning", Code: "domain_not_registered", Ref: rt.ID,
					Message: "route " + rt.Name + " uses " + mt.Value + ", which is not in the Domain Registry (no DNS evidence or certificate automation for it)"})
			}
		}
	}
	return out
}

// Must match deploy.KindACME.
const jobKindACME = "certificate.acme"

type acmeIn struct {
	Name        string   `json:"name"`
	Identifiers []string `json:"identifiers"`
	Directory   string   `json:"directory"`
	Email       string   `json:"email"`
	Challenge   string   `json:"challenge,omitempty"` // http-01 (default) | dns-01
}

var acmeDirectories = map[string]bool{"letsencrypt-staging": true, "letsencrypt": true}

// acmeCertificate queues an ACME (HTTP-01) order; the job validates names,
// CAA evidence and port-80 reachability before contacting the CA.
func (s *Server) acmeCertificate(w http.ResponseWriter, r *http.Request) error {
	var in acmeIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if !acmeDirectories[in.Directory] {
		return apierr.BadRequest("directory must be letsencrypt-staging or letsencrypt")
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 64 {
		return apierr.BadRequest("name must be 1–64 characters")
	}
	if len(in.Identifiers) == 0 || len(in.Identifiers) > 50 {
		return apierr.BadRequest("1–50 names required")
	}
	if in.Email != "" && (len(in.Email) > 254 || !strings.Contains(in.Email, "@") || strings.ContainsAny(in.Email, " <>\"\r\n")) {
		return apierr.BadRequest("invalid contact email")
	}
	if in.Challenge == "" {
		in.Challenge = "http-01"
	}
	if in.Challenge != "http-01" && in.Challenge != "dns-01" {
		return apierr.BadRequest("challenge must be http-01 or dns-01")
	}
	for _, n := range in.Identifiers {
		if strings.HasPrefix(n, "*.") && in.Challenge != "dns-01" {
			return apierr.BadRequest("wildcard names require the dns-01 challenge (Cloudflare)")
		}
	}
	return s.submitJob(w, r, jobKindACME, []string{"certificate"}, in)
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	c, err := s.d.GW.GetCertificate(r.Context(), id)
	if err != nil {
		return mapGWError(err)
	}
	if c.Source != "acme" {
		return apierr.Conflict("only ACME certificates can be renewed automatically; import a new certificate instead")
	}
	return s.submitJob(w, r, jobKindACME, []string{"certificate"}, map[string]string{"certificate_id": id, "trigger": "manual"})
}

// getFallback returns the fallback website setting (ADR-036).
func (s *Server) getFallback(w http.ResponseWriter, r *http.Request) error {
	f := gwstore.GetFallback(r.Context(), s.d.DB)
	return writeJSON(w, http.StatusOK, map[string]any{"fallback": f, "enabled": f.Enabled(),
		"note": "applies with the next deployment; unknown hosts, IP-only access and unknown or missing SNI then see this website"})
}

func (s *Server) putFallback(w http.ResponseWriter, r *http.Request) error {
	var in gwstore.Fallback
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if err := s.d.GW.SetFallback(r.Context(), PrincipalFrom(r.Context()), in); err != nil {
		if errors.Is(err, gwstore.ErrFallbackInvalid) {
			return apierr.BadRequest(err.Error())
		}
		return err
	}
	return s.getFallback(w, r)
}
