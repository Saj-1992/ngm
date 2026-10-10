package httpapi

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Must match deploy.KindDNSPreview / deploy.KindDNSApply / deploy.CloudflareTokenRef.
const (
	jobKindDNSPreview = "dns.cloudflare.preview"
	jobKindDNSApply   = "dns.cloudflare.apply"
)

var cfTokenRef = vault.Ref{Type: "cloudflare_token", Scope: "global", Name: "token"}

func (s *Server) registerCloudflareRoutes() {
	s.handle("GET", "/api/v1/integrations/cloudflare", "domains.read", s.getCloudflare)
	s.handle("PUT", "/api/v1/integrations/cloudflare", "secrets.write", s.putCloudflare)
	s.handle("DELETE", "/api/v1/integrations/cloudflare", "secrets.write", s.deleteCloudflare)
	s.handle("POST", "/api/v1/domains/{id}/cloudflare/preview", "domains.read", s.cloudflarePreview)
	s.handle("POST", "/api/v1/domains/{id}/cloudflare/apply", "domains.write", s.cloudflareApply)
}

func (s *Server) cloudflareConfigured(r *http.Request) bool {
	var n int
	_ = s.d.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM vault_secrets WHERE type=? AND scope=? AND name=?", cfTokenRef.Type, cfTokenRef.Scope, cfTokenRef.Name).Scan(&n)
	return n == 1
}

func (s *Server) getCloudflare(w http.ResponseWriter, r *http.Request) error {
	return writeJSON(w, http.StatusOK, map[string]any{"configured": s.cloudflareConfigured(r),
		"required_permissions": "Zone:Read and DNS:Edit, limited to the zones NGM should manage",
		"note":                 "NGM changes only records it created (comment managed-by:ngm) or records you explicitly adopt. DNS changes are not instant: caches honour TTLs."})
}

var cfTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`)

type cfTokenIn struct {
	Token string `json:"token"`
}

func (s *Server) putCloudflare(w http.ResponseWriter, r *http.Request) error {
	var in cfTokenIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	tok := strings.TrimSpace(in.Token)
	in.Token = ""
	if !cfTokenRe.MatchString(tok) {
		return apierr.BadRequest("this does not look like a Cloudflare API token")
	}
	if _, err := s.d.Vault.Put(r.Context(), cfTokenRef, []byte(tok)); err != nil {
		return err
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "integration.cloudflare_set", "integration", "cloudflare", nil))
	return writeJSON(w, http.StatusOK, map[string]any{"configured": true, "note": "the token is verified on the next DNS preview"})
}

func (s *Server) deleteCloudflare(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.d.DB.ExecContext(r.Context(), "DELETE FROM vault_secrets WHERE type=? AND scope=? AND name=?", cfTokenRef.Type, cfTokenRef.Scope, cfTokenRef.Name); err != nil {
		return err
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "integration.cloudflare_delete", "integration", "cloudflare", nil))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) cloudflarePreview(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if _, err := s.domains().Get(r.Context(), id); err != nil {
		return mapDomainError(err)
	}
	if !s.cloudflareConfigured(r) {
		return apierr.Conflict("no Cloudflare API token configured")
	}
	return s.submitJob(w, r, jobKindDNSPreview, []string{"dns-provider"}, map[string]string{"domain_id": id})
}

type cfApplyIn struct {
	PlanHash string   `json:"plan_hash"`
	Adopt    []string `json:"adopt"`
}

var cfIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// cloudflareApply applies exactly a previewed plan (its hash is the explicit
// confirmation); the job refuses if the zone or expectations changed since.
func (s *Server) cloudflareApply(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in cfApplyIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if len(in.PlanHash) != 32 {
		return apierr.BadRequest("plan_hash from a preview is required (explicit confirmation)")
	}
	for _, a := range in.Adopt {
		if !cfIDRe.MatchString(a) {
			return apierr.BadRequest("invalid record id in adopt")
		}
	}
	return s.submitJob(w, r, jobKindDNSApply, []string{"dns-provider"}, map[string]any{"domain_id": id, "plan_hash": in.PlanHash, "adopt": in.Adopt})
}
