package httpapi

import (
	"errors"
	"net/http"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/domains"
	"github.com/ngm-gateway/ngm/internal/ids"
)

func (s *Server) registerDomainRoutes() {
	s.handle("GET", "/api/v1/domains", "domains.read", s.listDomains)
	s.handle("POST", "/api/v1/domains", "domains.write", s.createDomain)
	s.handle("GET", "/api/v1/domains/{id}", "domains.read", s.getDomain)
	s.handle("PATCH", "/api/v1/domains/{id}", "domains.write", s.patchDomain)
	s.handle("DELETE", "/api/v1/domains/{id}", "domains.write", s.deleteDomain)
	s.handle("POST", "/api/v1/domains/{id}/expectations", "domains.write", s.addExpectation)
	s.handle("DELETE", "/api/v1/domains/{id}/expectations/{eid}", "domains.write", s.deleteExpectation)
	s.handle("POST", "/api/v1/domains/{id}/check", "domains.read", s.checkDomain)
	s.handle("POST", "/api/v1/domains/{id}/subdomains", "domains.write", s.createSubdomain)
}

func (s *Server) domains() *domains.Service {
	return &domains.Service{DB: s.d.DB, Audit: s.d.Audit, PublicOrigin: s.d.Config.API.PublicOrigin}
}

func mapDomainError(err error) error {
	var ve *domains.ValidationError
	switch {
	case errors.As(err, &ve):
		return apierr.BadRequest(ve.Msg)
	case errors.Is(err, domains.ErrNotFound):
		return apierr.NotFound("domain")
	case errors.Is(err, domains.ErrStale):
		return apierr.PreconditionFailed()
	case errors.Is(err, domains.ErrConflict), errors.Is(err, domains.ErrInUse):
		return apierr.Conflict(err.Error())
	}
	return err
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) error {
	ds, err := s.domains().List(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": ds})
}

type domainIn struct {
	FQDN    string `json:"fqdn"`
	Purpose string `json:"purpose"`
	Notes   string `json:"notes"`
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) error {
	var in domainIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	d, err := s.domains().Create(r.Context(), PrincipalFrom(r.Context()), in.FQDN, in.Purpose, in.Notes)
	if err != nil {
		return mapDomainError(err)
	}
	return writeEntity(w, http.StatusCreated, d.Revision, d)
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	d, err := s.domains().Get(r.Context(), id)
	if err != nil {
		return mapDomainError(err)
	}
	usage, err := s.domains().Usage(r.Context(), d.FQDN)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(d.Revision))
	return writeJSON(w, http.StatusOK, map[string]any{"domain": d, "usage": usage})
}

func (s *Server) patchDomain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	var in domainIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	d, err := s.domains().Update(r.Context(), PrincipalFrom(r.Context()), id, rev, in.Purpose, in.Notes)
	if err != nil {
		return mapDomainError(err)
	}
	return writeEntity(w, http.StatusOK, d.Revision, d)
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	if err := s.domains().Delete(r.Context(), PrincipalFrom(r.Context()), id, rev); err != nil {
		return mapDomainError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) addExpectation(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in domains.Expect
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	d, err := s.domains().AddExpectation(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		return mapDomainError(err)
	}
	return writeJSON(w, http.StatusCreated, d)
}

func (s *Server) deleteExpectation(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	eid := r.PathValue("eid")
	if !ids.Valid(eid) {
		return apierr.BadRequest("invalid expectation id")
	}
	if err := s.domains().DeleteExpectation(r.Context(), PrincipalFrom(r.Context()), id, eid); err != nil {
		return mapDomainError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// checkDomain records a check request; ngm-monitor performs the lookups.
func (s *Server) checkDomain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.domains().RequestCheck(r.Context(), id); err != nil {
		return mapDomainError(err)
	}
	return writeJSON(w, http.StatusAccepted, map[string]any{"requested": true, "note": "ngm-monitor checks within about 10 seconds"})
}

// subdomainIn is the request to create a subdomain under {id}.
type subdomainIn struct {
	Label   string `json:"label"` // empty or "auto" → generated
	Type    string `json:"type"`
	Value   string `json:"value"`
	TTL     *int   `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	// ExistingNames are names the caller saw at the provider (from a discovery
	// job), used to avoid collisions. They are advisory: the confirmed
	// Cloudflare preview/apply remains the authority and never overwrites a
	// record NGM does not manage unless the operator explicitly adopts it.
	ExistingNames []string `json:"existing_names,omitempty"`
}

// createSubdomain registers a subdomain and its expected DNS record. It changes
// nothing at the provider: use the Cloudflare preview/apply to publish it.
func (s *Server) createSubdomain(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in subdomainIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if len(in.ExistingNames) > 5000 {
		return apierr.BadRequest("too many existing names")
	}
	d, err := s.domains().CreateSubdomain(r.Context(), PrincipalFrom(r.Context()), domains.SubdomainInput{
		ParentID: id, Label: in.Label, Type: in.Type, Value: in.Value, TTL: in.TTL, Proxied: in.Proxied, Purpose: in.Purpose, Taken: in.ExistingNames})
	if err != nil {
		return mapDomainError(err)
	}
	return writeJSON(w, http.StatusCreated, d)
}
