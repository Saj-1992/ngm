package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/fwstore"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/observe"
)

// Must match deploy.KindFirewall / deploy.KindFirewallObservation (the API does
// not import the data-plane packages).
const (
	jobKindFirewall = "firewall.apply"
	obsKindFirewall = "firewall"
)

func (s *Server) registerFirewallRoutes() {
	s.handle("GET", "/api/v1/firewall", "firewall.read", s.getFirewall)
	s.handle("POST", "/api/v1/firewall/rules", "firewall.write", s.createFWRule)
	s.handle("POST", "/api/v1/firewall/rules/from-listeners", "firewall.write", s.fwFromListeners)
	s.handle("DELETE", "/api/v1/firewall/rules/{id}", "firewall.write", s.deleteFWRule)
	s.handle("POST", "/api/v1/firewall/apply", "firewall.write", s.applyFirewall)
	s.handle("POST", "/api/v1/firewall/confirm", "firewall.write", s.confirmFirewall)
}

func (s *Server) fw() *fwstore.Service { return &fwstore.Service{DB: s.d.DB, Audit: s.d.Audit} }

func mapFWError(err error) error {
	var ve *fwstore.ValidationError
	switch {
	case errors.As(err, &ve):
		return apierr.BadRequest(ve.Msg)
	case errors.Is(err, fwstore.ErrNotFound):
		return apierr.NotFound("rule")
	case errors.Is(err, fwstore.ErrStale):
		return apierr.PreconditionFailed()
	case errors.Is(err, fwstore.ErrConflict):
		return apierr.Conflict(err.Error())
	}
	return err
}

func (s *Server) getFirewall(w http.ResponseWriter, r *http.Request) error {
	rules, err := s.fw().List(r.Context())
	if err != nil {
		return err
	}
	var obs json.RawMessage
	at, err := observe.Latest(r.Context(), s.d.DB, obsKindFirewall, &obs)
	resp := map[string]any{"rules": rules, "observed": nil}
	if err == nil {
		resp["observed"] = obs
		resp["observed_at"] = at
	}
	return writeJSON(w, http.StatusOK, resp)
}

type fwRuleIn struct {
	Key    string `json:"key"`
	Action string `json:"action"`
	Proto  string `json:"proto"`
	Port   int    `json:"port"`
	Source string `json:"source"`
}

func (s *Server) createFWRule(w http.ResponseWriter, r *http.Request) error {
	var in fwRuleIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	rule, err := s.fw().Create(r.Context(), PrincipalFrom(r.Context()), fwstore.Rule{Key: in.Key, Action: in.Action, Proto: in.Proto, Port: in.Port, Source: in.Source})
	if err != nil {
		return mapFWError(err)
	}
	return writeEntity(w, http.StatusCreated, rule.Revision, rule)
}

func (s *Server) deleteFWRule(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	rev, err := ifMatchRevision(r)
	if err != nil {
		return err
	}
	if err := s.fw().Delete(r.Context(), PrincipalFrom(r.Context()), id, rev); err != nil {
		return mapFWError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// fwFromListeners creates allow rules for every enabled public listener port.
func (s *Server) fwFromListeners(w http.ResponseWriter, r *http.Request) error {
	if s.d.GW == nil {
		return apierr.Unavailable("gateway store unavailable")
	}
	ls, err := s.d.GW.ListListeners(r.Context())
	if err != nil {
		return err
	}
	existing, _ := s.fw().List(r.Context())
	have := map[string]bool{}
	for _, e := range existing {
		have[e.Key] = true
	}
	created := []string{}
	seen := map[int]bool{}
	for _, l := range ls {
		a, _ := netip.ParseAddr(l.Address)
		if !l.Enabled || a.IsLoopback() || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		key := "listener-" + strconv.Itoa(l.Port)
		if have[key] {
			continue
		}
		if _, err := s.fw().Create(r.Context(), PrincipalFrom(r.Context()), fwstore.Rule{Key: key, Action: "allow", Proto: "tcp", Port: l.Port, Source: "any"}); err != nil {
			return mapFWError(err)
		}
		created = append(created, key)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"created": created})
}

type fwApplyIn struct {
	Enable bool `json:"enable"`
}

func (s *Server) applyFirewall(w http.ResponseWriter, r *http.Request) error {
	var in fwApplyIn
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &in); err != nil {
			return err
		}
	}
	return s.submitJob(w, r, jobKindFirewall, []string{"firewall"}, in)
}

type fwConfirmIn struct {
	JobID string `json:"job_id"`
}

// confirmFirewall must be called by an operator who can still reach NGM after
// a risky change; without it the watchdog reverts.
func (s *Server) confirmFirewall(w http.ResponseWriter, r *http.Request) error {
	var in fwConfirmIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if !ids.Valid(in.JobID) {
		return apierr.BadRequest("invalid job_id")
	}
	if err := s.fw().Confirm(r.Context(), PrincipalFrom(r.Context()), in.JobID); err != nil {
		if strings.Contains(err.Error(), "not awaiting") {
			return apierr.Conflict(err.Error())
		}
		return mapFWError(err)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"confirmed": true})
}
