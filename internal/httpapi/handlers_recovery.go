package httpapi

import (
	"errors"
	"net/http"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/recovery"
)

func (s *Server) registerRecoveryRoutes() {
	s.handle("GET", "/api/v1/recovery/incidents", "recovery.read", s.listIncidents)
	s.handle("GET", "/api/v1/recovery/incidents/{id}", "recovery.read", s.getIncident)
	s.handle("POST", "/api/v1/recovery/incidents/{id}/resolve", "recovery.write", s.resolveIncident)
	s.handle("POST", "/api/v1/recovery/incidents/{id}/reconcile", "recovery.write", s.reconcileIncident)
	s.handle("GET", "/api/v1/recovery/drift", "recovery.read", s.getDrift)
	s.handle("POST", "/api/v1/recovery/reconcile", "recovery.write", s.reconcileDrift)
}

func (s *Server) recovery() *recovery.Service { return &recovery.Service{DB: s.d.DB, Audit: s.d.Audit} }

func mapRecoveryError(err error) error {
	switch {
	case errors.Is(err, recovery.ErrNotFound):
		return apierr.NotFound("incident")
	case errors.Is(err, recovery.ErrResolved):
		return apierr.Conflict(err.Error())
	case errors.Is(err, recovery.ErrOutcome), errors.Is(err, recovery.ErrNote):
		return apierr.BadRequest(err.Error())
	case errors.Is(err, recovery.ErrDrift):
		return apierr.New(http.StatusConflict, "active_drift", err.Error())
	case errors.Is(err, recovery.ErrNoEvidence):
		return apierr.New(http.StatusConflict, "no_evidence", err.Error())
	}
	return err
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) error {
	items, err := s.recovery().List(r.Context(), r.URL.Query().Get("status") == "open")
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	in, err := s.recovery().Get(r.Context(), id)
	if err != nil {
		return mapRecoveryError(err)
	}
	resp := map[string]any{"incident": in}
	if d, err := recovery.CurrentDrift(r.Context(), s.d.DB); err == nil {
		resp["drift"] = d // null when the record matches the data plane
	} else {
		resp["drift_error"] = err.Error()
	}
	if in.JobID != "" {
		if j, err := s.d.Jobs.Get(r.Context(), in.JobID); err == nil {
			resp["job"] = j
		}
		if st, err := s.d.Jobs.Steps(r.Context(), in.JobID); err == nil {
			resp["steps"] = st
		}
	}
	return writeJSON(w, http.StatusOK, resp)
}

type resolveIn struct {
	Outcome string `json:"outcome"`
	Note    string `json:"note"`
}

func (s *Server) resolveIncident(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in resolveIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	inc, err := s.recovery().Resolve(r.Context(), id, PrincipalFrom(r.Context()).UserID, in.Outcome, in.Note)
	if err != nil {
		return mapRecoveryError(err)
	}
	if s.d.Broker != nil {
		_, _ = s.d.Broker.Publish(r.Context(), "recovery.resolved", "global", map[string]any{"id": id})
	}
	return writeJSON(w, http.StatusOK, inc)
}

// Must match deploy.KindReconcile.
const jobKindReconcile = "deploy.reconcile"

type reconcileIn struct {
	Mode string `json:"mode"`
}

// reconcileIncident queues a supervised reconcile (adopt the serving
// generation, or restore the recorded one); the job verifies with probes and
// closes the incident only on proven success.
func (s *Server) reconcileIncident(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in reconcileIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Mode != "adopt" && in.Mode != "restore" {
		return apierr.BadRequest("mode must be adopt or restore")
	}
	inc, err := s.recovery().Get(r.Context(), id)
	if err != nil {
		return mapRecoveryError(err)
	}
	if inc.Status == "resolved" {
		return apierr.Conflict("incident already resolved")
	}
	return s.submitJob(w, r, jobKindReconcile, []string{"gateway-config", "certificate"}, map[string]string{"mode": in.Mode, "incident_id": id})
}

// getDrift reports record/data-plane drift from the latest observation.
func (s *Server) getDrift(w http.ResponseWriter, r *http.Request) error {
	d, err := recovery.CurrentDrift(r.Context(), s.d.DB)
	if err != nil {
		return writeJSON(w, http.StatusOK, map[string]any{"drift": nil, "evidence": false, "detail": err.Error()})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"drift": d, "evidence": true})
}

// reconcileDrift queues a supervised reconcile not tied to an incident
// (e.g. the pointer was changed outside NGM).
func (s *Server) reconcileDrift(w http.ResponseWriter, r *http.Request) error {
	var in reconcileIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Mode != "adopt" && in.Mode != "restore" {
		return apierr.BadRequest("mode must be adopt or restore")
	}
	return s.submitJob(w, r, jobKindReconcile, []string{"gateway-config", "certificate"}, map[string]string{"mode": in.Mode})
}
