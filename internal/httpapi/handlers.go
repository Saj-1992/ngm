package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/jobs"
)

func (s *Server) registerRoutes() {
	s.handle("GET", "/api/v1/system/health", "", s.getHealth)
	s.handle("GET", "/api/v1/system/version", "system.read", s.getVersion)
	s.handle("GET", "/api/v1/jobs", "jobs.read", s.listJobs)
	s.handle("GET", "/api/v1/jobs/{id}", "jobs.read", s.getJob)
	s.handle("GET", "/api/v1/jobs/{id}/steps", "jobs.read", s.getJobSteps)
	s.handle("GET", "/api/v1/events", "events.read", s.streamEvents)
	s.registerAuthRoutes()
	s.registerGatewayRoutes()
	s.registerFirewallRoutes()
	s.registerBackupRoutes()
	s.registerRecoveryRoutes()
	s.registerDomainRoutes()
	s.registerCloudflareRoutes()
	s.registerWebsiteRoutes()
	s.registerLogRoutes()
	s.registerAlertRoutes()
	s.registerPerfRoutes()
	s.registerTopologyRoutes()
	s.registerUpdateRoutes()
}

// Health statuses (MASTER_SPEC §13.2). Unknown is never reported as healthy.
const (
	Healthy  = "healthy"
	Degraded = "degraded"
	Down     = "down"
	Unknown  = "unknown"
	Disabled = "disabled"
)

type component struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Detail     string    `json:"detail,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type healthResponse struct {
	Status     string      `json:"status"`
	Components []component `json:"components"`
	ObservedAt time.Time   `json:"observed_at"`
}

func overall(cs []component) string {
	rank := map[string]int{Healthy: 0, Disabled: 0, Unknown: 1, Degraded: 2, Down: 3}
	worst := Healthy
	for _, c := range cs {
		if rank[c.Status] > rank[worst] {
			worst = c.Status
		}
	}
	return worst
}

// getHealth is public (load balancer / installer smoke test) but returns only
// coarse status to anonymous callers; component detail requires system.read.
func (s *Server) getHealth(w http.ResponseWriter, r *http.Request) error {
	now := time.Now().UTC()
	cs := []component{{Name: "api", Status: Healthy, ObservedAt: now}}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	db := component{Name: "database", ObservedAt: now}
	if err := s.d.DB.PingContext(ctx); err != nil {
		db.Status, db.Detail = Down, "database unreachable"
	} else if v, err := s.d.DB.SchemaVersion(ctx); err != nil {
		db.Status, db.Detail = Degraded, "schema version unreadable"
	} else {
		db.Status, db.Detail = Healthy, "schema v"+strconv.Itoa(v)
	}
	cs = append(cs, db)

	// Data-plane and worker state come from observations written by ngm-ops
	// (via ngm-helper). Missing or stale evidence is Unknown, never Healthy.
	cs = append(cs, s.nginxComponent(ctx, now))
	for _, name := range []string{"ngm-ops", "ngm-helper", "ngm-monitor"} {
		cs = append(cs, s.heartbeat(ctx, name, now))
	}
	if c, ok := s.backendsComponent(ctx, now); ok {
		cs = append(cs, c)
	}

	resp := healthResponse{Status: overall(cs), ObservedAt: now}
	if p := PrincipalFrom(r.Context()); p.Can("system.read") {
		resp.Components = cs
	} else {
		resp.Components = []component{}
	}
	status := http.StatusOK
	if resp.Status == Down {
		status = http.StatusServiceUnavailable
	}
	return writeJSON(w, status, resp)
}

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) error {
	v, err := s.d.DB.SchemaVersion(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, struct {
		buildinfo.Info
		SchemaVersion int `json:"schema_version"`
	}{buildinfo.Get(), v})
}

type page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) error {
	limit, err := pageLimit(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	f := jobs.ListFilter{Limit: limit + 1, Kind: q.Get("kind"), Before: q.Get("cursor")}
	if st := q.Get("state"); st != "" {
		if !jobs.State(st).Valid() {
			return apierr.BadRequest("unknown state filter")
		}
		f.State = jobs.State(st)
	}
	if f.Before != "" && !ids.Valid(f.Before) {
		return apierr.BadRequest("invalid cursor")
	}
	if len(f.Kind) > 64 {
		return apierr.BadRequest("kind filter too long")
	}
	list, err := s.d.Jobs.List(r.Context(), f)
	if err != nil {
		return err
	}
	out := page[*jobs.Job]{Items: list}
	if len(list) > limit {
		out.Items = list[:limit]
		c := list[limit-1].ID
		out.NextCursor = &c
	}
	if out.Items == nil {
		out.Items = []*jobs.Job{}
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadJob(r *http.Request) (*jobs.Job, error) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		return nil, apierr.NotFound("job")
	}
	j, err := s.d.Jobs.Get(r.Context(), id)
	if errors.Is(err, jobs.ErrNotFound) {
		return nil, apierr.NotFound("job")
	}
	return j, err
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) error {
	j, err := s.loadJob(r)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", ETag(j.Revision))
	return writeJSON(w, http.StatusOK, j)
}

func (s *Server) getJobSteps(w http.ResponseWriter, r *http.Request) error {
	j, err := s.loadJob(r)
	if err != nil {
		return err
	}
	steps, err := s.d.Jobs.Steps(r.Context(), j.ID)
	if err != nil {
		return err
	}
	if steps == nil {
		steps = []jobs.Step{}
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": steps})
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) error {
	p := PrincipalFrom(r.Context())
	s.d.Broker.Serve(w, r, p.CanSeeScope)
	return nil
}
