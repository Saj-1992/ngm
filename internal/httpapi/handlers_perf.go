package httpapi

import (
	"errors"
	"net/http"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/perf"
)

func (s *Server) registerPerfRoutes() {
	s.handle("GET", "/api/v1/performance", "performance.read", s.getPerf)
	s.handle("PUT", "/api/v1/performance", "performance.write", s.putPerf)
}

func (s *Server) perfView(r *http.Request) perf.View {
	var m struct {
		MemTotal uint64 `json:"mem_total"`
		CPUs     int    `json:"cpus"`
	}
	_, _ = observe.Latest(r.Context(), s.d.DB, "system", &m)
	return perf.Resolve(perf.Load(r.Context(), s.d.DB), m.MemTotal, m.CPUs)
}

func (s *Server) getPerf(w http.ResponseWriter, r *http.Request) error {
	v := s.perfView(r)
	return writeJSON(w, http.StatusOK, map[string]any{"view": v, "rendered": v.Render(), "profiles": perf.Profiles,
		"not_managed": map[string]string{"worker_processes": "main context of nginx.conf (not owned by NGM)", "worker_connections": "events context of nginx.conf (not owned by NGM)"},
		"note":        "profiles are provisional until benchmarked; changes reach Nginx only through a deployment (Safe Apply)"})
}

func (s *Server) putPerf(w http.ResponseWriter, r *http.Request) error {
	var in perf.Settings
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if err := perf.Save(r.Context(), s.d.DB, in); err != nil {
		if errors.Is(err, perf.ErrInvalid) {
			return apierr.BadRequest(err.Error())
		}
		return err
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "performance.update", "settings", "performance", map[string]any{"profile": in.Profile, "overrides": len(in.Overrides)}))
	return s.getPerf(w, r)
}
