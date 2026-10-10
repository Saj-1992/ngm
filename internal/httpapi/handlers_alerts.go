package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ngm-gateway/ngm/internal/alerts"
	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/observe"
)

func (s *Server) registerAlertRoutes() {
	s.handle("GET", "/api/v1/alerts", "monitoring.read", s.listAlerts)
	s.handle("POST", "/api/v1/alerts/{id}/ack", "alerts.write", s.ackAlert)
	s.handle("GET", "/api/v1/monitoring/system", "monitoring.read", s.systemMetrics)
	s.handle("GET", "/api/v1/notifications/targets", "settings.read", s.listTargets)
	s.handle("POST", "/api/v1/notifications/targets", "settings.write", s.createTarget)
	s.handle("PATCH", "/api/v1/notifications/targets/{id}", "settings.write", s.patchTarget)
	s.handle("DELETE", "/api/v1/notifications/targets/{id}", "settings.write", s.deleteTarget)
	s.handle("POST", "/api/v1/notifications/targets/{id}/test", "settings.write", s.testTarget)
	s.handle("GET", "/api/v1/notifications/deliveries", "settings.read", s.listDeliveries)
}

func (s *Server) notifier() *alerts.Notifier { return &alerts.Notifier{DB: s.d.DB, Vault: s.d.Vault} }

func mapAlertError(err error) error {
	var ve *alerts.ValidationError
	switch {
	case errors.As(err, &ve):
		return apierr.BadRequest(ve.Msg)
	case errors.Is(err, alerts.ErrNotFound), errors.Is(err, alerts.ErrTargetNotFound):
		return apierr.NotFound("resource")
	}
	return err
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) error {
	items, err := (&alerts.Store{DB: s.d.DB}).List(r.Context(), r.URL.Query().Get("state") == "open", 200)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := (&alerts.Store{DB: s.d.DB}).Acknowledge(r.Context(), id, PrincipalFrom(r.Context()).UserID); err != nil {
		return mapAlertError(err)
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "alert.ack", "alert", id, nil))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type metricPoint struct {
	TS        int64   `json:"ts"`
	CPU       float64 `json:"cpu_pct"`
	Load1     float64 `json:"load1"`
	MemUsed   int64   `json:"mem_used"`
	MemTotal  int64   `json:"mem_total"`
	DiskUsed  int64   `json:"disk_used"`
	DiskTotal int64   `json:"disk_total"`
}

// systemMetrics returns the latest sample (with freshness) and a bounded history.
func (s *Server) systemMetrics(w http.ResponseWriter, r *http.Request) error {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	var cur alerts.Metrics
	at, err := observe.Latest(r.Context(), s.d.DB, alerts.KindSystem, &cur)
	resp := map[string]any{"current": nil}
	if err == nil {
		resp["current"], resp["observed_at"], resp["stale"] = cur, at, time.Since(at) > 2*time.Minute
	}
	rows, err := s.d.DB.QueryContext(r.Context(), "SELECT ts,cpu_pct,load1,mem_used,mem_total,disk_used,disk_total FROM metric_samples WHERE ts>=? ORDER BY ts", time.Now().Add(-time.Duration(hours)*time.Hour).Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	pts := []metricPoint{}
	step := int64(hours * 60 * 60 / 300) // ≤ ~300 points
	var last int64
	for rows.Next() {
		var p metricPoint
		if err := rows.Scan(&p.TS, &p.CPU, &p.Load1, &p.MemUsed, &p.MemTotal, &p.DiskUsed, &p.DiskTotal); err != nil {
			return err
		}
		if p.TS-last >= step {
			pts = append(pts, p)
			last = p.TS
		}
	}
	resp["history"] = pts
	return writeJSON(w, http.StatusOK, resp)
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) error {
	items, err := s.notifier().List(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) error {
	var in alerts.TargetInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	t, err := s.notifier().Create(r.Context(), in)
	in.Secret = ""
	if err != nil {
		return mapAlertError(err)
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "notification.target_create", "notification_target", t.ID, map[string]any{"kind": t.Kind}))
	return writeJSON(w, http.StatusCreated, t)
}

type targetPatch struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) patchTarget(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	var in targetPatch
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if err := s.notifier().SetEnabled(r.Context(), id, in.Enabled); err != nil {
		return mapAlertError(err)
	}
	t, err := s.notifier().Get(r.Context(), id)
	if err != nil {
		return mapAlertError(err)
	}
	return writeJSON(w, http.StatusOK, t)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.notifier().Delete(r.Context(), id); err != nil {
		return mapAlertError(err)
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "notification.target_delete", "notification_target", id, nil))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// testTarget queues a test message (sent by ngm-ops within ~10 s).
func (s *Server) testTarget(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	did, err := s.notifier().Test(r.Context(), id)
	if err != nil {
		return mapAlertError(err)
	}
	return writeJSON(w, http.StatusAccepted, map[string]any{"delivery_id": did, "note": "delivery is attempted by ngm-ops within about 10 seconds; check the delivery list"})
}

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) error {
	items, err := s.notifier().Deliveries(r.Context(), 100)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
