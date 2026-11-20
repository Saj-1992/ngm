package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/alerts"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

func (s *Server) registerObservabilityRoutes() {
	s.handle("GET", "/api/v1/metrics", "monitoring.read", s.getPrometheusMetrics)
	s.handle("GET", "/api/v1/monitoring/traffic", "monitoring.read", s.getTrafficAnalytics)
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func (s *Server) getPrometheusMetrics(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	now := s.d.Now().UTC()
	var b strings.Builder

	b.WriteString("# HELP ngm_up Whether the NGM API process is responding.\n# TYPE ngm_up gauge\nngm_up 1\n")

	// Service heartbeats
	b.WriteString("# HELP ngm_service_status Status of NGM services (1=healthy, 0.5=degraded, 0=down/unknown).\n# TYPE ngm_service_status gauge\n")
	for _, name := range []string{"ngm-ops", "ngm-helper", "ngm-monitor", "ngm-log-indexer"} {
		c := s.heartbeat(ctx, name, now)
		val := 0.0
		switch c.Status {
		case Healthy:
			val = 1.0
		case Degraded:
			val = 0.5
		}
		fmt.Fprintf(&b, "ngm_service_status{service=%q} %.1f\n", promLabel(name), val)
	}

	// System metrics
	var m alerts.Metrics
	if at, err := observe.Latest(ctx, s.d.DB, alerts.KindSystem, &m); err == nil && now.Sub(at) <= 5*time.Minute {
		b.WriteString("# HELP ngm_system_cpu_percent Current CPU utilization percentage.\n# TYPE ngm_system_cpu_percent gauge\n")
		fmt.Fprintf(&b, "ngm_system_cpu_percent %.2f\n", m.CPUPct)
		b.WriteString("# HELP ngm_system_load1 1-minute system load average.\n# TYPE ngm_system_load1 gauge\n")
		fmt.Fprintf(&b, "ngm_system_load1 %.2f\n", m.Load1)
		b.WriteString("# HELP ngm_system_memory_used_bytes Used memory in bytes.\n# TYPE ngm_system_memory_used_bytes gauge\n")
		fmt.Fprintf(&b, "ngm_system_memory_used_bytes %d\n", m.MemUsed)
		b.WriteString("# HELP ngm_system_memory_total_bytes Total memory in bytes.\n# TYPE ngm_system_memory_total_bytes gauge\n")
		fmt.Fprintf(&b, "ngm_system_memory_total_bytes %d\n", m.MemTotal)
		b.WriteString("# HELP ngm_system_disk_used_bytes Used disk space in bytes.\n# TYPE ngm_system_disk_used_bytes gauge\n")
		fmt.Fprintf(&b, "ngm_system_disk_used_bytes %d\n", m.DiskUsed)
		b.WriteString("# HELP ngm_system_disk_total_bytes Total disk space in bytes.\n# TYPE ngm_system_disk_total_bytes gauge\n")
		fmt.Fprintf(&b, "ngm_system_disk_total_bytes %d\n", m.DiskTotal)
	}

	// Firing alerts by severity
	b.WriteString("# HELP ngm_alerts_firing Number of currently firing alerts.\n# TYPE ngm_alerts_firing gauge\n")
	alertCounts := map[string]int{"critical": 0, "warning": 0, "info": 0}
	if rows, err := s.d.DB.QueryContext(ctx, "SELECT severity, COUNT(*) FROM alerts WHERE state='firing' GROUP BY severity"); err == nil {
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				alertCounts[sev] = cnt
			}
		}
		rows.Close()
	}
	for _, sev := range []string{"critical", "warning", "info"} {
		fmt.Fprintf(&b, "ngm_alerts_firing{severity=%q} %d\n", sev, alertCounts[sev])
	}

	// Certificates expiry
	b.WriteString("# HELP ngm_cert_expiry_seconds Seconds remaining until certificate expiry.\n# TYPE ngm_cert_expiry_seconds gauge\n")
	if rows, err := s.d.DB.QueryContext(ctx, "SELECT name, COALESCE(not_after,'') FROM certificates"); err == nil {
		for rows.Next() {
			var name, na string
			if rows.Scan(&name, &na) == nil {
				if t, terr := store.ParseTime(na); terr == nil {
					fmt.Fprintf(&b, "ngm_cert_expiry_seconds{name=%q} %.0f\n", promLabel(name), t.Sub(now).Seconds())
				}
			}
		}
		rows.Close()
	}

	// Backend health
	b.WriteString("# HELP ngm_backend_health Backend endpoint health (1=healthy, 0=unhealthy).\n# TYPE ngm_backend_health gauge\n")
	if rows, err := s.d.DB.QueryContext(ctx, `SELECT COALESCE(e.name, h.subject_id), h.status FROM health_samples h
		JOIN (SELECT subject_id, MAX(seq) seq FROM health_samples WHERE subject_kind='endpoint' GROUP BY subject_id) m ON m.seq=h.seq
		LEFT JOIN backend_endpoints e ON e.id=h.subject_id WHERE e.id IS NOT NULL`); err == nil {
		for rows.Next() {
			var name, st string
			if rows.Scan(&name, &st) == nil {
				v := 0
				if st == Healthy {
					v = 1
				}
				fmt.Fprintf(&b, "ngm_backend_health{name=%q} %d\n", promLabel(name), v)
			}
		}
		rows.Close()
	}

	// Jobs by state
	b.WriteString("# HELP ngm_jobs_total Total jobs by state.\n# TYPE ngm_jobs_total gauge\n")
	if rows, err := s.d.DB.QueryContext(ctx, "SELECT state, COUNT(*) FROM jobs GROUP BY state"); err == nil {
		for rows.Next() {
			var st string
			var cnt int
			if rows.Scan(&st, &cnt) == nil {
				fmt.Fprintf(&b, "ngm_jobs_total{state=%q} %d\n", promLabel(st), cnt)
			}
		}
		rows.Close()
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
	return nil
}

type trafficBucket struct {
	TS    int64   `json:"ts"`
	Total int     `json:"total"`
	S2xx  int     `json:"s2xx"`
	S3xx  int     `json:"s3xx"`
	S4xx  int     `json:"s4xx"`
	S5xx  int     `json:"s5xx"`
	AvgMS float64 `json:"avg_ms"`
}

type topItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func (s *Server) getTrafficAnalytics(w http.ResponseWriter, r *http.Request) error {
	hours := 24
	if q := r.URL.Query().Get("hours"); q == "1" {
		hours = 1
	} else if q == "6" {
		hours = 6
	}
	now := s.d.Now().UTC()
	since := now.Add(-time.Duration(hours) * time.Hour).UnixMilli()
	bucketMS := int64(3600_000)
	if hours == 1 {
		bucketMS = 300_000 // 5-minute buckets for 1h view
	} else if hours == 6 {
		bucketMS = 900_000 // 15-minute buckets for 6h view
	}

	resp := map[string]any{
		"hours":       hours,
		"total":       0,
		"s2xx":        0,
		"s3xx":        0,
		"s4xx":        0,
		"s5xx":        0,
		"avg_ms":      0.0,
		"p95_ms":      0.0,
		"buckets":     []trafficBucket{},
		"top_hosts":   []topItem{},
		"top_paths":   []topItem{},
		"index_ready": false,
	}

	db, err := s.logDB()
	if err != nil {
		return writeJSON(w, http.StatusOK, resp)
	}
	resp["index_ready"] = true
	ctx := r.Context()

	var total, s2, s3, s4, s5 int
	var avgS float64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),0),
		COALESCE(AVG(dur),0)
		FROM entries WHERE cat='http' AND ts>=?`, since).Scan(&total, &s2, &s3, &s4, &s5, &avgS)

	resp["total"] = total
	resp["s2xx"] = s2
	resp["s3xx"] = s3
	resp["s4xx"] = s4
	resp["s5xx"] = s5
	resp["avg_ms"] = avgS * 1000.0

	// P95 latency (bounded sample of recent HTTP entries)
	if total > 0 {
		var durs []float64
		if rows, err := db.QueryContext(ctx, "SELECT dur FROM entries WHERE cat='http' AND ts>=? ORDER BY id DESC LIMIT 2000", since); err == nil {
			for rows.Next() {
				var d float64
				if rows.Scan(&d) == nil {
					durs = append(durs, d)
				}
			}
			rows.Close()
		}
		if len(durs) > 0 {
			sort.Float64s(durs)
			idx := int(float64(len(durs)-1) * 0.95)
			resp["p95_ms"] = durs[idx] * 1000.0
		}
	}

	// Time-series buckets
	buckets := []trafficBucket{}
	if rows, err := db.QueryContext(ctx, `SELECT (ts/?)*? AS b, COUNT(*),
		SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
		COALESCE(AVG(dur),0)*1000.0
		FROM entries WHERE cat='http' AND ts>=? GROUP BY b ORDER BY b ASC`, bucketMS, bucketMS, since); err == nil {
		for rows.Next() {
			var tb trafficBucket
			if rows.Scan(&tb.TS, &tb.Total, &tb.S2xx, &tb.S3xx, &tb.S4xx, &tb.S5xx, &tb.AvgMS) == nil {
				buckets = append(buckets, tb)
			}
		}
		rows.Close()
	}
	resp["buckets"] = buckets

	// Top hosts & paths
	topQuery := func(col string) []topItem {
		out := []topItem{}
		q := fmt.Sprintf("SELECT %s, COUNT(*) c FROM entries WHERE cat='http' AND ts>=? AND %s!='' GROUP BY %s ORDER BY c DESC LIMIT 8", col, col, col)
		if rows, err := db.QueryContext(ctx, q, since); err == nil {
			for rows.Next() {
				var it topItem
				if rows.Scan(&it.Key, &it.Count) == nil {
					out = append(out, it)
				}
			}
			rows.Close()
		}
		return out
	}
	resp["top_hosts"] = topQuery("host")
	resp["top_paths"] = topQuery("path")

	return writeJSON(w, http.StatusOK, resp)
}
