package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Metrics is the latest system sample (see metrics_*.go).
type Metrics struct {
	CPUPct    float64   `json:"cpu_pct"`
	Load1     float64   `json:"load1"`
	CPUs      int       `json:"cpus"`
	MemUsed   uint64    `json:"mem_used"`
	MemTotal  uint64    `json:"mem_total"`
	DiskUsed  uint64    `json:"disk_used"`
	DiskTotal uint64    `json:"disk_total"`
	At        time.Time `json:"at"`
}

// KindSystem is the observation kind for Metrics.
const KindSystem = "system"

// Evaluate derives conditions from recorded evidence only. Missing or stale
// evidence is reported as such ("unknown"), never as healthy.
func Evaluate(ctx context.Context, db *store.DB, now time.Time) ([]Condition, error) {
	var out []Condition
	add := func(rule, subject, sev, msg string, d map[string]any) {
		out = append(out, Condition{Rule: rule, Subject: subject, Severity: sev, Message: msg, Details: d})
	}
	// Services (heartbeats).
	rows, err := db.QueryContext(ctx, "SELECT service, status, detail, observed_at FROM service_heartbeats")
	if err == nil {
		for rows.Next() {
			var svc, st, detail, at string
			if rows.Scan(&svc, &st, &detail, &at) != nil {
				continue
			}
			t, _ := store.ParseTime(at)
			switch {
			case now.Sub(t) > 2*time.Minute:
				add("service_unresponsive", svc, "critical", fmt.Sprintf("%s has not reported for %s", svc, now.Sub(t).Round(time.Second)), map[string]any{"last": at})
			case st == "down":
				add("service_down", svc, "critical", svc+" is down: "+detail, nil)
			case st == "degraded":
				add("service_degraded", svc, "warning", svc+" is degraded: "+detail, nil)
			}
		}
		rows.Close()
	}
	// Nginx.
	var n observe.Nginx
	if at, err := observe.Latest(ctx, db, observe.KindNginx, &n); err != nil || now.Sub(at) > 5*time.Minute {
		add("nginx_unknown", "nginx", "warning", "no fresh observation of Nginx (is ngm-ops running?)", nil)
	} else {
		if n.Installed && n.ServiceState != "active" {
			add("nginx_down", "nginx", "critical", "nginx service state is "+n.ServiceState, nil)
		}
		nginxDrift(ctx, db, n, add)
	}
	// Backends (latest sample per endpoint).
	brows, err := db.QueryContext(ctx, `SELECT h.subject_id, h.status, h.detail, h.observed_at, COALESCE(e.name, h.subject_id) FROM health_samples h
		JOIN (SELECT subject_id, MAX(seq) seq FROM health_samples WHERE subject_kind='endpoint' GROUP BY subject_id) m ON m.seq=h.seq
		LEFT JOIN backend_endpoints e ON e.id=h.subject_id WHERE e.id IS NOT NULL`)
	if err == nil {
		for brows.Next() {
			var id, st, detail, at, name string
			if brows.Scan(&id, &st, &detail, &at, &name) != nil {
				continue
			}
			if st == "down" {
				add("backend_down", name, "warning", "backend "+name+" is down: "+detail, map[string]any{"endpoint_id": id})
			}
		}
		brows.Close()
	}
	// Certificates.
	crows, err := db.QueryContext(ctx, "SELECT name, COALESCE(not_after,''), source, acme_json FROM certificates")
	if err == nil {
		for crows.Next() {
			var name, na, src, aj string
			if crows.Scan(&name, &na, &src, &aj) != nil {
				continue
			}
			t, err := store.ParseTime(na)
			if err != nil {
				continue
			}
			left := t.Sub(now)
			switch {
			case left <= 0:
				add("cert_expired", name, "critical", "certificate "+name+" expired on "+t.Format("2006-01-02"), nil)
			case left < 3*24*time.Hour:
				add("cert_expiring", name, "critical", fmt.Sprintf("certificate %s expires in %s", name, left.Round(time.Hour)), nil)
			case left < 14*24*time.Hour:
				add("cert_expiring", name, "warning", fmt.Sprintf("certificate %s expires on %s", name, t.Format("2006-01-02")), nil)
			}
			if src == "acme" {
				var st struct {
					LastError string `json:"last_error"`
				}
				if json.Unmarshal([]byte(aj), &st) == nil && st.LastError != "" {
					add("acme_renewal_failed", name, "warning", "ACME renewal of "+name+" failed: "+st.LastError, nil)
				}
			}
		}
		crows.Close()
	}
	// DNS: authoritative mismatch/missing (propagation is not an alert).
	drows, err := db.QueryContext(ctx, `SELECT d.fqdn, e.name, e.rtype, e.value, COALESCE(o.values_json,''), COALESCE(o.error,''), COALESCE(o.observed_at,'')
		FROM dns_record_expectations e JOIN domains d ON d.id=e.domain_id
		LEFT JOIN dns_observations o ON o.domain_id=e.domain_id AND o.name=e.name AND o.rtype=e.rtype AND o.source='authoritative'`)
	if err == nil {
		for drows.Next() {
			var fqdn, name, rt, val, vj, oerr, at string
			if drows.Scan(&fqdn, &name, &rt, &val, &vj, &oerr, &at) != nil || at == "" || oerr != "" {
				continue
			}
			var vals []string
			_ = json.Unmarshal([]byte(vj), &vals)
			ok := false
			for _, v := range vals {
				ok = ok || strings.EqualFold(strings.TrimSuffix(v, "."), strings.TrimSuffix(val, "."))
			}
			if !ok {
				add("dns_mismatch", rt+" "+name, "warning", fmt.Sprintf("%s %s: authoritative answer %v, expected %s", rt, name, vals, val), map[string]any{"domain": fqdn})
			}
		}
		drows.Close()
	}
	// Recovery incidents.
	var incidents int
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM recovery_incidents WHERE status<>'resolved'").Scan(&incidents)
	if incidents > 0 {
		add("recovery_required", "recovery", "critical", fmt.Sprintf("%d recovery incident(s) need supervised action", incidents), nil)
	}
	// Recent failed jobs (24 h).
	var failed int
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE state='Failed' AND updated_at>?", store.FormatTime(now.Add(-24*time.Hour))).Scan(&failed)
	if failed > 0 {
		add("jobs_failed", "jobs", "warning", fmt.Sprintf("%d job(s) failed in the last 24 hours", failed), nil)
	}
	// System metrics.
	var m Metrics
	if at, err := observe.Latest(ctx, db, KindSystem, &m); err == nil && now.Sub(at) < 5*time.Minute {
		if m.DiskTotal > 0 {
			free := float64(m.DiskTotal-m.DiskUsed) / float64(m.DiskTotal) * 100
			switch {
			case free < 5:
				add("disk_low", "/", "critical", fmt.Sprintf("only %.1f%% disk space free", free), nil)
			case free < 10:
				add("disk_low", "/", "warning", fmt.Sprintf("%.1f%% disk space free", free), nil)
			}
		}
		if m.MemTotal > 0 && float64(m.MemUsed)/float64(m.MemTotal) > 0.92 {
			add("memory_high", "memory", "warning", fmt.Sprintf("memory %.0f%% used", float64(m.MemUsed)/float64(m.MemTotal)*100), nil)
		}
	}
	// Log pipeline.
	var lp struct {
		Paused  bool   `json:"paused"`
		Reason  string `json:"reason"`
		Sources []struct {
			Path string `json:"path"`
			Lag  int64  `json:"lag_bytes"`
		} `json:"sources"`
	}
	if at, err := observe.Latest(ctx, db, "log_pipeline", &lp); err == nil {
		switch {
		case now.Sub(at) > 5*time.Minute:
			add("log_pipeline_stale", "log-indexer", "warning", "the log indexer has not reported recently", nil)
		case lp.Paused:
			add("log_pipeline_paused", "log-indexer", "warning", lp.Reason, nil)
		default:
			for _, s := range lp.Sources {
				if s.Lag > 50<<20 {
					add("log_pipeline_lag", s.Path, "warning", fmt.Sprintf("log indexing is %d MiB behind", s.Lag>>20), nil)
				}
			}
		}
	}
	return out, nil
}
