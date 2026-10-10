package httpapi

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/logs"
	"github.com/ngm-gateway/ngm/internal/observe"
)

func (s *Server) registerLogRoutes() {
	s.handle("GET", "/api/v1/logs", "logs.read", s.searchLogs)
	s.handle("GET", "/api/v1/logs/export", "logs.read", s.exportLogs)
	s.handle("GET", "/api/v1/logs/tail", "logs.read", s.tailLogs)
	s.handle("GET", "/api/v1/logs/status", "logs.read", s.logStatus)
}

var logDBMu sync.Mutex

func (s *Server) logDB() (*sql.DB, error) {
	logDBMu.Lock()
	defer logDBMu.Unlock()
	p := filepath.Join(s.d.Config.Paths.StateDir, "logindex", "index.db")
	if s.d.LogIndexPath != "" {
		p = s.d.LogIndexPath
	}
	fi, statErr := os.Stat(p)
	if s.logIndex != nil {
		// A rebuilt index is a new file: drop the handle on the old one.
		if statErr == nil && s.logIndexFile != nil && os.SameFile(fi, s.logIndexFile) {
			return s.logIndex, nil
		}
		s.logIndex.Close()
		s.logIndex, s.logIndexFile = nil, nil
	}
	db, err := logs.OpenReadOnly(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, apierr.Unavailable("the log index is not available yet (is ngm-log-indexer running?)")
	}
	if err != nil {
		return nil, err
	}
	s.logIndex = db
	s.logIndexFile = fi
	return db, nil
}

var logCats = map[string]bool{"": true, "http": true, "stream": true, "error": true, "api": true, "ops": true, "monitor": true, "security": true, "audit": true, "health": true}

func parseLogQuery(r *http.Request, maxLimit int) (logs.Query, error) {
	v := r.URL.Query()
	q := logs.Query{Cat: v.Get("category"), Text: v.Get("q"), Route: v.Get("route"), Host: v.Get("host"), Status: v.Get("status"), Sev: v.Get("severity")}
	if !logCats[q.Cat] {
		return q, apierr.BadRequest("unknown category")
	}
	if len(q.Text) > 200 || len(q.Host) > 253 || len(q.Route) > 64 {
		return q, apierr.BadRequest("filter too long")
	}
	num := func(k string) (int64, error) {
		if v.Get(k) == "" {
			return 0, nil
		}
		return strconv.ParseInt(v.Get(k), 10, 64)
	}
	var err error
	if q.Since, err = num("since"); err != nil {
		return q, apierr.BadRequest("since must be unix milliseconds")
	}
	if q.Until, err = num("until"); err != nil {
		return q, apierr.BadRequest("until must be unix milliseconds")
	}
	if q.Before, err = num("before"); err != nil {
		return q, apierr.BadRequest("invalid cursor")
	}
	lim, _ := num("limit")
	if lim <= 0 {
		lim = 100
	}
	if lim > int64(maxLimit) {
		lim = int64(maxLimit)
	}
	q.Limit = int(lim)
	return q, nil
}

func (s *Server) searchLogs(w http.ResponseWriter, r *http.Request) error {
	q, err := parseLogQuery(r, 500)
	if err != nil {
		return err
	}
	db, err := s.logDB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	items, err := logs.Search(ctx, db, q)
	if err != nil {
		return err
	}
	var next any
	if len(items) == q.Limit && len(items) > 0 {
		next = strconv.FormatInt(items[len(items)-1].ID, 10)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_before": next})
}

// exportLogs streams up to 50,000 matching entries as CSV, JSONL or text.
func (s *Server) exportLogs(w http.ResponseWriter, r *http.Request) error {
	q, err := parseLogQuery(r, 50000)
	if err != nil {
		return err
	}
	if r.URL.Query().Get("limit") == "" {
		q.Limit = 10000
	}
	format := r.URL.Query().Get("format")
	db, err := s.logDB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	items, err := logs.Search(ctx, db, q)
	if err != nil {
		return err
	}
	name := "ngm-logs-" + time.Now().UTC().Format("20060102T150405Z")
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "logs.export", "logs", q.Cat, map[string]any{"format": format, "rows": len(items)}))
	switch format {
	case "csv":
		h.Set("Content-Type", "text/csv; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"time", "category", "severity", "host", "route", "status", "method", "path", "ip", "duration_s", "message"})
		for _, e := range items {
			_ = cw.Write([]string{time.UnixMilli(e.TS).UTC().Format(time.RFC3339Nano), e.Cat, e.Sev, e.Host, e.Route, strconv.Itoa(e.Status), e.Method, csvSafe(e.Path), e.IP,
				strconv.FormatFloat(e.Dur, 'f', 3, 64), csvSafe(e.Msg)})
		}
		cw.Flush()
		return cw.Error()
	case "jsonl":
		h.Set("Content-Type", "application/x-ndjson")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.jsonl"`)
		enc := json.NewEncoder(w)
		for _, e := range items {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	case "txt", "":
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.txt"`)
		for _, e := range items {
			if _, err := fmt.Fprintf(w, "%s %-8s %-5s %s\n", time.UnixMilli(e.TS).UTC().Format(time.RFC3339), e.Cat, e.Sev, strings.ReplaceAll(e.Msg, "\n", " ")); err != nil {
				return err
			}
		}
		return nil
	}
	return apierr.BadRequest("format must be csv, jsonl or txt")
}

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// tailLogs streams new matching entries over SSE (polling the index).
func (s *Server) tailLogs(w http.ResponseWriter, r *http.Request) error {
	q, err := parseLogQuery(r, 200)
	if err != nil {
		return err
	}
	db, err := s.logDB()
	if err != nil {
		return err
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		return apierr.Internal()
	}
	// Start from the newest entry: live tail shows what arrives from now on.
	var last int64
	_ = db.QueryRowContext(r.Context(), "SELECT COALESCE(MAX(id),0) FROM entries").Scan(&last)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	deadline := time.After(30 * time.Minute)
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-deadline:
			return nil
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return nil
			}
			fl.Flush()
		case <-tick.C:
			qq := q
			qq.After, qq.Limit = last, 200
			items, err := logs.Search(r.Context(), db, qq)
			if err != nil {
				return nil
			}
			for _, e := range items {
				b, _ := json.Marshal(e)
				if _, err := fmt.Fprintf(w, "id: %d\nevent: log\ndata: %s\n\n", e.ID, b); err != nil {
					return nil
				}
				last = e.ID
			}
			if len(items) > 0 {
				fl.Flush()
			}
		}
	}
}

func (s *Server) logStatus(w http.ResponseWriter, r *http.Request) error {
	var st json.RawMessage
	at, err := observe.Latest(r.Context(), s.d.DB, "log_pipeline", &st)
	if err != nil {
		return writeJSON(w, http.StatusOK, map[string]any{"status": nil, "retention_days": logs.Retention})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"status": st, "observed_at": at, "retention_days": logs.Retention})
}
