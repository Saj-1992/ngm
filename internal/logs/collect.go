package logs

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Source is one tailed log file.
type Source struct {
	Path  string
	Kind  string // http | stream | error | app
	Cat   string // for app logs: api | ops | monitor
	Label string
}

// Collector tails sources into the index.
type Collector struct {
	Ix      *Index
	Sources []Source
	// MaxBatch bounds lines read per source per pass (backpressure).
	MaxBatch int
}

// Status of one source after a pass.
type SourceStatus struct {
	Path    string `json:"path"`
	Offset  int64  `json:"offset"`
	Size    int64  `json:"size"`
	LagByte int64  `json:"lag_bytes"`
	Error   string `json:"error,omitempty"`
}

type checkpoint struct {
	ident  string
	offset int64
}

func (c *Collector) load(ctx context.Context, path string) (checkpoint, bool) {
	var cp checkpoint
	err := c.Ix.DB.QueryRowContext(ctx, "SELECT ident, offset FROM checkpoints WHERE path=?", path).Scan(&cp.ident, &cp.offset)
	return cp, err == nil
}

func (c *Collector) save(ctx context.Context, path string, cp checkpoint) error {
	_, err := c.Ix.DB.ExecContext(ctx, `INSERT INTO checkpoints(path,ident,offset,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET ident=excluded.ident, offset=excluded.offset, updated_at=excluded.updated_at`, path, cp.ident, cp.offset, time.Now().UnixMilli())
	return err
}

// Pass reads new data from every source once.
func (c *Collector) Pass(ctx context.Context) ([]SourceStatus, int, error) {
	var sts []SourceStatus
	total := 0
	for _, s := range c.Sources {
		st, n, err := c.passOne(ctx, s)
		if err != nil {
			st.Error = err.Error()
		}
		total += n
		sts = append(sts, st)
	}
	return sts, total, nil
}

func (c *Collector) passOne(ctx context.Context, s Source) (SourceStatus, int, error) {
	st := SourceStatus{Path: s.Path}
	n := 0
	// The rotated file (.1) keeps its own checkpoint and is drained on every
	// pass while it exists: Nginx reopens its logs asynchronously after
	// rotation, so lines can still be appended to the renamed file.
	prevKey := s.Path + "#rotated"
	if pcp, ok := c.load(ctx, prevKey); ok {
		ofi, err := os.Stat(s.Path + ".1")
		if err == nil && fileIdent(ofi) == pcp.ident {
			if ofi.Size() > pcp.offset {
				k, off, err := c.read(ctx, s, s.Path+".1", pcp.offset, ofi.Size())
				n += k
				if err != nil {
					return st, n, err
				}
				pcp.offset = off
				_ = c.save(ctx, prevKey, pcp)
			}
		} else {
			c.forget(ctx, prevKey) // compressed or rotated away
		}
	}
	fi, err := os.Stat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return st, n, nil
	}
	if err != nil {
		return st, n, err
	}
	id := fileIdent(fi)
	cp, ok := c.load(ctx, s.Path)
	if ok && cp.ident != "" && id != "" && cp.ident != id {
		// Rotated: hand the old file over to the rotated-file checkpoint.
		if ofi, err := os.Stat(s.Path + ".1"); err == nil && fileIdent(ofi) == cp.ident {
			k, off, err := c.read(ctx, s, s.Path+".1", cp.offset, ofi.Size())
			n += k
			if err != nil {
				return st, n, err
			}
			_ = c.save(ctx, prevKey, checkpoint{ident: cp.ident, offset: off})
		}
		cp = checkpoint{ident: id}
	}
	if !ok {
		// Fresh index (first run or rebuild): include the last rotated file.
		if ofi, err := os.Stat(s.Path + ".1"); err == nil {
			k, off, err := c.read(ctx, s, s.Path+".1", 0, ofi.Size())
			n += k
			if err != nil {
				return st, n, err
			}
			if oid := fileIdent(ofi); oid != "" {
				_ = c.save(ctx, prevKey, checkpoint{ident: oid, offset: off})
			}
		}
		cp = checkpoint{ident: id}
	}
	if fi.Size() < cp.offset {
		cp.offset = 0 // truncated (copytruncate or manual)
	}
	cp.ident = id
	k, off, err := c.read(ctx, s, s.Path, cp.offset, fi.Size())
	n += k
	cp.offset = off
	if serr := c.save(ctx, s.Path, cp); serr != nil && err == nil {
		err = serr
	}
	st.Offset, st.Size, st.LagByte = cp.offset, fi.Size(), fi.Size()-cp.offset
	return st, n, err
}

func (c *Collector) forget(ctx context.Context, path string) {
	_, _ = c.Ix.DB.ExecContext(ctx, "DELETE FROM checkpoints WHERE path=?", path)
}

// read indexes complete lines from [from, to) and returns the new offset
// (a partial last line is left for the next pass).
func (c *Collector) read(ctx context.Context, s Source, path string, from, to int64) (int, int64, error) {
	if to <= from {
		return 0, from, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, from, err
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return 0, from, err
	}
	max := c.MaxBatch
	if max <= 0 {
		max = 5000
	}
	br := bufio.NewReaderSize(io.LimitReader(f, to-from), 64<<10)
	var batch []Entry
	off := from
	lines := 0
	for lines < max {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Overlong line: skip it entirely (bounded memory).
			off += int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				off += int64(len(line))
			}
			lines++
			continue
		}
		if err != nil {
			break // EOF without newline: partial line stays for later
		}
		off += int64(len(line))
		lines++
		if e, ok := Parse(s, strings.TrimRight(string(line), "\r\n")); ok {
			batch = append(batch, e)
		}
	}
	if err := c.Ix.Insert(ctx, batch); err != nil {
		return 0, from, err
	}
	return len(batch), off, nil
}

// ─── parsers ──────────────────────────────────────────────────────────────

type httpLine struct {
	T, C, Port, Host, SNI, Route, M, P, S, B, RT, Up, US, URT, IP, TLS string
}

func (h *httpLine) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*h = httpLine{T: m["t"], C: m["c"], Port: m["port"], Host: m["host"], SNI: m["sni"], Route: m["route"], M: m["m"], P: m["p"], S: m["s"], B: m["b"],
		RT: m["rt"], Up: m["up"], US: m["us"], URT: m["urt"], IP: m["ip"], TLS: m["tls"]}
	return nil
}

func ts(s string) int64 {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006/01/02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli()
		}
	}
	return time.Now().UnixMilli()
}

var errLineRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (.*)$`)
var errFieldRe = regexp.MustCompile(`, (client|server|host|request|upstream): "?([^,"]*)"?`)

// Parse converts one line of a source into an entry.
func Parse(s Source, line string) (Entry, bool) {
	if strings.TrimSpace(line) == "" {
		return Entry{}, false
	}
	switch s.Kind {
	case "http":
		var h httpLine
		if json.Unmarshal([]byte(line), &h) != nil {
			return Entry{}, false
		}
		st, _ := strconv.Atoi(h.S)
		d, _ := strconv.ParseFloat(h.RT, 64)
		sev := "info"
		if st >= 500 {
			sev = "error"
		} else if st >= 400 {
			sev = "warn"
		}
		host := strings.ToLower(h.Host)
		msg := h.M + " " + StripQuery(h.P) + " " + h.S
		if h.Up != "" && h.Up != "-" {
			msg += " upstream " + h.Up + " (" + h.US + ")"
		}
		return Entry{TS: ts(h.T), Cat: "http", Sev: sev, Source: s.Path, Host: host, Route: h.Route, Status: st, Method: h.M, Path: StripQuery(h.P), IP: h.IP, Dur: d, Msg: msg}, true
	case "stream":
		var m map[string]string
		if json.Unmarshal([]byte(line), &m) != nil {
			return Entry{}, false
		}
		st, _ := strconv.Atoi(m["s"])
		d, _ := strconv.ParseFloat(m["d"], 64)
		sev := "info"
		if st >= 500 {
			sev = "error"
		}
		msg := "port " + m["port"] + " → " + m["up"] + " status " + m["s"] + " in " + m["bi"] + "B out " + m["bo"] + "B"
		return Entry{TS: ts(m["t"]), Cat: "stream", Sev: sev, Source: s.Path, Host: strings.ToLower(m["sni"]), Status: st, IP: m["ip"], Dur: d, Msg: msg}, true
	case "error":
		m := errLineRe.FindStringSubmatch(line)
		if m == nil {
			return Entry{TS: time.Now().UnixMilli(), Cat: "error", Sev: "error", Source: s.Path, Msg: Redact(line)}, true
		}
		e := Entry{TS: ts(m[1]), Cat: "error", Sev: nginxSev(m[2]), Source: s.Path, Msg: Redact(m[3])}
		for _, f := range errFieldRe.FindAllStringSubmatch(m[3], -1) {
			switch f[1] {
			case "client":
				e.IP = f[2]
			case "host":
				e.Host = strings.ToLower(f[2])
			case "request":
				if parts := strings.Fields(f[2]); len(parts) >= 2 {
					e.Method, e.Path = parts[0], StripQuery(parts[1])
				}
			}
		}
		return e, true
	case "app":
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			return Entry{}, false
		}
		lv, _ := m["level"].(string)
		msg, _ := m["msg"].(string)
		t, _ := m["time"].(string)
		var extra []string
		for k, v := range m {
			if k == "time" || k == "level" || k == "msg" {
				continue
			}
			if sensitiveKey(k) {
				continue
			}
			extra = append(extra, k+"="+strings.TrimSpace(strconv.Quote(toString(v))))
		}
		if len(extra) > 0 {
			sortStrings(extra)
			msg += " " + strings.Join(extra, " ")
		}
		return Entry{TS: ts(t), Cat: s.Cat, Sev: strings.ToLower(lv), Source: s.Path, Msg: Redact(msg)}, true
	}
	return Entry{}, false
}

func nginxSev(s string) string {
	switch s {
	case "emerg", "alert", "crit", "error":
		return "error"
	case "warn":
		return "warn"
	}
	return "info"
}

func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"password", "secret", "token", "authorization", "cookie", "key", "passphrase"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// ─── database-backed categories (security, audit, health) ────────────────

// DBSources copies security/audit/health records from the main database
// (read-only) using per-table cursors.
func (c *Collector) DBSources(ctx context.Context, main *sql.DB) (int, error) {
	n := 0
	cur := func(name string) int64 {
		var v string
		_ = c.Ix.DB.QueryRowContext(ctx, "SELECT value FROM cursors WHERE name=?", name).Scan(&v)
		x, _ := strconv.ParseInt(v, 10, 64)
		return x
	}
	set := func(name string, v int64) {
		_, _ = c.Ix.DB.ExecContext(ctx, "INSERT INTO cursors(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", name, strconv.FormatInt(v, 10))
	}
	// Audit events (security = failures/denials).
	rows, err := main.QueryContext(ctx, "SELECT seq, at, actor_kind, COALESCE(actor_id,''), action, COALESCE(target_kind,''), COALESCE(target_id,''), result FROM audit_events WHERE seq>? ORDER BY seq LIMIT 2000", cur("audit"))
	if err != nil {
		return 0, err
	}
	var batch []Entry
	var last int64
	for rows.Next() {
		var seq int64
		var at, kind, actor, action, tk, tid, result string
		if err := rows.Scan(&seq, &at, &kind, &actor, &action, &tk, &tid, &result); err != nil {
			rows.Close()
			return n, err
		}
		last = seq
		cat, sev := "audit", "info"
		if result != "success" {
			cat, sev = "security", "warn"
		}
		batch = append(batch, Entry{TS: ts(at), Cat: cat, Sev: sev, Source: "audit", Msg: action + " " + result + " by " + kind + " " + actor + " on " + tk + " " + tid})
	}
	rows.Close()
	if err := c.Ix.Insert(ctx, batch); err != nil {
		return n, err
	}
	n += len(batch)
	if last > 0 {
		set("audit", last)
	}
	// Health samples.
	hrows, err := main.QueryContext(ctx, "SELECT seq, subject_kind, subject_id, status, COALESCE(latency_ms,0), detail, observed_at FROM health_samples WHERE seq>? ORDER BY seq LIMIT 5000", cur("health"))
	if err != nil {
		return n, err
	}
	batch, last = nil, 0
	for hrows.Next() {
		var seq, lat int64
		var kind, id, status, detail, at string
		if err := hrows.Scan(&seq, &kind, &id, &status, &lat, &detail, &at); err != nil {
			hrows.Close()
			return n, err
		}
		last = seq
		sev := "info"
		if status == "down" {
			sev = "error"
		} else if status != "healthy" {
			sev = "warn"
		}
		batch = append(batch, Entry{TS: ts(at), Cat: "health", Sev: sev, Source: kind, Route: id, Dur: float64(lat) / 1000, Msg: kind + " " + id + " " + status + " " + Redact(detail)})
	}
	hrows.Close()
	if err := c.Ix.Insert(ctx, batch); err != nil {
		return n, err
	}
	n += len(batch)
	if last > 0 {
		set("health", last)
	}
	return n, nil
}
