// Package logs collects NGM's log sources into a rebuildable search index
// (MASTER_SPEC §13.1). Source files (JSONL/text) stay the source of truth;
// the SQLite+FTS5 index under /var/lib/ngm/logindex can be deleted and
// rebuilt at any time. Collection checkpoints (file identity + offset)
// survive rotation, truncation and restarts. Query strings and credentials
// never enter the index.
package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is one indexed log record.
type Entry struct {
	ID     int64   `json:"id"`
	TS     int64   `json:"ts"` // unix milliseconds
	Cat    string  `json:"category"`
	Sev    string  `json:"severity"`
	Source string  `json:"source"`
	Host   string  `json:"host,omitempty"`
	Route  string  `json:"route,omitempty"`
	Status int     `json:"status,omitempty"`
	Method string  `json:"method,omitempty"`
	Path   string  `json:"path,omitempty"`
	IP     string  `json:"ip,omitempty"`
	Dur    float64 `json:"duration_s,omitempty"`
	Msg    string  `json:"message"`
}

// Categories (MASTER_SPEC §13.1) and default retention in days.
var Retention = map[string]int{"http": 7, "stream": 7, "error": 30, "api": 14, "ops": 14, "monitor": 14, "security": 90, "audit": 180, "health": 30, "website": 30}

// Index is the search database.
type Index struct {
	DB   *sql.DB
	Path string
}

const schema = `
CREATE TABLE IF NOT EXISTS entries (
  id     INTEGER PRIMARY KEY,
  ts     INTEGER NOT NULL,
  cat    TEXT NOT NULL,
  sev    TEXT NOT NULL DEFAULT 'info',
  src    TEXT NOT NULL,
  host   TEXT NOT NULL DEFAULT '',
  route  TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 0,
  method TEXT NOT NULL DEFAULT '',
  path   TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT '',
  dur    REAL NOT NULL DEFAULT 0,
  msg    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS entries_cat_ts ON entries(cat, ts);
CREATE INDEX IF NOT EXISTS entries_ts ON entries(ts);
CREATE INDEX IF NOT EXISTS entries_route ON entries(route, ts);
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(msg, path, host, content='entries', content_rowid='id');
CREATE TABLE IF NOT EXISTS checkpoints (
  path   TEXT PRIMARY KEY,
  ident  TEXT NOT NULL,
  offset INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cursors (
  name  TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// Open opens (creating if needed) the index. A corrupt index is moved aside
// and recreated: it is derived data, the source logs are untouched.
func Open(path string) (*Index, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, err
	}
	ix, err := open(path)
	if err == nil {
		var res string
		if err = ix.DB.QueryRow("PRAGMA quick_check").Scan(&res); err == nil && res == "ok" {
			return ix, nil
		}
		ix.DB.Close()
	}
	bad := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405")
	for _, suf := range []string{"", "-wal", "-shm"} {
		_ = os.Rename(path+suf, bad+suf)
	}
	return open(path)
}

func open(path string) (*Index, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("log index schema: %w", err)
	}
	return &Index{DB: db, Path: path}, nil
}

// OpenReadOnly opens the index for queries (the API).
func OpenReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	return db, nil
}

// ShareWithGroup gives group ngm read/write on the index files: SQLite
// creates them 0640, but read-only readers in WAL mode (the API) still need
// write access to the -shm file.
func (ix *Index) ShareWithGroup() {
	for _, suf := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(ix.Path + suf); err == nil && fi.Mode().Perm() != 0o660 {
			_ = os.Chmod(ix.Path+suf, 0o660)
		}
	}
}

// Close closes the index.
func (ix *Index) Close() error { return ix.DB.Close() }

// Insert adds entries in one transaction (and to the full-text index).
func (ix *Index) Insert(ctx context.Context, es []Entry) error {
	if len(es) == 0 {
		return nil
	}
	tx, err := ix.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO entries(ts,cat,sev,src,host,route,status,method,path,ip,dur,msg) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	fts, err := tx.PrepareContext(ctx, `INSERT INTO entries_fts(rowid,msg,path,host) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	for _, e := range es {
		r, err := st.ExecContext(ctx, e.TS, e.Cat, e.Sev, e.Source, e.Host, e.Route, e.Status, e.Method, e.Path, e.IP, e.Dur, e.Msg)
		if err != nil {
			return err
		}
		id, _ := r.LastInsertId()
		if _, err := fts.ExecContext(ctx, id, e.Msg, e.Path, e.Host); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Prune applies retention per category and an overall row budget (oldest first).
func (ix *Index) Prune(ctx context.Context, now time.Time, maxRows int64) (int64, error) {
	var removed int64
	for cat, days := range Retention {
		cut := now.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
		n, err := ix.deleteWhere(ctx, "cat=? AND ts<?", cat, cut)
		if err != nil {
			return removed, err
		}
		removed += n
	}
	var total int64
	if err := ix.DB.QueryRowContext(ctx, "SELECT count(*) FROM entries").Scan(&total); err != nil {
		return removed, err
	}
	if maxRows > 0 && total > maxRows {
		var cutID int64
		if err := ix.DB.QueryRowContext(ctx, "SELECT id FROM entries ORDER BY id LIMIT 1 OFFSET ?", total-maxRows).Scan(&cutID); err == nil {
			n, err := ix.deleteWhere(ctx, "id<?", cutID)
			removed += n
			if err != nil {
				return removed, err
			}
		}
	}
	return removed, nil
}

func (ix *Index) deleteWhere(ctx context.Context, where string, args ...any) (int64, error) {
	tx, err := ix.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Keep the external-content FTS table consistent.
	if _, err := tx.ExecContext(ctx, `INSERT INTO entries_fts(entries_fts,rowid,msg,path,host) SELECT 'delete',id,msg,path,host FROM entries WHERE `+where, args...); err != nil {
		return 0, err
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM entries WHERE "+where, args...)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, tx.Commit()
}

// Query filters entries (newest first).
type Query struct {
	Cat    string
	Text   string // full-text (FTS5 query is built from plain words)
	Route  string
	Host   string
	Status string // "404", "5xx", "4xx"
	Sev    string
	Since  int64
	Until  int64
	Before int64 // id cursor
	After  int64 // id cursor (tail)
	Limit  int
}

var wordRe = regexp.MustCompile(`[\p{L}\p{N}_./:-]+`)

// FTSMatch turns user text into a safe FTS5 expression (quoted terms, AND).
func FTSMatch(s string) string {
	var terms []string
	for _, w := range wordRe.FindAllString(s, 10) {
		terms = append(terms, `"`+strings.ReplaceAll(w, `"`, ``)+`"`)
	}
	return strings.Join(terms, " AND ")
}

// Search runs q against db (an Index.DB or a read-only handle).
func Search(ctx context.Context, db *sql.DB, q Query) ([]Entry, error) {
	where, args := []string{"1=1"}, []any{}
	add := func(c string, a ...any) { where = append(where, c); args = append(args, a...) }
	if q.Cat != "" {
		add("e.cat=?", q.Cat)
	}
	if q.Route != "" {
		add("e.route=?", q.Route)
	}
	if q.Host != "" {
		add("e.host=?", strings.ToLower(q.Host))
	}
	if q.Sev != "" {
		add("e.sev=?", q.Sev)
	}
	switch {
	case q.Status == "":
	case len(q.Status) == 3 && strings.HasSuffix(q.Status, "xx"):
		d := int(q.Status[0] - '0')
		add("e.status>=? AND e.status<?", d*100, d*100+100)
	default:
		var s int
		if _, err := fmt.Sscanf(q.Status, "%d", &s); err == nil {
			add("e.status=?", s)
		}
	}
	if q.Since > 0 {
		add("e.ts>=?", q.Since)
	}
	if q.Until > 0 {
		add("e.ts<=?", q.Until)
	}
	if q.Before > 0 {
		add("e.id<?", q.Before)
	}
	if q.After > 0 {
		add("e.id>?", q.After)
	}
	from := "entries e"
	if m := FTSMatch(q.Text); m != "" {
		from = "entries e JOIN entries_fts f ON f.rowid=e.id"
		add("entries_fts MATCH ?", m)
	}
	lim := q.Limit
	if lim <= 0 || lim > 50000 {
		lim = 200
	}
	order := "DESC"
	if q.After > 0 {
		order = "ASC"
	}
	rows, err := db.QueryContext(ctx, `SELECT e.id,e.ts,e.cat,e.sev,e.src,e.host,e.route,e.status,e.method,e.path,e.ip,e.dur,e.msg FROM `+from+
		` WHERE `+strings.Join(where, " AND ")+` ORDER BY e.id `+order+` LIMIT ?`, append(args, lim)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.TS, &e.Cat, &e.Sev, &e.Source, &e.Host, &e.Route, &e.Status, &e.Method, &e.Path, &e.IP, &e.Dur, &e.Msg); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrNoIndex means the indexer has not created the index yet.
var ErrNoIndex = errors.New("log index not available yet")

// redactQuery removes query strings from URLs/paths inside free text.
var urlQueryRe = regexp.MustCompile(`(\S)\?[^\s"]*`)

// Redact strips query strings and obvious credentials from a message.
func Redact(s string) string {
	s = urlQueryRe.ReplaceAllString(s, "$1?[redacted]")
	s = authRe.ReplaceAllString(s, "${1}[redacted]")
	return s
}

// The auth scheme (Bearer/Basic/…) is consumed together with the credential.
var authRe = regexp.MustCompile(`(?i)((?:proxy-authorization|authorization|cookie|x-api-key|password|token)["']?\s*[:=]\s*)(?:(?:bearer|basic|digest|token|negotiate)\s+)?\S+`)

// StripQuery removes a query string from a path.
func StripQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if u, err := url.PathUnescape(p); err == nil && len(u) < 2048 {
		return u
	}
	return p
}
