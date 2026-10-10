package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newIndex(t *testing.T) *Index {
	ix, err := Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ix.Close() })
	return ix
}

const httpLine1 = `{"t":"2026-10-08T10:00:00+00:00","c":"http","port":"80","host":"A.Example.com","sni":"","route":"R1","m":"GET","p":"/api/x","s":"502","b":"0","rt":"0.012","up":"127.0.0.1:9101","us":"502","urt":"0.010","ip":"203.0.113.5","tls":""}`

func TestParsersRedact(t *testing.T) {
	e, ok := Parse(Source{Kind: "http", Path: "a"}, httpLine1)
	if !ok || e.Status != 502 || e.Sev != "error" || e.Host != "a.example.com" || e.Route != "R1" || e.Path != "/api/x" || e.Dur != 0.012 {
		t.Fatalf("%+v", e)
	}
	// Error log: query strings and credentials never reach the index.
	el := `2026/10/08 10:00:01 [error] 123#123: *45 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.5, server: a.example.com, request: "GET /login?token=SECRET123&x=1 HTTP/1.1", upstream: "http://127.0.0.1:9101/login?token=SECRET123", host: "a.example.com"`
	e, ok = Parse(Source{Kind: "error"}, el)
	if !ok || e.Sev != "error" || e.IP != "203.0.113.5" || e.Path != "/login" || strings.Contains(e.Msg, "SECRET123") || e.Host != "a.example.com" {
		t.Fatalf("%+v", e)
	}
	// App log: sensitive keys dropped.
	e, ok = Parse(Source{Kind: "app", Cat: "api"}, `{"time":"2026-10-08T10:00:02Z","level":"WARN","msg":"login failed","user":"bob","password":"hunter2","authorization":"Bearer x"}`)
	if !ok || e.Cat != "api" || e.Sev != "warn" || strings.Contains(e.Msg, "hunter2") || strings.Contains(e.Msg, "Bearer") || !strings.Contains(e.Msg, `user="bob"`) {
		t.Fatalf("%+v", e)
	}
	if _, ok := Parse(Source{Kind: "http"}, "not json"); ok {
		t.Fatal("garbage parsed")
	}
	if got := Redact(`Authorization: Bearer abc.def cookie=sess123`); strings.Contains(got, "abc.def") || strings.Contains(got, "sess123") {
		t.Fatal(got)
	}
}

func TestCollectorPartialTruncationAndSearch(t *testing.T) {
	ctx := context.Background()
	ix := newIndex(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "access.jsonl")
	os.WriteFile(p, []byte(httpLine1+"\n"+strings.Replace(httpLine1, `"s":"502"`, `"s":"200"`, 1)+"\n"+`{"t":"2026-10-08T10:00:03`), 0o644)
	c := &Collector{Ix: ix, Sources: []Source{{Path: p, Kind: "http"}}}
	sts, n, _ := c.Pass(ctx)
	if n != 2 || sts[0].LagByte == 0 {
		t.Fatalf("partial line must wait: n=%d %+v", n, sts)
	}
	// The line completes later → indexed exactly once.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`+00:00","c":"http","host":"b.example.com","m":"POST","p":"/upload","s":"404"}` + "\n")
	f.Close()
	if _, n, _ := c.Pass(ctx); n != 1 {
		t.Fatalf("completed line: %d", n)
	}
	if _, n, _ := c.Pass(ctx); n != 0 {
		t.Fatal("re-read lines")
	}
	// Truncation restarts at 0.
	os.WriteFile(p, []byte(strings.Replace(httpLine1, "/api/x", "/after-truncate", 1)+"\n"), 0o644)
	if _, n, _ := c.Pass(ctx); n != 1 {
		t.Fatalf("after truncation: %d", n)
	}
	all, _ := Search(ctx, ix.DB, Query{})
	if len(all) != 4 {
		t.Fatalf("total %d", len(all))
	}
	if r, _ := Search(ctx, ix.DB, Query{Status: "5xx"}); len(r) != 2 {
		t.Fatalf("5xx %d", len(r))
	}
	if r, _ := Search(ctx, ix.DB, Query{Text: "upload"}); len(r) != 1 || r[0].Status != 404 {
		t.Fatalf("fts %+v", r)
	}
	if r, _ := Search(ctx, ix.DB, Query{Text: `") OR 1=1 --`}); len(r) != 0 {
		t.Fatalf("fts injection %d", len(r))
	}
	if r, _ := Search(ctx, ix.DB, Query{Host: "B.example.com"}); len(r) != 1 {
		t.Fatal("host filter")
	}
	// Tail cursor returns only newer entries in order.
	if r, _ := Search(ctx, ix.DB, Query{After: all[2].ID}); len(r) != 2 || r[0].ID > r[1].ID {
		t.Fatalf("tail %+v", r)
	}
}

func TestPruneRetentionAndBudget(t *testing.T) {
	ctx := context.Background()
	ix := newIndex(t)
	now := time.Now()
	ix.Insert(ctx, []Entry{
		{TS: now.Add(-8 * 24 * time.Hour).UnixMilli(), Cat: "http", Source: "x", Msg: "old access"},
		{TS: now.Add(-8 * 24 * time.Hour).UnixMilli(), Cat: "error", Source: "x", Msg: "old error kept 30d"},
		{TS: now.UnixMilli(), Cat: "http", Source: "x", Msg: "new a"},
		{TS: now.UnixMilli(), Cat: "http", Source: "x", Msg: "new b"},
	})
	n, err := ix.Prune(ctx, now, 0)
	if err != nil || n != 1 {
		t.Fatalf("retention removed %d %v", n, err)
	}
	if r, _ := Search(ctx, ix.DB, Query{Text: "old access"}); len(r) != 0 {
		t.Fatal("FTS still finds a pruned row")
	}
	if n, _ := ix.Prune(ctx, now, 2); n != 1 {
		t.Fatalf("budget removed %d", n)
	}
}

func TestCorruptIndexIsRebuilt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "index.db")
	os.WriteFile(p, []byte("this is not a database at all, definitely not sqlite"), 0o644)
	ix, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ix.Close()
	if err := ix.Insert(context.Background(), []Entry{{TS: 1, Cat: "http", Source: "x", Msg: "ok"}}); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(p + ".corrupt-*")
	if len(m) == 0 {
		t.Fatal("corrupt index not kept aside")
	}
}
