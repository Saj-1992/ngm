package httpapi

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/logs"
)

func TestLogsSearchExportTail(t *testing.T) {
	f, ts := setupServer(t)
	p := filepath.Join(t.TempDir(), "index.db")
	ix, err := logs.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ix.Close()
	now := time.Now().UnixMilli()
	ix.Insert(context.Background(), []logs.Entry{
		{TS: now, Cat: "http", Sev: "error", Source: "a", Host: "a.example.com", Status: 502, Path: "=cmd|calc", Msg: "GET /x 502"},
		{TS: now, Cat: "http", Sev: "info", Source: "a", Host: "a.example.com", Status: 200, Path: "/ok", Msg: "GET /ok 200"},
	})
	f.srv.d.LogIndexPath = p
	t.Cleanup(func() {
		if f.srv.logIndex != nil {
			f.srv.logIndex.Close()
		}
	})
	owner, _ := enrolOwner(t, ts)
	r := owner.do("GET", "/api/v1/logs?category=http&status=5xx", nil, nil)
	if r.code != 200 || len(r.body["items"].([]any)) != 1 {
		t.Fatalf("search: %d %v", r.code, r.body)
	}
	if r := owner.do("GET", "/api/v1/logs?category=bogus", nil, nil); r.code != 400 {
		t.Fatalf("bad category: %d", r.code)
	}
	res, err := owner.hc.Get(ts.URL + "/api/v1/logs/export?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "'=cmd|calc") || !strings.Contains(res.Header.Get("Content-Disposition"), ".csv") {
		t.Fatalf("csv export: %d %s", res.StatusCode, body)
	}
	// Tail: a new entry arrives as an SSE event.
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/logs/tail?category=http", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err = owner.hc.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	go func() {
		time.Sleep(300 * time.Millisecond)
		ix.Insert(context.Background(), []logs.Entry{{TS: now, Cat: "http", Sev: "info", Source: "a", Msg: "GET /tail-me 200"}})
	}()
	sc := bufio.NewScanner(res.Body)
	got := false
	for sc.Scan() {
		if strings.Contains(sc.Text(), "tail-me") {
			got = true
			break
		}
	}
	if !got {
		t.Fatal("tail did not deliver the new entry")
	}
}
