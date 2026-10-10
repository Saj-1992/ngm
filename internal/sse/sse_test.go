package sse

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

type frame struct{ id, event, data string }

func readFrames(t *testing.T, resp *http.Response, n int, timeout time.Duration) []frame {
	t.Helper()
	out := make(chan []frame, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		var fs []frame
		var cur frame
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.event != "" {
					fs = append(fs, cur)
					if len(fs) == n {
						out <- fs
						return
					}
				}
				cur = frame{}
			case strings.HasPrefix(line, "id: "):
				cur.id = line[4:]
			case strings.HasPrefix(line, "event: "):
				cur.event = line[7:]
			case strings.HasPrefix(line, "data: "):
				cur.data = line[6:]
			}
		}
		out <- fs
	}()
	select {
	case fs := <-out:
		return fs
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %d frames", n)
		return nil
	}
}

func server(t *testing.T, b *Broker, allow Authorizer) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.Serve(w, r, allow) }))
	t.Cleanup(s.Close)
	return s
}

func get(t *testing.T, url, lastID string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestLiveAndReplay(t *testing.T) {
	ctx := context.Background()
	b := NewBroker(storetest.New(t))
	b.Poll = 50 * time.Millisecond
	for i := 0; i < 3; i++ {
		b.Publish(ctx, "job.updated", "global", map[string]int{"i": i})
	}
	s := server(t, b, nil)
	// Replay from id 1 → receives 2 and 3.
	resp := get(t, s.URL, "1")
	fs := readFrames(t, resp, 2, 3*time.Second)
	if fs[0].id != "2" || fs[1].id != "3" {
		t.Fatalf("replay frames %+v", fs)
	}
	// Live delivery.
	resp2 := get(t, s.URL, "")
	time.Sleep(100 * time.Millisecond)
	b.Publish(ctx, "job.updated", "global", map[string]int{"i": 9})
	fs = readFrames(t, resp2, 1, 3*time.Second)
	if fs[0].id != "4" || !strings.Contains(fs[0].data, `"i":9`) {
		t.Fatalf("live frame %+v", fs)
	}
}

func TestReplayGapSendsResync(t *testing.T) {
	ctx := context.Background()
	b := NewBroker(storetest.New(t))
	b.Retention = 3
	for i := 0; i < 10; i++ {
		b.Publish(ctx, "x", "global", i)
	}
	s := server(t, b, nil)
	fs := readFrames(t, get(t, s.URL, "2"), 1, 3*time.Second)
	if fs[0].event != "resync" {
		t.Fatalf("want resync, got %+v", fs)
	}
	fs = readFrames(t, get(t, s.URL, "999"), 1, 3*time.Second)
	if fs[0].event != "resync" {
		t.Fatalf("ahead-of-server id: want resync, got %+v", fs)
	}
}

func TestScopeFiltering(t *testing.T) {
	ctx := context.Background()
	b := NewBroker(storetest.New(t))
	b.Publish(ctx, "site.updated", "website:A", 1)
	b.Publish(ctx, "site.updated", "website:B", 2)
	b.Publish(ctx, "site.updated", "website:A", 3)
	s := server(t, b, func(scope string) bool { return scope == "website:A" })
	fs := readFrames(t, get(t, s.URL, "0"), 2, 3*time.Second)
	for _, f := range fs {
		if strings.Contains(f.data, "website:B") {
			t.Fatalf("leaked out-of-scope event: %+v", f)
		}
	}
	if fs[0].id != "1" || fs[1].id != "3" {
		t.Fatalf("%+v", fs)
	}
}

func TestRejectsInjectionInType(t *testing.T) {
	b := NewBroker(storetest.New(t))
	if _, err := b.Publish(context.Background(), "x\ndata: evil", "global", 1); err == nil {
		t.Fatal("newline in event type accepted")
	}
}
