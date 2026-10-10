// Package sse provides Server-Sent Events backed by the durable `events`
// table (MASTER_SPEC §12). SQLite is the source of truth; SSE only notifies.
//
// Events published by other processes (ngm-ops, ngm-monitor) are picked up by
// polling, so the API process does not need an in-memory channel from them.
// Each subscriber reads from the table at its own pace, which gives natural
// backpressure: a slow client never blocks publishers, and a client that falls
// behind the retention window receives `event: resync`.
package sse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ngm-gateway/ngm/internal/store"
)

// Event is one notification.
type Event struct {
	Seq   int64           `json:"seq"`
	Type  string          `json:"type"`
	Scope string          `json:"scope"`
	At    time.Time       `json:"at"`
	Data  json.RawMessage `json:"data"`
}

// Broker publishes and serves events.
type Broker struct {
	db        *store.DB
	mu        sync.Mutex
	subs      map[chan struct{}]struct{}
	Retention int           // max events retained (default 10000)
	Heartbeat time.Duration // default 15s
	Poll      time.Duration // default 1s (cross-process pickup)
	Batch     int           // max events per DB read (default 200)
}

// NewBroker returns a Broker.
func NewBroker(db *store.DB) *Broker {
	return &Broker{db: db, subs: map[chan struct{}]struct{}{}, Retention: 10000, Heartbeat: 15 * time.Second, Poll: time.Second, Batch: 200}
}

// Publish appends an event and wakes local subscribers. data must not contain secrets.
func (b *Broker) Publish(ctx context.Context, typ, scope string, data any) (int64, error) {
	if typ == "" || strings.ContainsAny(typ, "\r\n") {
		return 0, fmt.Errorf("invalid event type %q", typ)
	}
	if scope == "" {
		scope = "global"
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	var seq int64
	err = b.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "INSERT INTO events(type,scope,at,data_json) VALUES(?,?,?,?) RETURNING seq",
			typ, scope, store.FormatTime(time.Now()), string(raw)).Scan(&seq); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM events WHERE seq <= ?", seq-int64(b.Retention))
		return err
	})
	if err != nil {
		return 0, err
	}
	b.wake()
	return seq, nil
}

func (b *Broker) wake() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (b *Broker) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) unsubscribe(ch chan struct{}) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

// bounds returns the min and max retained seq (0,0 if empty).
func (b *Broker) bounds(ctx context.Context) (lo, hi int64, err error) {
	var l, h sql.NullInt64
	err = b.db.QueryRowContext(ctx, "SELECT MIN(seq), MAX(seq) FROM events").Scan(&l, &h)
	return l.Int64, h.Int64, err
}

func (b *Broker) after(ctx context.Context, seq int64) ([]Event, error) {
	rows, err := b.db.QueryContext(ctx, "SELECT seq,type,scope,at,data_json FROM events WHERE seq > ? ORDER BY seq LIMIT ?", seq, b.Batch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, data string
		if err := rows.Scan(&e.Seq, &e.Type, &e.Scope, &at, &data); err != nil {
			return nil, err
		}
		e.At, _ = store.ParseTime(at)
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Authorizer decides whether the subscriber may see events of a scope.
// It is evaluated per event so permission changes apply without reconnect
// once the session layer re-evaluates (Phase 2).
type Authorizer func(scope string) bool

// Serve streams events to w until the client disconnects or ctx ends.
func (b *Broker) Serve(w http.ResponseWriter, r *http.Request, allow Authorizer) {
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // disable nginx proxy buffering for this response
	ctx := r.Context()

	lo, hi, err := b.bounds(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	cursor := hi // default: only new events
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if last, err := strconv.ParseInt(v, 10, 64); err == nil && last >= 0 {
			switch {
			case last > hi:
				// Client is ahead of us (e.g. DB restored): force resync.
				b.writeResync(w, hi)
			case lo > 0 && last < lo-1:
				// Requested events were pruned: replay gap.
				b.writeResync(w, hi)
			default:
				cursor = last
			}
		} else {
			b.writeResync(w, hi)
		}
	}
	fmt.Fprintf(w, "retry: 3000\n\n")
	if err := rc.Flush(); err != nil {
		return
	}

	ch := b.subscribe()
	defer b.unsubscribe(ch)
	hb := time.NewTicker(b.Heartbeat)
	defer hb.Stop()
	poll := time.NewTicker(b.Poll)
	defer poll.Stop()

	for {
		// Drain everything available.
		for {
			evs, err := b.after(ctx, cursor)
			if err != nil {
				return
			}
			if len(evs) > 0 && evs[0].Seq > cursor+1 && cursor > 0 {
				// Pruned while we were behind.
				b.writeResync(w, evs[len(evs)-1].Seq)
			}
			for _, e := range evs {
				cursor = e.Seq
				if allow != nil && !allow(e.Scope) {
					continue
				}
				_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
				payload, _ := json.Marshal(e)
				if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Type, payload); err != nil {
					return
				}
			}
			if len(evs) > 0 {
				if err := rc.Flush(); err != nil {
					return
				}
			}
			if len(evs) < b.Batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ch:
		case <-poll.C:
		case <-hb.C:
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

func (b *Broker) writeResync(w http.ResponseWriter, hi int64) {
	fmt.Fprintf(w, "id: %d\nevent: resync\ndata: {\"reason\":\"replay_gap\"}\n\n", hi)
}
