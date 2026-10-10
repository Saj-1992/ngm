package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

// Target is a notification destination (secret never included).
type Target struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"` // telegram | webhook
	ChatID    string    `json:"chat_id,omitempty"`
	URL       string    `json:"url,omitempty"`
	MinSev    string    `json:"min_severity"`
	Enabled   bool      `json:"enabled"`
	HasSecret bool      `json:"has_secret"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}

// Delivery is one notification attempt record.
type Delivery struct {
	ID        string     `json:"id"`
	TargetID  string     `json:"target_id"`
	AlertID   string     `json:"alert_id,omitempty"`
	Event     string     `json:"event"`
	Status    string     `json:"status"`
	Attempts  int        `json:"attempts"`
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	SentAt    *time.Time `json:"sent_at,omitempty"`
}

// Notifier manages targets and deliveries.
type Notifier struct {
	DB    *store.DB
	Vault *vault.Vault
	HTTP  *http.Client
	// TelegramBase overrides https://api.telegram.org (tests).
	TelegramBase string
	// AllowPrivate disables the public-address check (tests only).
	AllowPrivate bool
	Host         string
}

// ValidationError is a client-safe problem.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{fmt.Sprintf(f, a...)} }

func secretRef(id string) vault.Ref {
	return vault.Ref{Type: "notification", Scope: "target:" + id, Name: "secret"}
}

var (
	tgTokenRe = regexp.MustCompile(`^\d{5,15}:[A-Za-z0-9_-]{30,64}$`)
	tgChatRe  = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$`)
	sevs      = map[string]bool{"info": true, "warning": true, "critical": true}
)

// TargetInput creates or replaces a target.
type TargetInput struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	ChatID  string `json:"chat_id"`
	URL     string `json:"url"`
	Secret  string `json:"secret"` // telegram bot token / webhook HMAC key
	MinSev  string `json:"min_severity"`
	Enabled bool   `json:"enabled"`
}

// Create stores a target; the secret goes to the vault.
func (n *Notifier) Create(ctx context.Context, in TargetInput) (*Target, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return nil, invalid("name must be 1–64 characters")
	}
	if in.MinSev == "" {
		in.MinSev = "warning"
	}
	if !sevs[in.MinSev] {
		return nil, invalid("min_severity must be info, warning or critical")
	}
	cfg := map[string]string{"min_severity": in.MinSev}
	switch in.Kind {
	case "telegram":
		if !tgTokenRe.MatchString(in.Secret) {
			return nil, invalid("this does not look like a Telegram bot token")
		}
		if !tgChatRe.MatchString(in.ChatID) {
			return nil, invalid("chat id must be a number or @channel")
		}
		cfg["chat_id"] = in.ChatID
	case "webhook":
		if err := checkWebhookURL(in.URL, n.AllowPrivate); err != nil {
			return nil, err
		}
		if in.Secret != "" && (len(in.Secret) < 16 || len(in.Secret) > 256) {
			return nil, invalid("webhook signing secret must be 16–256 characters")
		}
		cfg["url"] = in.URL
	default:
		return nil, invalid("kind must be telegram or webhook")
	}
	cj, _ := json.Marshal(cfg)
	id := ids.New()
	now := store.FormatTime(time.Now())
	err := n.DB.Tx(ctx, func(tx *sql.Tx) error {
		var sid any
		if in.Secret != "" {
			s, err := n.Vault.PutTx(ctx, tx, secretRef(id), []byte(in.Secret))
			if err != nil {
				return err
			}
			sid = s
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO notification_targets(id,name,kind,secret_id,config_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
			id, in.Name, in.Kind, sid, string(cj), b2i(in.Enabled), now, now)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return invalid("a target with this name exists")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return n.Get(ctx, id)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func checkWebhookURL(s string, allowPrivate bool) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(s) > 2000 {
		return invalid("webhook URL must be an https:// URL without credentials")
	}
	// Early, user-visible rejection of obvious internal targets. The dialer
	// re-checks every resolved address (DNS rebinding), so this is not the
	// only line of defense.
	h := strings.ToLower(u.Hostname())
	if !allowPrivate {
		if a, err := netip.ParseAddr(h); err == nil && !publicOnly(a.Unmap()) {
			return invalid("webhook URL must point to a public address")
		}
		if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
			return invalid("webhook URL must point to a public address")
		}
	}
	return nil
}

// ErrNotFound is returned for unknown targets.
var ErrTargetNotFound = errors.New("notification target not found")

// List returns all targets.
func (n *Notifier) List(ctx context.Context) ([]*Target, error) {
	rows, err := n.DB.QueryContext(ctx, "SELECT id,name,kind,config_json,enabled,secret_id IS NOT NULL,revision,created_at FROM notification_targets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var cj, c string
	var en, hs int
	if err := sc.Scan(&t.ID, &t.Name, &t.Kind, &cj, &en, &hs, &t.Revision, &c); err != nil {
		return nil, err
	}
	var cfg map[string]string
	_ = json.Unmarshal([]byte(cj), &cfg)
	t.ChatID, t.URL, t.MinSev = cfg["chat_id"], cfg["url"], cfg["min_severity"]
	t.Enabled, t.HasSecret = en == 1, hs == 1
	t.CreatedAt, _ = store.ParseTime(c)
	return &t, nil
}

// Get returns one target.
func (n *Notifier) Get(ctx context.Context, id string) (*Target, error) {
	t, err := scanTarget(n.DB.QueryRowContext(ctx, "SELECT id,name,kind,config_json,enabled,secret_id IS NOT NULL,revision,created_at FROM notification_targets WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTargetNotFound
	}
	return t, err
}

// SetEnabled toggles a target.
func (n *Notifier) SetEnabled(ctx context.Context, id string, on bool) error {
	r, err := n.DB.ExecContext(ctx, "UPDATE notification_targets SET enabled=?, revision=revision+1, updated_at=? WHERE id=?", b2i(on), store.FormatTime(time.Now()), id)
	if err != nil {
		return err
	}
	if k, _ := r.RowsAffected(); k != 1 {
		return ErrTargetNotFound
	}
	return nil
}

// Delete removes a target and its secret.
func (n *Notifier) Delete(ctx context.Context, id string) error {
	return n.DB.Tx(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, "DELETE FROM notification_targets WHERE id=?", id)
		if err != nil {
			return err
		}
		if k, _ := r.RowsAffected(); k != 1 {
			return ErrTargetNotFound
		}
		return n.Vault.DeleteTx(ctx, tx, secretRef(id))
	})
}

// Enqueue creates deliveries for transitions (respecting min severity).
func (n *Notifier) Enqueue(ctx context.Context, trs []Transition) (int, error) {
	if len(trs) == 0 {
		return 0, nil
	}
	ts, err := n.List(ctx)
	if err != nil {
		return 0, err
	}
	k := 0
	now := store.FormatTime(time.Now())
	for _, tr := range trs {
		pj, _ := json.Marshal(map[string]any{"event": tr.Event, "alert": tr.Alert, "text": Text(tr, n.Host)})
		for _, t := range ts {
			if !t.Enabled || sevRank(tr.Alert.Severity) < sevRank(t.MinSev) {
				continue
			}
			if _, err := n.DB.ExecContext(ctx, "INSERT INTO notification_deliveries(id,target_id,alert_id,event,status,next_at,payload_json,created_at) VALUES(?,?,?,?,'pending',?,?,?)",
				ids.New(), t.ID, tr.Alert.ID, tr.Event, now, string(pj), now); err != nil {
				return k, err
			}
			k++
		}
	}
	return k, nil
}

// Test queues a test message for one target.
func (n *Notifier) Test(ctx context.Context, id string) (string, error) {
	if _, err := n.Get(ctx, id); err != nil {
		return "", err
	}
	did := ids.New()
	now := store.FormatTime(time.Now())
	pj, _ := json.Marshal(map[string]any{"event": "test", "text": "✅ NGM test notification from " + n.Host})
	_, err := n.DB.ExecContext(ctx, "INSERT INTO notification_deliveries(id,target_id,event,status,next_at,payload_json,created_at) VALUES(?,?,'test','pending',?,?,?)", did, id, now, string(pj), now)
	return did, err
}

// Deliveries lists recent attempts.
func (n *Notifier) Deliveries(ctx context.Context, limit int) ([]Delivery, error) {
	rows, err := n.DB.QueryContext(ctx, "SELECT id,target_id,COALESCE(alert_id,''),event,status,attempts,last_error,created_at,COALESCE(sent_at,'') FROM notification_deliveries ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var c, s string
		if err := rows.Scan(&d.ID, &d.TargetID, &d.AlertID, &d.Event, &d.Status, &d.Attempts, &d.LastError, &c, &s); err != nil {
			return nil, err
		}
		d.CreatedAt, _ = store.ParseTime(c)
		if s != "" {
			t, _ := store.ParseTime(s)
			d.SentAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Backoff schedule; after the last step a delivery is marked failed.
var Backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour}

// RatePerHour limits sends per target.
const RatePerHour = 30

// Run sends due deliveries once.
func (n *Notifier) Run(ctx context.Context, now time.Time) (sent, failed int, err error) {
	rows, err := n.DB.QueryContext(ctx, "SELECT id,target_id,attempts,payload_json FROM notification_deliveries WHERE status='pending' AND next_at<=? ORDER BY created_at LIMIT 50", store.FormatTime(now))
	if err != nil {
		return 0, 0, err
	}
	type due struct {
		id, target, payload string
		attempts            int
	}
	var ds []due
	for rows.Next() {
		var d due
		if rows.Scan(&d.id, &d.target, &d.attempts, &d.payload) == nil {
			ds = append(ds, d)
		}
	}
	rows.Close()
	for _, d := range ds {
		t, err := n.Get(ctx, d.target)
		if err != nil {
			continue
		}
		var recent int
		_ = n.DB.QueryRowContext(ctx, "SELECT count(*) FROM notification_deliveries WHERE target_id=? AND status='sent' AND sent_at>?", d.target, store.FormatTime(now.Add(-time.Hour))).Scan(&recent)
		if recent >= RatePerHour {
			_, _ = n.DB.ExecContext(ctx, "UPDATE notification_deliveries SET status='rate_limited', last_error=? WHERE id=?", fmt.Sprintf("more than %d notifications per hour to this target", RatePerHour), d.id)
			continue
		}
		var p struct {
			Text  string `json:"text"`
			Event string `json:"event"`
		}
		_ = json.Unmarshal([]byte(d.payload), &p)
		serr := n.send(ctx, t, p.Text, []byte(d.payload))
		if serr == nil {
			sent++
			_, _ = n.DB.ExecContext(ctx, "UPDATE notification_deliveries SET status='sent', attempts=attempts+1, sent_at=?, last_error='' WHERE id=?", store.FormatTime(now), d.id)
			continue
		}
		msg := serr.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if d.attempts >= len(Backoff) {
			failed++
			_, _ = n.DB.ExecContext(ctx, "UPDATE notification_deliveries SET status='failed', attempts=attempts+1, last_error=? WHERE id=?", msg, d.id)
		} else {
			_, _ = n.DB.ExecContext(ctx, "UPDATE notification_deliveries SET attempts=attempts+1, last_error=?, next_at=? WHERE id=?", msg, store.FormatTime(now.Add(Backoff[d.attempts])), d.id)
		}
	}
	_, _ = n.DB.ExecContext(ctx, "DELETE FROM notification_deliveries WHERE created_at<?", store.FormatTime(now.Add(-30*24*time.Hour)))
	return sent, failed, nil
}

// publicOnly refuses non-public destinations (SSRF guard for webhooks).
func publicOnly(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func (n *Notifier) client() *http.Client {
	if n.HTTP != nil {
		return n.HTTP
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %v", host, err)
			}
			for _, ip := range ips {
				if !n.AllowPrivate && !publicOnly(ip) {
					return nil, fmt.Errorf("refusing non-public address %s for %s", ip, host)
				}
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (n *Notifier) send(ctx context.Context, t *Target, text string, payload []byte) error {
	var secret []byte
	if t.HasSecret {
		s, err := n.Vault.Get(ctx, secretRef(t.ID))
		if err != nil {
			return errors.New("target secret unavailable")
		}
		secret = s
		defer clear(secret)
	}
	var req *http.Request
	var err error
	switch t.Kind {
	case "telegram":
		base := n.TelegramBase
		if base == "" {
			base = "https://api.telegram.org"
		}
		body, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": text, "disable_web_page_preview": true})
		req, err = http.NewRequestWithContext(ctx, "POST", base+"/bot"+string(secret)+"/sendMessage", bytes.NewReader(body))
	case "webhook":
		req, err = http.NewRequestWithContext(ctx, "POST", t.URL, bytes.NewReader(payload))
		if err == nil && len(secret) > 0 {
			m := hmac.New(sha256.New, secret)
			m.Write(payload)
			req.Header.Set("X-NGM-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
		}
	default:
		return errors.New("unknown target kind")
	}
	if err != nil {
		return errors.New("cannot build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ngm-notify")
	resp, err := n.client().Do(req)
	if err != nil {
		// Never include the URL (the Telegram URL carries the bot token).
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("send failed: %v", ue.Err)
		}
		return errors.New("send failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.ReplaceAll(string(b), string(secret), "[redacted]"))
	}
	return nil
}
