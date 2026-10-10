// Package cloudflare is NGM's optional Cloudflare DNS integration
// (MASTER_SPEC §6.1): least-privilege API token kept in the vault, change
// preview, explicit confirmation, audit, and preservation of records NGM
// does not manage. NGM marks the records it creates with a comment and only
// ever updates or deletes records carrying that mark (or records the
// operator explicitly adopts). DNS changes are not instant: caches honour
// TTLs and NGM never promises immediate propagation or rollback.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Marker is written into the comment of records NGM manages.
const Marker = "managed-by:ngm"

// APIBase is Cloudflare's v4 API endpoint (overridden in tests).
const APIBase = "https://api.cloudflare.com/client/v4"

// Client talks to the Cloudflare API with a scoped token.
type Client struct {
	Token string
	Base  string
	HTTP  *http.Client
}

// Record is a DNS record as Cloudflare returns it.
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
	// CAA records use structured data.
	Data *CAAData `json:"data,omitempty"`
}

// CAAData is the structured CAA payload.
type CAAData struct {
	Flags int    `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// Managed reports whether NGM owns the record.
func (r Record) Managed() bool { return strings.Contains(r.Comment, Marker) }

// Value is the normalised comparable value.
func (r Record) Value() string {
	if r.Type == "CAA" && r.Data != nil {
		return fmt.Sprintf("%d %s %q", r.Data.Flags, strings.ToLower(r.Data.Tag), r.Data.Value)
	}
	if r.Type == "CNAME" {
		return strings.ToLower(strings.TrimSuffix(r.Content, "."))
	}
	return r.Content
}

// APIError is a Cloudflare error (messages are safe to show; the token never
// appears in them).
type APIError struct {
	Status int
	Msgs   []string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare API %d: %s", e.Status, strings.Join(e.Msgs, "; "))
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	base := c.Base
	if base == "" {
		base = APIBase
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// Never wrap the request (it carries the token) into the error.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("cloudflare API unreachable: %v", ue.Err)
		}
		return errors.New("cloudflare API unreachable")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var env struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return &APIError{Status: resp.StatusCode, Msgs: []string{"unexpected response"}}
	}
	if !env.Success || resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Msgs = append(e.Msgs, m.Message)
		}
		return e
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Verify checks that the token is active.
func (c *Client) Verify(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, "GET", "/user/tokens/verify", nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return fmt.Errorf("token status %q", r.Status)
	}
	return nil
}

// Zone is a Cloudflare zone.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// FindZone finds the zone containing fqdn (longest matching zone name).
func (c *Client) FindZone(ctx context.Context, fqdn string) (*Zone, error) {
	labels := strings.Split(fqdn, ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zs []Zone
		if err := c.do(ctx, "GET", "/zones?name="+url.QueryEscape(name), nil, &zs); err != nil {
			return nil, err
		}
		if len(zs) == 1 {
			return &zs[0], nil
		}
	}
	return nil, fmt.Errorf("no Cloudflare zone accessible with this token contains %s", fqdn)
}

// Records lists the zone's records of the given names (all types).
func (c *Client) Records(ctx context.Context, zoneID string) ([]Record, error) {
	var all []Record
	for page := 1; page <= 50; page++ {
		var rs []Record
		if err := c.do(ctx, "GET", fmt.Sprintf("/zones/%s/dns_records?per_page=500&page=%d", url.PathEscape(zoneID), page), nil, &rs); err != nil {
			return nil, err
		}
		all = append(all, rs...)
		if len(rs) < 500 {
			break
		}
	}
	return all, nil
}

// Desired is one record NGM should ensure.
type Desired struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"` // 1 = automatic
}

// Change is one planned change.
type Change struct {
	Action  string  `json:"action"` // create | update | conflict | unchanged
	Desired Desired `json:"desired"`
	Current *Record `json:"current,omitempty"`
	Reason  string  `json:"reason,omitempty"`
}

// Plan is a previewed set of changes; Hash binds an apply to this preview.
type Plan struct {
	ZoneID   string   `json:"zone_id"`
	ZoneName string   `json:"zone_name"`
	Changes  []Change `json:"changes"`
	External int      `json:"external_records_untouched"`
	Hash     string   `json:"hash"`
}

func toRecord(d Desired) (Record, error) {
	r := Record{Type: d.Type, Name: d.Name, TTL: d.TTL, Comment: Marker}
	if r.TTL == 0 {
		r.TTL = 1
	}
	switch d.Type {
	case "A", "AAAA", "CNAME", "TXT":
		r.Content = d.Value
		if d.Type != "TXT" {
			f := false
			r.Proxied = &f // the gateway must receive client traffic directly
		}
	case "CAA":
		f := strings.SplitN(d.Value, " ", 3)
		if len(f) != 3 {
			return r, fmt.Errorf("bad CAA value %q", d.Value)
		}
		flags := 0
		if f[0] == "128" {
			flags = 128
		}
		r.Data = &CAAData{Flags: flags, Tag: strings.ToLower(f[1]), Value: strings.Trim(f[2], `"`)}
	default:
		return r, fmt.Errorf("record type %s is not managed through Cloudflare by NGM", d.Type)
	}
	return r, nil
}

// MakePlan compares desired records with the zone. Records are matched by
// (name, type, value); a name/type that exists only with other values is
// updated when NGM manages it and reported as a conflict otherwise.
func MakePlan(zone *Zone, current []Record, desired []Desired) (*Plan, error) {
	p := &Plan{ZoneID: zone.ID, ZoneName: zone.Name, Changes: []Change{}}
	used := map[string]bool{}
	for _, d := range desired {
		want, err := toRecord(d)
		if err != nil {
			return nil, err
		}
		var same, managedOther, externalOther *Record
		for i := range current {
			c := &current[i]
			if !strings.EqualFold(c.Name, d.Name) || c.Type != d.Type || used[c.ID] {
				continue
			}
			switch {
			case c.Value() == want.Value():
				same = c
			case c.Managed() && managedOther == nil:
				managedOther = c
			case externalOther == nil:
				externalOther = c
			}
		}
		switch {
		case same != nil:
			used[same.ID] = true
			p.Changes = append(p.Changes, Change{Action: "unchanged", Desired: d, Current: same})
		case managedOther != nil:
			used[managedOther.ID] = true
			p.Changes = append(p.Changes, Change{Action: "update", Desired: d, Current: managedOther, Reason: "NGM-managed record has another value"})
		case externalOther != nil && (d.Type == "CNAME" || d.Type == "A" || d.Type == "AAAA"):
			used[externalOther.ID] = true
			p.Changes = append(p.Changes, Change{Action: "conflict", Desired: d, Current: externalOther,
				Reason: "an existing record not managed by NGM has another value; NGM will not change it unless you adopt it"})
		default:
			p.Changes = append(p.Changes, Change{Action: "create", Desired: d})
		}
	}
	for _, c := range current {
		if !used[c.ID] && !c.Managed() {
			p.External++
		}
	}
	sort.SliceStable(p.Changes, func(i, j int) bool {
		return p.Changes[i].Desired.Name+p.Changes[i].Desired.Type < p.Changes[j].Desired.Name+p.Changes[j].Desired.Type
	})
	b, _ := json.Marshal(struct {
		Z string
		C []Change
	}{p.ZoneID, p.Changes})
	h := sha256.Sum256(b)
	p.Hash = hex.EncodeToString(h[:16])
	return p, nil
}

// Applied is the outcome of one change.
type Applied struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Apply executes the plan. adopt lists record ids of conflicts the operator
// explicitly allowed NGM to take over (they are then marked as managed).
func (c *Client) Apply(ctx context.Context, p *Plan, adopt map[string]bool) ([]Applied, error) {
	var out []Applied
	var failed bool
	for _, ch := range p.Changes {
		want, err := toRecord(ch.Desired)
		if err != nil {
			return out, err
		}
		a := Applied{Action: ch.Action, Name: ch.Desired.Name, Type: ch.Desired.Type}
		switch ch.Action {
		case "unchanged":
			continue
		case "conflict":
			if !adopt[ch.Current.ID] {
				a.Action = "skipped_conflict"
				out = append(out, a)
				continue
			}
			a.Action = "adopt"
			fallthrough
		case "update":
			var r Record
			err = c.do(ctx, "PUT", fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(p.ZoneID), url.PathEscape(ch.Current.ID)), want, &r)
			a.ID = ch.Current.ID
		case "create":
			var r Record
			err = c.do(ctx, "POST", fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(p.ZoneID)), want, &r)
			a.ID = r.ID
		}
		if err != nil {
			a.Error = err.Error()
			failed = true
		}
		out = append(out, a)
	}
	if failed {
		return out, errors.New("some DNS changes failed (see results); DNS is not transactional: applied changes remain")
	}
	return out, nil
}

// Drift lists NGM-managed records whose provider value no longer matches
// what NGM desires (changed or removed outside NGM).
func Drift(current []Record, desired []Desired) []string {
	var out []string
	for _, d := range desired {
		want, err := toRecord(d)
		if err != nil {
			continue
		}
		found, managedSeen := false, false
		for _, c := range current {
			if strings.EqualFold(c.Name, d.Name) && c.Type == d.Type {
				if c.Value() == want.Value() {
					found = true
				}
				if c.Managed() {
					managedSeen = true
				}
			}
		}
		if !found && managedSeen {
			out = append(out, fmt.Sprintf("%s %s changed outside NGM (expected %s)", d.Name, d.Type, d.Value))
		}
	}
	return out
}

// Zones lists every zone the token can access (paginated), sorted by name.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var all []Zone
	for page := 1; page <= 50; page++ {
		var zs []Zone
		if err := c.do(ctx, "GET", fmt.Sprintf("/zones?per_page=50&page=%d", page), nil, &zs); err != nil {
			return nil, err
		}
		all = append(all, zs...)
		if len(zs) < 50 {
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	return all, nil
}

// UpsertTXT creates or updates a TXT record (used for ACME DNS-01). It marks
// the record as NGM-managed and returns its id.
func (c *Client) UpsertTXT(ctx context.Context, zoneID, name, value string) (string, error) {
	recs, err := c.Records(ctx, zoneID)
	if err != nil {
		return "", err
	}
	body := Record{Type: "TXT", Name: name, Content: value, TTL: 60, Comment: Marker + " acme-dns01"}
	for _, r := range recs {
		if r.Type == "TXT" && strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(name, ".")) && r.Content == value {
			return r.ID, nil // already present
		}
	}
	var out Record
	if err := c.do(ctx, "POST", fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID)), body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// DeleteRecord removes a record by id (NGM-created challenge cleanup).
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(recordID)), nil, nil)
}

var labelAlphabet = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

// GenerateLabel returns a random DNS label of n characters (a–z0–9, first
// character a letter). It is used for automatic subdomain naming; the caller
// checks for collisions against the zone's existing records.
func GenerateLabel(n int, randByte func() byte) string {
	if n < 2 {
		n = 2
	}
	b := make([]byte, n)
	b[0] = labelAlphabet[int(randByte())%26]
	for i := 1; i < n; i++ {
		b[i] = labelAlphabet[int(randByte())%len(labelAlphabet)]
	}
	return string(b)
}

// LabelTaken reports whether any record exists at fqdn (case-insensitive).
func LabelTaken(records []Record, fqdn string) bool {
	f := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	for _, r := range records {
		if strings.ToLower(strings.TrimSuffix(r.Name, ".")) == f {
			return true
		}
	}
	return false
}
