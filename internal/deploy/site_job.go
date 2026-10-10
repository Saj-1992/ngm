package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/helper"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
	"github.com/ngm-gateway/ngm/internal/websites"
)

// Website jobs.
const (
	KindSiteBuild   = "website.build"
	KindSitePublish = "website.publish"
	KindSiteDelete  = "website.delete"
)

// SitePayload addresses a website (and a version for publish).
type SitePayload struct {
	WebsiteID string `json:"website_id"`
	VersionID string `json:"version_id,omitempty"`
}

var siteLocks = []locks.Resource{locks.WebsitePublish}

func (c *Coordinator) siteSvc() *websites.Service {
	return &websites.Service{DB: c.DB, Audit: c.Audit, Root: c.WebsitesRoot}
}

func (c *Coordinator) runSiteBuild(r *runner) {
	ctx := r.ctx
	var p SitePayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	if _, err := c.siteSvc().Get(ctx, p.WebsiteID); err != nil {
		r.end(jobs.Blocked, "not_found", nil, &failure{Code: "not_found", Message: "website not found"})
		return
	}
	_ = r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, map[string]string{"note": "builds an immutable version; nothing is published"})
	_ = r.to(jobs.Staging, "build", jobs.Idempotent, nil)
	res, err := c.siteSvc().Build(ctx, p.WebsiteID, r.j.ActorID, r.j.ID)
	if err != nil {
		r.end(jobs.Failed, "build_failed", nil, &failure{Code: "build_failed", Message: err.Error()})
		return
	}
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	_ = r.to(jobs.Applying, "recorded", jobs.Idempotent, map[string]any{"version": res.Version.ID, "reused": res.Reused})
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, map[string]any{"content_hash": res.Version.ContentHash, "size": res.Version.Size})
	r.end(jobs.Succeeded, "succeeded", res, nil)
}

// siteTarget is one way the active configuration serves a website.
type siteTarget struct {
	Route string `json:"route"`
	URL   string `json:"url"`
	Host  string `json:"host"`
	TLS   bool   `json:"tls"`
	addr  string
}

// siteTargets lists routes of the ACTIVE generation that serve the site.
func (c *Coordinator) siteTargets(ctx context.Context, siteID string) ([]siteTarget, error) {
	g, err := c.active(ctx)
	if err != nil || g == nil {
		return nil, err
	}
	if !strings.Contains(g.Files[gateway.FileHTTP], gateway.SiteRoot(siteID)) {
		return nil, nil
	}
	var mj string
	if err := c.DB.QueryRowContext(ctx, `SELECT d.model_json FROM config_generations g JOIN desired_revisions d ON d.id=g.desired_revision_id WHERE g.id=?`, g.ID).Scan(&mj); err != nil {
		return nil, err
	}
	var m gateway.Model
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		return nil, err
	}
	ls := map[string]gateway.Listener{}
	for _, l := range m.Listeners {
		ls[l.ID] = l
	}
	var out []siteTarget
	for _, rt := range m.Routes {
		if !rt.Enabled || rt.DestKind != gateway.DestWebsite || rt.DestID != siteID {
			continue
		}
		l, ok := ls[rt.ListenerID]
		if !ok || !l.Enabled {
			continue
		}
		host, path := "", "/"
		for _, mt := range rt.Matches {
			switch mt.Field {
			case gateway.FieldHost, gateway.FieldSNI:
				if host == "" && !strings.HasPrefix(mt.Value, "*") {
					host = mt.Value
				}
			case gateway.FieldPathPrefix:
				path = mt.Value
			}
		}
		if host == "" {
			host = "localhost"
		}
		a, _ := netip.ParseAddr(l.Address)
		ip := l.Address
		if a.IsUnspecified() {
			ip = "127.0.0.1"
			if a.Is6() {
				ip = "::1"
			}
		}
		tlsOn := l.Kind == gateway.KindHTTPS || l.Kind == gateway.KindStreamTLSFront
		out = append(out, siteTarget{Route: rt.Name, Host: host, TLS: tlsOn, URL: path, addr: net.JoinHostPort(ip, strconv.Itoa(l.Port))})
	}
	return out, nil
}

// fetchIndex requests the site's index through Nginx and returns its sha256.
func fetchIndex(ctx context.Context, t siteTarget) (string, int, error) {
	scheme := "http"
	if t.TLS {
		scheme = "https"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, t.addr)
		},
		// Content, not the certificate, is verified here (deploys verify TLS).
		TLSClientConfig: &tls.Config{ServerName: t.Host, InsecureSkipVerify: true}, //nolint:gosec
	}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+"://"+t.Host+t.URL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	_, _ = io.Copy(h, io.LimitReader(resp.Body, 16<<20))
	return hex.EncodeToString(h.Sum(nil)), resp.StatusCode, nil
}

func manifestIndex(m json.RawMessage) string {
	var files []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	_ = json.Unmarshal(m, &files)
	for _, f := range files {
		if f.Path == "index.html" {
			return f.SHA256
		}
	}
	return ""
}

func (c *Coordinator) runSitePublish(r *runner) {
	ctx := r.ctx
	var p SitePayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	if c.blockedByIncident(r, KindSitePublish, KindSiteDelete) {
		return
	}
	svc := c.siteSvc()
	w, err := svc.Get(ctx, p.WebsiteID)
	if err != nil {
		r.end(jobs.Blocked, "not_found", nil, &failure{Code: "not_found", Message: "website not found"})
		return
	}
	v, err := svc.GetVersion(ctx, p.WebsiteID, p.VersionID)
	if err != nil || v.Status == websites.StatusFailed {
		r.end(jobs.Blocked, "not_found", nil, &failure{Code: "version_not_found", Message: "version not found or failed"})
		return
	}
	var st map[string]any
	if err := c.call(ctx, r, "site.state", helper.SiteArgs{SiteID: p.WebsiteID}, &st); err != nil {
		c.failSafely(r, &failure{Code: "helper", Message: err.Error()})
		return
	}
	prev, _ := st["current"].(string)
	if prev != w.ActiveVersionID && !(prev == "" && w.ActiveVersionID == "") {
		r.end(jobs.Blocked, "drift", nil, &failure{Code: "site_drift", Message: fmt.Sprintf("the public tree serves version %q but NGM records %q; publish again after checking", prev, w.ActiveVersionID)})
		return
	}
	targets, err := c.siteTargets(ctx, p.WebsiteID)
	if err != nil {
		c.failSafely(r, &failure{Code: "internal", Message: err.Error()})
		return
	}
	impact := map[string]any{"from": prev, "to": v.ID, "number": v.Number, "routes": targets, "reload": "none (per-site pointer switch)"}
	if err := r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, impact); err != nil {
		return
	}
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	if err := r.to(jobs.Applying, "apply", jobs.External, map[string]string{"version": v.ID}); err != nil {
		return
	}
	var res map[string]any
	if err := c.call(ctx, r, "site.publish", helper.SiteArgs{SiteID: p.WebsiteID, VersionID: v.ID}, &res); err != nil {
		// The helper switches the pointer only after a complete copy.
		_ = r.to(jobs.Compensating, "publish_failed", jobs.Idempotent, map[string]string{"error": err.Error()})
		c.siteRestore(r, p.WebsiteID, v.ID, prev, &failure{Code: "publish_failed", Message: err.Error()})
		return
	}
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, res)
	want := manifestIndex(v.Manifest)
	ev := map[string]any{"helper": res}
	if got, _ := res["index_sha256"].(string); want != "" && got != want {
		c.siteRestore(r, p.WebsiteID, v.ID, prev, &failure{Code: "verification_failed", Message: "published index.html differs from the build"})
		return
	}
	// Real requests through Nginx for every active route serving the site.
	var checks []map[string]any
	for _, t := range targets {
		ok := false
		var last string
		for i := 0; i < 5 && !ok; i++ {
			sum, code, err := fetchIndex(ctx, t)
			switch {
			case err != nil:
				last = err.Error()
			case code != 200:
				last = fmt.Sprintf("HTTP %d", code)
			case want != "" && sum != want:
				last = "served index.html differs from the build"
			default:
				ok = true
			}
			if !ok {
				time.Sleep(300 * time.Millisecond)
			}
		}
		checks = append(checks, map[string]any{"route": t.Route, "host": t.Host, "path": t.URL, "ok": ok, "error": last})
		if !ok {
			ev["checks"] = checks
			c.siteRestore(r, p.WebsiteID, v.ID, prev, &failure{Code: "verification_failed", Message: "route " + t.Route + ": " + last, Details: ev})
			return
		}
	}
	ev["checks"] = checks
	if len(targets) == 0 {
		ev["note"] = "no active route serves this website yet: verified at file level only"
	}
	if err := svc.MarkPublished(ctx, p.WebsiteID, v.ID); err != nil {
		c.recoveryRequired(r, &failure{Code: "record_failed", Message: err.Error()})
		return
	}
	// Keep the three most recent published copies for instant rollback.
	keep := []string{}
	vs, _ := svc.Versions(ctx, p.WebsiteID)
	for _, x := range vs {
		if (x.Status == websites.StatusPublished || x.Status == websites.StatusSuperseded) && len(keep) < 3 {
			keep = append(keep, x.ID)
		}
	}
	_ = c.call(ctx, r, "site.gc", helper.SiteArgs{SiteID: p.WebsiteID, Keep: keep}, nil)
	keepMap := map[string]bool{}
	for _, k := range keep {
		keepMap[k] = true
	}
	_, _ = svc.Prune(ctx, p.WebsiteID, keepMap)
	if c.Broker != nil {
		_, _ = c.Broker.Publish(ctx, "website.published", "global", map[string]any{"id": p.WebsiteID, "version": v.ID})
	}
	r.end(jobs.Succeeded, "succeeded", ev, nil)
}

// siteRestore switches the pointer back to prev (or removes a first
// publication) and verifies the pointer.
func (c *Coordinator) siteRestore(r *runner, site, failed, prev string, f *failure) {
	ctx := context.WithoutCancel(r.ctx)
	if r.state != jobs.Compensating {
		_ = r.to(jobs.Compensating, "compensate", jobs.External, f)
	}
	var st map[string]any
	if err := c.call(ctx, r, "site.state", helper.SiteArgs{SiteID: site}, &st); err != nil {
		c.recoveryRequired(r, &failure{Code: "site_state_unknown", Message: err.Error()})
		return
	}
	cur, _ := st["current"].(string)
	switch {
	case cur == prev:
		// The pointer never moved.
	case prev == "":
		if err := c.call(ctx, r, "site.remove", helper.SiteArgs{SiteID: site}, nil); err != nil {
			c.recoveryRequired(r, &failure{Code: "compensation_failed", Message: err.Error()})
			return
		}
	default:
		if err := c.call(ctx, r, "site.activate", helper.SiteArgs{SiteID: site, VersionID: prev, Expected: cur}, nil); err != nil {
			c.recoveryRequired(r, &failure{Code: "compensation_failed", Message: "could not switch back to " + prev + ": " + err.Error()})
			return
		}
	}
	r.end(jobs.RolledBack, "rolled_back", map[string]string{"serving": prev}, f)
}

func (c *Coordinator) runSiteDelete(r *runner) {
	ctx := r.ctx
	var p SitePayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	svc := c.siteSvc()
	if _, err := svc.Get(ctx, p.WebsiteID); err != nil {
		r.end(jobs.Blocked, "not_found", nil, &failure{Code: "not_found", Message: "website not found"})
		return
	}
	if used, _ := svc.InUse(ctx, p.WebsiteID); len(used) > 0 {
		r.end(jobs.Blocked, "in_use", nil, &failure{Code: "in_use", Message: "routes still serve this website: " + strings.Join(used, ", ")})
		return
	}
	_ = r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, nil)
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	if err := r.to(jobs.Applying, "remove", jobs.External, nil); err != nil {
		return
	}
	if err := c.call(ctx, r, "site.remove", helper.SiteArgs{SiteID: p.WebsiteID}, nil); err != nil {
		c.recoveryRequired(r, &failure{Code: "remove_failed", Message: err.Error()})
		return
	}
	if err := svc.DeleteRecord(ctx, nil, p.WebsiteID); err != nil {
		c.recoveryRequired(r, &failure{Code: "remove_failed", Message: "published files removed but the record could not be deleted: " + err.Error()})
		return
	}
	_ = r.to(jobs.Verifying, "verify", jobs.Idempotent, nil)
	r.end(jobs.Succeeded, "succeeded", nil, nil)
}
