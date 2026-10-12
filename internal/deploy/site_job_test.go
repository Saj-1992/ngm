package deploy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/websites"
)

func siteEnv(t *testing.T) (*env, *websites.Service, string) {
	e := newEnv(t)
	e.c.WebsitesRoot = t.TempDir()
	svc := e.c.siteSvc()
	w, err := svc.Create(context.Background(), nil, "Shop", "template", "corporate", "fa", []string{"fa", "en"})
	if err != nil {
		t.Fatal(err)
	}
	return e, svc, w.ID
}

func buildVersion(t *testing.T, e *env, site string) *websites.Version {
	j := e.submit(t, KindSiteBuild, SitePayload{WebsiteID: site})
	if j.State != jobs.Succeeded {
		t.Fatalf("build: %s %s", j.State, j.Error)
	}
	var res websites.BuildResult
	json.Unmarshal(j.Result, &res)
	// The fake helper "copies" correctly: index sha equals the manifest.
	if e.h.siteIndex == nil {
		e.h.siteIndex = map[string]string{}
	}
	e.h.siteIndex[res.Version.ID] = manifestIndex(res.Version.Manifest)
	return res.Version
}

func TestSitePublishRollbackAndDrift(t *testing.T) {
	ctx := context.Background()
	e, svc, site := siteEnv(t)
	v1 := buildVersion(t, e, site)
	if j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v1.ID}); j.State != jobs.Succeeded || !strings.Contains(string(j.Result), "file level only") {
		t.Fatalf("publish v1: %s %s %s", j.State, j.Error, j.Result)
	}
	w, _ := svc.Get(ctx, site)
	if w.ActiveVersionID != v1.ID || e.h.sites[site] != v1.ID {
		t.Fatal("v1 not active")
	}
	// New content → v2; a corrupted copy fails verification and v1 stays served.
	c := *w.Content
	c.Site.Title["fa"] = "دیگر"
	raw, _ := json.Marshal(c)
	if _, _, _, err := svc.SaveContent(ctx, nil, site, w.DraftRevision, raw); err != nil {
		t.Fatal(err)
	}
	v2 := buildVersion(t, e, site)
	e.h.siteIndexSum = "0000"
	j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v2.ID})
	if j.State != jobs.RolledBack || e.h.sites[site] != v1.ID {
		t.Fatalf("bad copy: %s %s serving=%s", j.State, j.Error, e.h.sites[site])
	}
	e.h.siteIndexSum = ""
	// A failed copy never moves the pointer.
	e.h.sitePublishFail = true
	if j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v2.ID}); j.State != jobs.RolledBack || e.h.sites[site] != v1.ID {
		t.Fatalf("failed copy: %s", j.State)
	}
	e.h.sitePublishFail = false
	if j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v2.ID}); j.State != jobs.Succeeded {
		t.Fatalf("publish v2: %s %s", j.State, j.Error)
	}
	// Rollback = publishing the older version again.
	if j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v1.ID}); j.State != jobs.Succeeded || e.h.sites[site] != v1.ID {
		t.Fatalf("rollback: %s", j.State)
	}
	// Drift: the public pointer changed outside NGM → Blocked.
	e.h.sites[site] = v2.ID
	if j := e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v2.ID}); j.State != jobs.Blocked || !strings.Contains(string(j.Error), "site_drift") {
		t.Fatalf("drift: %s %s", j.State, j.Error)
	}
	e.h.sites[site] = v1.ID
	// First publication that fails is removed again (nothing half-published).
	e2, _, site2 := siteEnv(t)
	v := buildVersion(t, e2, site2)
	e2.h.siteIndexSum = "bad"
	if j := e2.submit(t, KindSitePublish, SitePayload{WebsiteID: site2, VersionID: v.ID}); j.State != jobs.RolledBack {
		t.Fatalf("first publish failure: %s", j.State)
	}
	if _, ok := e2.h.sites[site2]; ok {
		t.Fatal("a failed first publication left files served")
	}
}

func TestSiteDeleteRefusedWhileRouted(t *testing.T) {
	ctx := context.Background()
	e, svc, site := siteEnv(t)
	v := buildVersion(t, e, site)
	e.submit(t, KindSitePublish, SitePayload{WebsiteID: site, VersionID: v.ID})
	e.db.ExecContext(ctx, `INSERT INTO listeners(id,name,kind,address,port,family,enabled,options_json,created_at,updated_at) VALUES('L1','web','http','0.0.0.0',8080,'ipv4',1,'{}','x','x')`)
	if _, err := e.db.ExecContext(ctx, `INSERT INTO routes(id,name,listener_id,protocol,priority,destination_kind,destination_id,is_fallback,options_json,enabled,created_at,updated_at)
		VALUES('R1','site','L1','http',100,'website',?,0,'{}',1,'x','x')`, site); err != nil {
		t.Fatal(err)
	}
	if j := e.submit(t, KindSiteDelete, SitePayload{WebsiteID: site}); j.State != jobs.Blocked {
		t.Fatalf("delete while routed: %s", j.State)
	}
	e.db.ExecContext(ctx, "DELETE FROM routes")
	if j := e.submit(t, KindSiteDelete, SitePayload{WebsiteID: site}); j.State != jobs.Succeeded {
		t.Fatalf("delete: %s %s", j.State, j.Error)
	}
	if _, err := svc.Get(ctx, site); err == nil {
		t.Fatal("record still present")
	}
}
