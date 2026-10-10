package websites

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

func svc(t *testing.T) *Service {
	db := storetest.New(t)
	return &Service{DB: db, Audit: audit.New(db), Root: t.TempDir()}
}

var png = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)

func TestTemplateSiteLifecycle(t *testing.T) {
	ctx := context.Background()
	s := svc(t)
	if _, err := s.Create(ctx, nil, "x", "template", "nope", "fa", []string{"fa"}); err == nil {
		t.Fatal("unknown template accepted")
	}
	if _, err := s.Create(ctx, nil, "x", "template", "landing", "fa", []string{"en"}); err == nil {
		t.Fatal("default locale outside locales accepted")
	}
	w, err := s.Create(ctx, nil, "Shop", "template", "landing", "fa", []string{"fa", "en"})
	if err != nil || w.Content == nil || len(w.Content.Pages) == 0 {
		t.Fatalf("%v %+v", err, w)
	}
	// Media: real type checked, SVG refused, names sanitised.
	if _, err := s.AddMedia(ctx, nil, w.ID, "x.svg", []byte(`<svg onload="alert(1)"/>`)); err == nil {
		t.Fatal("svg accepted")
	}
	if _, err := s.AddMedia(ctx, nil, w.ID, "fake.png", []byte("GIF89a....")); err != nil {
		t.Fatalf("gif named .png should be stored as .gif: %v", err)
	}
	m, err := s.AddMedia(ctx, nil, w.ID, `..\..\Evil Name!.PNG`, png)
	if err != nil || m.Name != "evil-name.png" {
		t.Fatalf("%v %+v", err, m)
	}
	// Content: unknown fields rejected, stale draft revision refused.
	if _, _, _, err := s.SaveContent(ctx, nil, w.ID, w.DraftRevision, []byte(`{"site":{},"pages":[],"script":"x"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	c := *w.Content
	c.Pages[0].Blocks[0].Image = m.Name
	raw, _ := json.Marshal(c)
	w2, errs, _, err := s.SaveContent(ctx, nil, w.ID, w.DraftRevision, raw)
	if err != nil || len(errs) != 0 {
		t.Fatalf("save: %v %v", err, errs)
	}
	if _, _, _, err := s.SaveContent(ctx, nil, w.ID, w.DraftRevision, raw); !errors.Is(err, ErrStale) {
		t.Fatalf("stale draft: %v", err)
	}
	// Build → version; identical rebuild reuses it.
	b1, err := s.Build(ctx, w.ID, "U1", "J1")
	if err != nil || b1.Reused || b1.Version.Number != 1 {
		t.Fatalf("build: %v %+v", err, b1)
	}
	if _, err := os.Stat(filepath.Join(s.BuildDir(w.ID, b1.Version.ID), "media", m.Name)); err != nil {
		t.Fatal("media not in build")
	}
	b2, _ := s.Build(ctx, w.ID, "U1", "J2")
	if !b2.Reused || b2.Version.ID != b1.Version.ID {
		t.Fatal("identical content must reuse the version")
	}
	c.Site.Title["fa"] = "فروشگاه"
	raw, _ = json.Marshal(c)
	s.SaveContent(ctx, nil, w.ID, w2.DraftRevision, raw)
	b3, _ := s.Build(ctx, w.ID, "U1", "J3")
	if b3.Reused || b3.Version.Number != 2 || b3.Version.ContentHash == b1.Version.ContentHash {
		t.Fatalf("changed content: %+v", b3.Version)
	}
	if err := s.MarkPublished(ctx, w.ID, b1.Version.ID); err != nil {
		t.Fatal(err)
	}
	s.MarkPublished(ctx, w.ID, b3.Version.ID)
	vs, _ := s.Versions(ctx, w.ID)
	if vs[0].Status != "published" || vs[1].Status != "superseded" {
		t.Fatalf("statuses %s %s", vs[0].Status, vs[1].Status)
	}
	w3, _ := s.Get(ctx, w.ID)
	if w3.ActiveVersionID != b3.Version.ID {
		t.Fatal("active version")
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		f, _ := zw.Create(n)
		f.Write([]byte(c))
	}
	zw.Close()
	return buf.Bytes()
}

func TestStaticZipSite(t *testing.T) {
	ctx := context.Background()
	s := svc(t)
	w, err := s.Create(ctx, nil, "Static", "static_zip", "", "en", []string{"en"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Build(ctx, w.ID, "", ""); err == nil {
		t.Fatal("build without upload")
	}
	if _, err := s.SaveUpload(ctx, nil, w.ID, bytes.NewReader(zipOf(t, map[string]string{"index.html": "<h1>hi</h1>", "x.php": "<?php"}))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Build(ctx, w.ID, "", ""); err == nil || !strings.Contains(err.Error(), "server-side") {
		t.Fatalf("php archive: %v", err)
	}
	s.SaveUpload(ctx, nil, w.ID, bytes.NewReader(zipOf(t, map[string]string{"index.html": "<h1>hi</h1>", "css/a.css": "h1{}"})))
	b, err := s.Build(ctx, w.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(s.BuildDir(w.ID, b.Version.ID), "css", "a.css"))
	if string(got) != "h1{}" {
		t.Fatal("extracted content")
	}
	// Oversized uploads are refused while streaming.
	big := bytes.NewReader(make([]byte, MaxUploadBytes+10))
	if _, err := s.SaveUpload(ctx, nil, w.ID, big); err == nil {
		t.Fatal("oversized upload accepted")
	}
	if _, err := s.AddMedia(ctx, nil, w.ID, "a.png", png); err == nil {
		t.Fatal("static sites have no media library")
	}
}
