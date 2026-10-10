package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ngm-gateway/ngm/internal/ipc"
)

// Published websites live in the public tree: /var/www/ngm/sites/<site>/
// <version>/ (immutable copies) and current → <version> (per-site pointer,
// switched atomically with rename(2); Nginx resolves it per request, so
// publishing needs no reload).

// SiteLimits bound what the helper copies.
const (
	siteMaxFiles = 20000
	siteMaxTotal = 300 << 20
)

func (l NginxLayout) sites() string { return filepath.Join(l.public(), "sites") }

// WebsitesRoot is where ngm-ops writes builds (helper only reads from there).
func (o *NginxOps) websitesRoot() string {
	if o.WebsitesRoot != "" {
		return o.WebsitesRoot
	}
	return "/var/lib/ngm/websites"
}

// SiteArgs addresses a site version.
type SiteArgs struct {
	SiteID    string   `json:"site_id"`
	VersionID string   `json:"version_id,omitempty"`
	Expected  string   `json:"expected,omitempty"` // activate: current pointer must equal this ("" = none)
	Keep      []string `json:"keep,omitempty"`     // gc: versions to keep besides current
}

func (a SiteArgs) check(needVersion bool) error {
	if !genIDRe.MatchString(a.SiteID) || needVersion && !genIDRe.MatchString(a.VersionID) {
		return &ipc.Error{Code: "bad_args", Message: "invalid site or version id"}
	}
	return nil
}

func (o *NginxOps) siteDir(id string) string { return filepath.Join(o.L.sites(), id) }

func (o *NginxOps) siteCurrent(id string) (string, error) {
	t, err := os.Readlink(filepath.Join(o.siteDir(id), "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !genIDRe.MatchString(t) {
		return "", fmt.Errorf("unexpected site pointer %q", t)
	}
	return t, nil
}

// copyTree copies regular files and directories from src to dst (new),
// refusing symlinks and special files, with explicit modes.
func copyTree(src, dst string) (map[string]string, int64, error) {
	manifest := map[string]string{}
	var total int64
	files := 0
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing symlink %s", rel)
		case info.IsDir():
			if err := os.Mkdir(target, 0o755); err != nil && !(rel == "." && os.IsExist(err)) {
				return err
			}
			return os.Chmod(target, 0o755)
		case !info.Mode().IsRegular():
			return fmt.Errorf("refusing special file %s", rel)
		}
		files++
		total += info.Size()
		if files > siteMaxFiles || total > siteMaxTotal {
			return errors.New("website too large")
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o644)
		if err != nil {
			return err
		}
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		if err := os.Chmod(target, 0o644); err != nil { // independent of UMask=0077
			return err
		}
		manifest[filepath.ToSlash(rel)] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return manifest, total, err
}

func (o *NginxOps) ensureSiteDir(id string) error {
	if err := o.ensurePublicDir(o.L.sites()); err != nil {
		return err
	}
	return o.ensurePublicDir(o.siteDir(id))
}

// switchPointer atomically points current at version.
func (o *NginxOps) switchPointer(id, version string) error {
	dir := o.siteDir(id)
	tmp := filepath.Join(dir, "current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "current"))
}

// SitePublish copies a built version into the public tree (immutable) and
// switches the site pointer to it.
func (o *NginxOps) SitePublish(_ context.Context, a SiteArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := a.check(true); err != nil {
		return nil, err
	}
	src := filepath.Join(o.websitesRoot(), a.SiteID, "builds", a.VersionID)
	st, err := os.Lstat(src)
	if err != nil || !st.IsDir() {
		return nil, &ipc.Error{Code: "not_found", Message: "build directory not found"}
	}
	if _, err := os.Lstat(filepath.Join(src, "index.html")); err != nil {
		return nil, &ipc.Error{Code: "bad_args", Message: "build has no index.html"}
	}
	if err := o.ensureSiteDir(a.SiteID); err != nil {
		return nil, err
	}
	prev, err := o.siteCurrent(a.SiteID)
	if err != nil {
		return nil, err
	}
	final := filepath.Join(o.siteDir(a.SiteID), a.VersionID)
	var manifest map[string]string
	var total int64
	if _, err := os.Lstat(final); err == nil {
		// Already copied (re-publish / rollback): verify against the build.
		m1, _, err1 := hashTree(final)
		m2, _, err2 := hashTree(src)
		if err1 != nil || err2 != nil || !equalManifest(m1, m2) {
			return nil, &ipc.Error{Code: "mismatch", Message: "published copy differs from its build"}
		}
		manifest = m1
	} else {
		tmp := final + ".staging"
		_ = os.RemoveAll(tmp)
		manifest, total, err = copyTree(src, tmp)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return nil, &ipc.Error{Code: "copy_failed", Message: err.Error()}
		}
		if err := os.Rename(tmp, final); err != nil {
			_ = os.RemoveAll(tmp)
			return nil, err
		}
	}
	if err := o.switchPointer(a.SiteID, a.VersionID); err != nil {
		return nil, err
	}
	return map[string]any{"previous": prev, "current": a.VersionID, "files": len(manifest), "bytes": total, "index_sha256": manifest["index.html"]}, nil
}

// SiteActivate switches the pointer to an already published version (rollback).
func (o *NginxOps) SiteActivate(_ context.Context, a SiteArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := a.check(true); err != nil {
		return nil, err
	}
	cur, err := o.siteCurrent(a.SiteID)
	if err != nil {
		return nil, err
	}
	if cur != a.Expected {
		return nil, &ipc.Error{Code: "current_changed", Message: fmt.Sprintf("site pointer is %q, expected %q", cur, a.Expected)}
	}
	if st, err := os.Lstat(filepath.Join(o.siteDir(a.SiteID), a.VersionID)); err != nil || !st.IsDir() {
		return nil, &ipc.Error{Code: "not_found", Message: "version is not in the public tree"}
	}
	if err := o.switchPointer(a.SiteID, a.VersionID); err != nil {
		return nil, err
	}
	return map[string]any{"previous": cur, "current": a.VersionID}, nil
}

// SiteState reports the pointer and published versions of a site.
func (o *NginxOps) SiteState(a SiteArgs) (map[string]any, error) {
	if err := a.check(false); err != nil {
		return nil, err
	}
	cur, err := o.siteCurrent(a.SiteID)
	if err != nil {
		return nil, err
	}
	vs := []string{}
	es, _ := os.ReadDir(o.siteDir(a.SiteID))
	for _, e := range es {
		if e.IsDir() && genIDRe.MatchString(e.Name()) {
			vs = append(vs, e.Name())
		}
	}
	sort.Strings(vs)
	return map[string]any{"current": cur, "versions": vs}, nil
}

// SiteGC removes published copies other than current and keep.
func (o *NginxOps) SiteGC(_ context.Context, a SiteArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := a.check(false); err != nil {
		return nil, err
	}
	cur, err := o.siteCurrent(a.SiteID)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{cur: true}
	for _, k := range a.Keep {
		keep[k] = true
	}
	removed := []string{}
	es, _ := os.ReadDir(o.siteDir(a.SiteID))
	for _, e := range es {
		n := e.Name()
		if (genIDRe.MatchString(n) || strings.HasSuffix(n, ".staging")) && !keep[n] && e.IsDir() {
			if os.RemoveAll(filepath.Join(o.siteDir(a.SiteID), n)) == nil {
				removed = append(removed, n)
			}
		}
	}
	return map[string]any{"removed": removed}, nil
}

// SiteRemove deletes every published file of a site.
func (o *NginxOps) SiteRemove(_ context.Context, a SiteArgs) (map[string]any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := a.check(false); err != nil {
		return nil, err
	}
	d := o.siteDir(a.SiteID)
	if st, err := os.Lstat(d); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return nil, &ipc.Error{Code: "bad_state", Message: "site path is not a directory"}
		}
		if err := os.RemoveAll(d); err != nil {
			return nil, err
		}
	}
	return map[string]any{"removed": a.SiteID}, nil
}

func hashTree(root string) (map[string]string, int64, error) {
	m := map[string]string{}
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in tree")
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		s := sha256.Sum256(b)
		m[filepath.ToSlash(rel)] = hex.EncodeToString(s[:])
		total += int64(len(b))
		return nil
	})
	return m, total, err
}

func equalManifest(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
