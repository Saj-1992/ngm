package lifecycle

import (
	"os"
	"path/filepath"
	"sort"
)

// KeepReleases is how many recent releases survive garbage collection, in
// addition to the current one and the rollback target.
var KeepReleases = 3

// GCReleases removes old release directories. It never removes the release
// the current pointer resolves to or any name in protect.
func GCReleases(releasesDir, current string, protect ...string) (removed []string, err error) {
	es, err := os.ReadDir(releasesDir)
	if err != nil {
		return nil, err
	}
	cur, _ := filepath.EvalSymlinks(current)
	keep := map[string]bool{filepath.Base(cur): true}
	for _, p := range protect {
		keep[p] = true
	}
	type rel struct {
		name string
		mod  int64
	}
	var rs []rel
	for _, e := range es {
		if !e.IsDir() || keep[e.Name()] {
			continue
		}
		if fi, err := e.Info(); err == nil {
			rs = append(rs, rel{e.Name(), fi.ModTime().UnixNano()})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].mod > rs[j].mod })
	for i, r := range rs {
		if i < KeepReleases {
			continue
		}
		if err := os.RemoveAll(filepath.Join(releasesDir, r.name)); err != nil {
			return removed, err
		}
		removed = append(removed, r.name)
	}
	return removed, nil
}
