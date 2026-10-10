//go:build unix

package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rotation while the indexer is behind: the unread tail of the rotated file
// (.1) is read before the new file, so no line is lost or duplicated.
func TestRotationKeepsEveryLine(t *testing.T) {
	ctx := context.Background()
	ix := newIndex(t)
	p := filepath.Join(t.TempDir(), "access.jsonl")
	line := func(path string) string { return strings.Replace(httpLine1, "/api/x", path, 1) + "\n" }
	os.WriteFile(p, []byte(line("/a")), 0o644)
	c := &Collector{Ix: ix, Sources: []Source{{Path: p, Kind: "http"}}}
	c.Pass(ctx)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line("/b-written-before-rotation"))
	f.Close()
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte(line("/c-new-file")), 0o644)
	if _, n, err := c.Pass(ctx); err != nil || n != 2 {
		t.Fatalf("after rotation n=%d err=%v", n, err)
	}
	all, _ := Search(ctx, ix.DB, Query{Limit: 10})
	got := []string{}
	for _, e := range all {
		got = append(got, e.Path)
	}
	if strings.Join(got, ",") != "/c-new-file,/b-written-before-rotation,/a" {
		t.Fatalf("%v", got)
	}
}

// Nginx reopens logs asynchronously after rotation: lines written to the
// renamed file after the indexer noticed the rotation must still be indexed.
func TestLateWritesToRotatedFile(t *testing.T) {
	ctx := context.Background()
	ix := newIndex(t)
	p := filepath.Join(t.TempDir(), "access.jsonl")
	line := func(path string) string { return strings.Replace(httpLine1, "/api/x", path, 1) + "\n" }
	os.WriteFile(p, []byte(line("/a")), 0o644)
	c := &Collector{Ix: ix, Sources: []Source{{Path: p, Kind: "http"}}}
	c.Pass(ctx)
	os.Rename(p, p+".1")
	os.WriteFile(p, nil, 0o644)
	c.Pass(ctx) // rotation detected, old file drained so far
	f, _ := os.OpenFile(p+".1", os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line("/late"))
	f.Close()
	if _, n, _ := c.Pass(ctx); n != 1 {
		t.Fatalf("late write to the rotated file not indexed (%d)", n)
	}
	if _, n, _ := c.Pass(ctx); n != 0 {
		t.Fatal("rotated file re-read")
	}
	// Once .1 is compressed away, its checkpoint is forgotten.
	os.Remove(p + ".1")
	c.Pass(ctx)
	var k int
	ix.DB.QueryRow("SELECT count(*) FROM checkpoints WHERE path LIKE '%#rotated'").Scan(&k)
	if k != 0 {
		t.Fatal("stale rotated checkpoint")
	}
}
