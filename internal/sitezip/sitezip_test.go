package sitezip

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name string
	data []byte
	mode fs.FileMode
}

func mk(t *testing.T, es ...ent) *bytes.Reader {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range es {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(e.data)
	}
	w.Close()
	return bytes.NewReader(buf.Bytes())
}

var page = []byte("<!doctype html><title>x</title>")

func extract(t *testing.T, r *bytes.Reader) (*Result, error, string) {
	dest := filepath.Join(t.TempDir(), "out")
	res, err := Extract(r, int64(r.Len()), dest, DefaultLimits)
	return res, err, dest
}

func TestValidSiteAndFolderStripping(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	res, err, dest := extract(t, mk(t, ent{"site/index.html", page, 0}, ent{"site/css/a.css", []byte("body{}"), 0}, ent{"site/img/x.png", png, 0}, ent{"__MACOSX/site/._x", []byte("junk"), 0}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stripped != "site" || len(res.Files) != 3 || res.Hash == "" {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "img", "x.png")); !bytes.Equal(b, png) {
		t.Fatal("content")
	}
	// Deterministic hash regardless of entry order.
	res2, _, _ := extract(t, mk(t, ent{"site/img/x.png", png, 0}, ent{"site/css/a.css", []byte("body{}"), 0}, ent{"site/index.html", page, 0}))
	if res2.Hash != res.Hash {
		t.Fatal("hash depends on entry order")
	}
}

func TestRejections(t *testing.T) {
	mz := append([]byte("MZ"), make([]byte, 100)...)
	cases := []struct {
		name string
		r    *bytes.Reader
		want string
	}{
		{"traversal", mk(t, ent{"index.html", page, 0}, ent{"../../etc/cron.d/x", []byte("x"), 0}), ".. segment"},
		{"absolute", mk(t, ent{"index.html", page, 0}, ent{"/etc/passwd.txt", []byte("x"), 0}), "absolute"},
		{"backslash", mk(t, ent{"index.html", page, 0}, ent{`a\..\..\x.txt`, []byte("x"), 0}), "forbidden character"},
		{"symlink", mk(t, ent{"index.html", page, 0}, ent{"link.html", []byte("/etc/shadow"), fs.ModeSymlink | 0o777}), "symbolic link"},
		{"device", mk(t, ent{"index.html", page, 0}, ent{"dev.txt", nil, fs.ModeDevice | 0o600}), "not a regular file"},
		{"php", mk(t, ent{"index.html", page, 0}, ent{"shell.php", []byte("<?php system($_GET[1]);"), 0}), "server-side code"},
		{"htaccess", mk(t, ent{"index.html", page, 0}, ent{"x/.htaccess", []byte("x"), 0}), "hidden"},
		{"env", mk(t, ent{"index.html", page, 0}, ent{".env", []byte("SECRET=1"), 0}), "hidden"},
		{"unknown-ext", mk(t, ent{"index.html", page, 0}, ent{"a.exe2", []byte("x"), 0}), "not allowed"},
		{"disguised-exe", mk(t, ent{"index.html", page, 0}, ent{"logo.png", mz, 0}), "executable"},
		{"shebang-js", mk(t, ent{"index.html", page, 0}, ent{"a.js", []byte("#!/bin/sh\nrm -rf /"), 0}), "executable"},
		{"mime-mismatch", mk(t, ent{"index.html", page, 0}, ent{"a.png", []byte("GIF89a...."), 0}), "does not match"},
		{"binary-as-text", mk(t, ent{"index.html", page, 0}, ent{"a.css", []byte("a\x00b"), 0}), "does not match"},
		{"case-dup", mk(t, ent{"index.html", page, 0}, ent{"A.html", page, 0}, ent{"a.html", page, 0}), "duplicate"},
		{"no-index", mk(t, ent{"home.html", page, 0}), "index.html"},
		{"bidi", mk(t, ent{"index.html", page, 0}, ent{"evil‮gnp.html", page, 0}), "forbidden character"},
		{"bomb", mk(t, ent{"index.html", page, 0}, ent{"big.txt", bytes.Repeat([]byte("A"), 20<<20), 0}), "compression ratio"},
	}
	for _, c := range cases {
		_, err, dest := extract(t, c.r)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want %q", c.name, err, c.want)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%s: destination left behind", c.name)
		}
	}
}

// lyingHeader writes an entry whose header claims a small size but whose
// deflate stream expands much further.
func TestLyingHeaderAndEncryption(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.CreateHeader(&zip.FileHeader{Name: "index.html", Method: zip.Deflate})
	f.Write(page)
	payload := bytes.Repeat([]byte("B"), 1<<20)
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.BestCompression)
	fw.Write(payload)
	fw.Close()
	rw, _ := w.CreateRaw(&zip.FileHeader{Name: "a.txt", Method: zip.Deflate, CompressedSize64: uint64(comp.Len()), UncompressedSize64: 10, CRC32: crc32.ChecksumIEEE(payload[:10])})
	rw.Write(comp.Bytes())
	enc, _ := w.CreateRaw(&zip.FileHeader{Name: "secret.txt", Method: zip.Store, Flags: 0x1, CompressedSize64: 3, UncompressedSize64: 3})
	enc.Write([]byte("abc"))
	w.Close()
	r := bytes.NewReader(buf.Bytes())
	_, err, _ := extract(t, r)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted entry: %v", err)
	}
	// Without the encrypted entry the lying header is caught while reading.
	buf.Reset()
	w = zip.NewWriter(&buf)
	f, _ = w.CreateHeader(&zip.FileHeader{Name: "index.html", Method: zip.Deflate})
	f.Write(page)
	rw, _ = w.CreateRaw(&zip.FileHeader{Name: "a.txt", Method: zip.Deflate, CompressedSize64: uint64(comp.Len()), UncompressedSize64: 100000, CRC32: 0})
	rw.Write(comp.Bytes())
	w.Close()
	r = bytes.NewReader(buf.Bytes())
	_, err, dest := extract(t, r)
	if err == nil || !(strings.Contains(err.Error(), "size differs") || strings.Contains(err.Error(), "corrupt")) {
		t.Fatalf("lying header: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("partial extraction left behind")
	}
}

func TestLimits(t *testing.T) {
	lim := DefaultLimits
	lim.MaxEntries = 3
	var es []ent
	for i := 0; i < 5; i++ {
		es = append(es, ent{name: "f" + string(rune('a'+i)) + ".txt", data: []byte("x")})
	}
	r := mk(t, es...)
	if _, err := Extract(r, int64(r.Len()), filepath.Join(t.TempDir(), "o"), lim); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader([]byte("not a zip")), 9, filepath.Join(t.TempDir(), "o"), DefaultLimits); err == nil {
		t.Fatal("garbage accepted")
	}
}
