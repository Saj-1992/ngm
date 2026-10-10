// Package sitezip validates and extracts uploaded static-site ZIP archives
// (MASTER_SPEC §6.3): bounded archive and file sizes, decompression-ratio
// and lying-header detection, path normalisation, rejection of symlinks,
// devices, encrypted entries, server-side code, executables and hidden
// files, extension allowlisting and content sniffing. Extraction writes only
// regular files below the destination directory.
package sitezip

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits bound an archive.
type Limits struct {
	MaxEntries   int
	MaxFileBytes int64
	MaxTotal     int64
	MaxRatio     float64 // uncompressed / compressed, per entry
}

// DefaultLimits are conservative for small VPS hosts.
var DefaultLimits = Limits{MaxEntries: 5000, MaxFileBytes: 25 << 20, MaxTotal: 200 << 20, MaxRatio: 200}

// Allowed static extensions and what their content must look like.
var allowed = map[string]string{
	".html": "text", ".htm": "text", ".css": "text", ".js": "text", ".mjs": "text", ".json": "text", ".txt": "text", ".xml": "text",
	".svg": "text", ".map": "text", ".webmanifest": "text", ".csv": "text", ".md": "text",
	".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp", ".avif": "avif", ".ico": "ico",
	".woff": "woff", ".woff2": "woff2", ".ttf": "bin", ".otf": "bin", ".eot": "bin",
	".pdf": "pdf", ".mp4": "bin", ".webm": "bin", ".mp3": "bin", ".ogg": "bin", ".wav": "bin",
}

// Server-side or executable types get a specific message (never served as code).
var serverSide = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".phar": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
	".sh": true, ".bash": true, ".asp": true, ".aspx": true, ".jsp": true, ".jspx": true, ".exe": true, ".dll": true, ".so": true, ".bat": true,
	".cmd": true, ".ps1": true, ".jar": true, ".war": true, ".shtml": true, ".htaccess": true, ".lua": true}

// File is one extracted file.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Result describes a validated archive.
type Result struct {
	Files    []File   `json:"files"`
	Total    int64    `json:"total_bytes"`
	Hash     string   `json:"hash"`
	Stripped string   `json:"stripped_prefix,omitempty"`
	Warnings []string `json:"warnings"`
}

// RejectError lists every problem found (shown to the uploader).
type RejectError struct{ Problems []string }

func (e *RejectError) Error() string {
	p := e.Problems
	if len(p) > 20 {
		p = append(append([]string{}, p[:20]...), fmt.Sprintf("… and %d more", len(e.Problems)-20))
	}
	return "archive rejected: " + strings.Join(p, "; ")
}

// cleanName normalises an entry name or explains why it is unsafe.
func cleanName(n string) (string, error) {
	if n == "" || len(n) > 512 {
		return "", errors.New("empty or overlong name")
	}
	if !utf8.ValidString(n) {
		return "", errors.New("name is not valid UTF-8")
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f || r == '\\' || r == ':' || unicode.Is(unicode.Bidi_Control, r) {
			return "", fmt.Errorf("name %q contains a forbidden character", n)
		}
	}
	if strings.HasPrefix(n, "/") {
		return "", fmt.Errorf("absolute path %q", n)
	}
	for _, seg := range strings.Split(strings.TrimSuffix(n, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("path %q has an empty, . or .. segment", n)
		}
	}
	c := path.Clean(n)
	if c != strings.TrimSuffix(n, "/") || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("path %q is not normalised", n)
	}
	return c, nil
}

func sniff(kind string, head []byte) bool {
	switch kind {
	case "text":
		return !bytes.Contains(head, []byte{0}) // binaries disguised as text
	case "png":
		return bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n"))
	case "jpeg":
		return bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF})
	case "gif":
		return bytes.HasPrefix(head, []byte("GIF87a")) || bytes.HasPrefix(head, []byte("GIF89a"))
	case "webp":
		return len(head) >= 12 && string(head[:4]) == "RIFF" && string(head[8:12]) == "WEBP"
	case "avif":
		return len(head) >= 12 && string(head[4:8]) == "ftyp"
	case "ico":
		return bytes.HasPrefix(head, []byte{0, 0, 1, 0})
	case "woff":
		return bytes.HasPrefix(head, []byte("wOFF"))
	case "woff2":
		return bytes.HasPrefix(head, []byte("wOF2"))
	case "pdf":
		return bytes.HasPrefix(head, []byte("%PDF-"))
	}
	return true
}

// executable reports native executables or scripts with an interpreter line.
func executable(head []byte) bool {
	return bytes.HasPrefix(head, []byte("MZ")) || bytes.HasPrefix(head, []byte("\x7fELF")) || bytes.HasPrefix(head, []byte("#!")) ||
		bytes.HasPrefix(head, []byte{0xCF, 0xFA, 0xED, 0xFE}) || bytes.HasPrefix(head, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

type entry struct {
	f    *zip.File
	name string
}

// Extract validates ra (size bytes) and writes its files below dest, which
// must not exist yet. Nothing is written unless the whole archive passes the
// metadata checks; content checks abort and remove dest.
func Extract(ra io.ReaderAt, size int64, dest string, lim Limits) (*Result, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, &RejectError{Problems: []string{"not a valid ZIP archive"}}
	}
	if len(zr.File) > lim.MaxEntries {
		return nil, &RejectError{Problems: []string{fmt.Sprintf("too many entries (%d > %d)", len(zr.File), lim.MaxEntries)}}
	}
	var probs []string
	bad := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }
	res := &Result{Warnings: []string{}}
	var files []entry
	seen := map[string]bool{}
	var declared uint64
	for _, f := range zr.File {
		n := f.Name
		if strings.HasPrefix(n, "__MACOSX/") || path.Base(n) == ".DS_Store" || path.Base(n) == "Thumbs.db" {
			res.Warnings = append(res.Warnings, "skipped OS metadata "+n)
			continue
		}
		name, err := cleanName(n)
		if err != nil {
			bad("%v", err)
			continue
		}
		mode := f.Mode()
		if mode.IsDir() {
			continue
		}
		if mode&os.ModeSymlink != 0 {
			bad("%s is a symbolic link", name)
			continue
		}
		if !mode.IsRegular() {
			bad("%s is not a regular file (%v)", name, mode.Type())
			continue
		}
		if f.Flags&0x1 != 0 {
			bad("%s is encrypted", name)
			continue
		}
		if f.Method != zip.Store && f.Method != zip.Deflate {
			bad("%s uses an unsupported compression method", name)
			continue
		}
		for _, seg := range strings.Split(name, "/") {
			if strings.HasPrefix(seg, ".") {
				bad("%s is hidden (dot files such as .env or .git are never published)", name)
				break
			}
		}
		ext := strings.ToLower(path.Ext(name))
		if serverSide[ext] {
			bad("%s is server-side code or an executable; NGM serves static files only", name)
			continue
		}
		if _, ok := allowed[ext]; !ok {
			bad("%s: file type %q is not allowed", name, ext)
			continue
		}
		if int64(f.UncompressedSize64) > lim.MaxFileBytes {
			bad("%s is larger than %d MiB", name, lim.MaxFileBytes>>20)
			continue
		}
		if f.CompressedSize64 > 0 && float64(f.UncompressedSize64)/float64(f.CompressedSize64) > lim.MaxRatio {
			bad("%s has a suspicious compression ratio (possible ZIP bomb)", name)
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			bad("duplicate path %s (names are compared case-insensitively)", name)
			continue
		}
		seen[key] = true
		declared += f.UncompressedSize64
		files = append(files, entry{f, name})
	}
	if declared > uint64(lim.MaxTotal) {
		bad("archive expands to more than %d MiB", lim.MaxTotal>>20)
	}
	if len(files) == 0 && len(probs) == 0 {
		bad("the archive contains no files")
	}
	// A single top-level folder (common when zipping a directory) is stripped.
	prefix := ""
	if len(files) > 0 && !seen["index.html"] {
		first := strings.SplitN(files[0].name, "/", 2)[0] + "/"
		all := true
		for _, e := range files {
			if !strings.HasPrefix(e.name, first) {
				all = false
				break
			}
		}
		if all && seen[strings.ToLower(first)+"index.html"] {
			prefix = first
			res.Stripped = strings.TrimSuffix(first, "/")
		}
	}
	if prefix == "" && !seen["index.html"] && len(files) > 0 {
		bad("index.html must exist at the top level")
	}
	if len(probs) > 0 {
		return nil, &RejectError{Problems: probs}
	}
	if err := os.Mkdir(dest, 0o750); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dest)
		}
	}()
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	var total int64
	h := sha256.New()
	for _, e := range files {
		rel := strings.TrimPrefix(e.name, prefix)
		kind := allowed[strings.ToLower(path.Ext(rel))]
		rc, err := e.f.Open()
		if err != nil {
			return nil, &RejectError{Problems: []string{e.name + ": cannot be read"}}
		}
		// Never trust the header: read at most declared+1 bytes.
		data, err := io.ReadAll(io.LimitReader(rc, int64(e.f.UncompressedSize64)+1))
		rc.Close()
		if err != nil {
			return nil, &RejectError{Problems: []string{e.name + ": corrupt data (" + err.Error() + ")"}}
		}
		if int64(len(data)) != int64(e.f.UncompressedSize64) {
			return nil, &RejectError{Problems: []string{e.name + ": size differs from its header (possible ZIP bomb or corrupt archive)"}}
		}
		head := data[:min(len(data), 512)]
		if executable(head) {
			return nil, &RejectError{Problems: []string{rel + ": looks like an executable or script"}}
		}
		if !sniff(kind, head) {
			return nil, &RejectError{Problems: []string{rel + ": content does not match its extension"}}
		}
		total += int64(len(data))
		if total > lim.MaxTotal {
			return nil, &RejectError{Problems: []string{"archive expands beyond the size limit"}}
		}
		p := filepath.Join(dest, filepath.FromSlash(rel))
		if !strings.HasPrefix(p, filepath.Clean(dest)+string(os.PathSeparator)) {
			return nil, &RejectError{Problems: []string{rel + ": escapes the destination"}}
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return nil, err
		}
		if err := writeNew(p, data); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		res.Files = append(res.Files, File{Path: rel, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
		h.Write([]byte(rel + "\x00"))
		h.Write(data)
		h.Write([]byte{0})
	}
	res.Total = total
	res.Hash = hex.EncodeToString(h.Sum(nil))
	ok = true
	return res, nil
}

func writeNew(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
