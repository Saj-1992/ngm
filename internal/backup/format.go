// Package backup implements NGM's portable encrypted backups (MASTER_SPEC
// §10.2). An archive is a plaintext JSON header followed by a tar stream
// encrypted in authenticated chunks:
//
//	NGMBAK1\n<header JSON>\n{ len:uint32 | AES-256-GCM(chunk) }*
//
// The key is Argon2id(passphrase, salt, params in header). Each chunk's nonce
// is prefix||counter||final-flag and its AAD is SHA-256(header), so chunks
// cannot be reordered, dropped, truncated, or moved between archives, and the
// header (KDF parameters, metadata) cannot be altered undetected.
package backup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	magic     = "NGMBAK1\n"
	chunkSize = 1 << 20
	maxHeader = 8 << 10
)

var (
	ErrWrongPassphrase = errors.New("wrong passphrase or corrupted archive (authentication failed)")
	ErrCorrupt         = errors.New("archive corrupted or truncated")
	ErrNotBackup       = errors.New("not an NGM backup archive")
)

// KDF holds Argon2id parameters.
type KDF struct {
	Alg       string `json:"alg"` // argon2id
	MemoryKiB uint32 `json:"m"`
	Time      uint32 `json:"t"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
}

// DefaultKDF returns production KDF parameters with a fresh salt.
func DefaultKDF() KDF {
	s := make([]byte, 16)
	_, _ = rand.Read(s)
	return KDF{Alg: "argon2id", MemoryKiB: 64 * 1024, Time: 3, Threads: 2, Salt: s}
}

// Derive computes the archive key.
func (k KDF) Derive(passphrase string) ([]byte, error) {
	if k.Alg != "argon2id" || len(k.Salt) < 16 || k.MemoryKiB < 8*1024 || k.MemoryKiB > 1<<20 || k.Time < 1 || k.Time > 20 || k.Threads < 1 {
		return nil, ErrNotBackup
	}
	return argon2.IDKey([]byte(passphrase), k.Salt, k.Time, k.MemoryKiB, k.Threads, 32), nil
}

// Header is the authenticated plaintext header.
type Header struct {
	Format        int       `json:"format"`
	KDF           KDF       `json:"kdf"`
	NoncePrefix   []byte    `json:"nonce_prefix"` // 7 bytes
	Created       time.Time `json:"created"`
	NGMVersion    string    `json:"ngm_version"`
	SchemaVersion int       `json:"schema_version"`
	Hostname      string    `json:"hostname"`
	Trigger       string    `json:"trigger"`
}

func nonce(prefix []byte, n uint32, final bool) []byte {
	b := make([]byte, 12)
	copy(b, prefix[:7])
	binary.BigEndian.PutUint32(b[7:11], n)
	if final {
		b[11] = 1
	}
	return b
}

// Writer encrypts a stream.
type Writer struct {
	w    io.Writer
	aead cipher.AEAD
	aad  []byte
	pre  []byte
	buf  []byte
	n    uint32
	done bool
}

// NewWriter writes the header and returns a writer for the plaintext.
func NewWriter(w io.Writer, key []byte, h Header) (*Writer, error) {
	h.Format = 1
	h.NoncePrefix = make([]byte, 7)
	if _, err := rand.Read(h.NoncePrefix); err != nil {
		return nil, err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return nil, err
	}
	if _, err := w.Write(append(hb, '\n')); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(hb)
	return &Writer{w: w, aead: a, aad: sum[:], pre: h.NoncePrefix}, nil
}

func (x *Writer) flush(final bool) error {
	ct := x.aead.Seal(nil, nonce(x.pre, x.n, final), x.buf, x.aad)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := x.w.Write(l[:]); err != nil {
		return err
	}
	if _, err := x.w.Write(ct); err != nil {
		return err
	}
	x.n++
	x.buf = x.buf[:0]
	return nil
}

func (x *Writer) Write(p []byte) (int, error) {
	if x.done {
		return 0, errors.New("write after close")
	}
	total := len(p)
	for len(p) > 0 {
		room := chunkSize - len(x.buf)
		k := min(room, len(p))
		x.buf = append(x.buf, p[:k]...)
		p = p[k:]
		if len(x.buf) == chunkSize {
			if err := x.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

// Close writes the final (possibly empty) chunk.
func (x *Writer) Close() error {
	if x.done {
		return nil
	}
	x.done = true
	return x.flush(true)
}

// ReadHeader parses the plaintext header without decrypting.
func ReadHeader(r *bufio.Reader) (Header, []byte, error) {
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(r, m); err != nil || string(m) != magic {
		return Header{}, nil, ErrNotBackup
	}
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) > maxHeader {
		return Header{}, nil, ErrNotBackup
	}
	hb := bytes.TrimSuffix(append([]byte(nil), line...), []byte("\n"))
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil || h.Format != 1 || len(h.NoncePrefix) != 7 {
		return Header{}, nil, ErrNotBackup
	}
	return h, hb, nil
}

// Reader decrypts a stream; it fails if any chunk is altered or the final
// chunk is missing.
type Reader struct {
	r     io.Reader
	aead  cipher.AEAD
	aad   []byte
	pre   []byte
	n     uint32
	buf   []byte
	final bool
}

// NewReader verifies the header and returns a plaintext reader.
func NewReader(br *bufio.Reader, passphrase string) (*Reader, Header, error) {
	h, hb, err := ReadHeader(br)
	if err != nil {
		return nil, h, err
	}
	key, err := h.KDF.Derive(passphrase)
	if err != nil {
		return nil, h, err
	}
	return NewReaderWithKey(br, key, h, hb)
}

// NewReaderWithKey uses an already-derived key.
func NewReaderWithKey(br io.Reader, key []byte, h Header, hb []byte) (*Reader, Header, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, h, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, h, err
	}
	sum := sha256.Sum256(hb)
	return &Reader{r: br, aead: a, aad: sum[:], pre: h.NoncePrefix}, h, nil
}

func (x *Reader) next() error {
	var l [4]byte
	if _, err := io.ReadFull(x.r, l[:]); err != nil {
		return ErrCorrupt
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > chunkSize+64 {
		return ErrCorrupt
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(x.r, ct); err != nil {
		return ErrCorrupt
	}
	// Try as a normal chunk, then as the final chunk.
	pt, err := x.aead.Open(nil, nonce(x.pre, x.n, false), ct, x.aad)
	if err != nil {
		pt, err = x.aead.Open(nil, nonce(x.pre, x.n, true), ct, x.aad)
		if err != nil {
			if x.n == 0 {
				return ErrWrongPassphrase
			}
			return ErrCorrupt
		}
		x.final = true
	}
	x.n++
	x.buf = pt
	return nil
}

func (x *Reader) Read(p []byte) (int, error) {
	for len(x.buf) == 0 {
		if x.final {
			// Anything after the final chunk is tampering.
			var one [1]byte
			if n, _ := x.r.Read(one[:]); n > 0 {
				return 0, ErrCorrupt
			}
			return 0, io.EOF
		}
		if err := x.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, x.buf)
	x.buf = x.buf[n:]
	return n, nil
}

// fmtSize renders bytes for messages.
func fmtSize(n int64) string {
	switch {
	case n > 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n > 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
