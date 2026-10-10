// Package ids generates sortable, unguessable identifiers: 48-bit millisecond
// timestamp followed by 80 random bits, encoded as 26 Crockford base32 chars.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	mu     sync.Mutex
	lastMs uint64
	lastR  [10]byte
)

// New returns a new identifier for the current time. IDs from one process are
// strictly increasing: within the same millisecond the random part is
// incremented (ULID monotonic mode). Ordering across processes within the same
// millisecond is arbitrary.
func New() string {
	mu.Lock()
	defer mu.Unlock()
	ms := uint64(time.Now().UnixMilli())
	if ms <= lastMs {
		ms = lastMs
		if !incr(&lastR) {
			ms++
			fresh(&lastR)
		}
	} else {
		fresh(&lastR)
	}
	lastMs = ms
	var b [16]byte
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32))
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))
	copy(b[6:], lastR[:])
	return encode(b)
}

func fresh(r *[10]byte) {
	if _, err := rand.Read(r[:]); err != nil {
		panic("ids: crypto/rand failed: " + err.Error())
	}
	// Leave headroom so increments rarely overflow into the next millisecond.
	r[0] &= 0x7f
}

func incr(r *[10]byte) bool {
	for i := len(r) - 1; i >= 0; i-- {
		r[i]++
		if r[i] != 0 {
			return true
		}
	}
	return false
}

// At returns a new identifier with the given timestamp prefix.
func At(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32))
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ids: crypto/rand failed: " + err.Error())
	}
	return encode(b)
}

func encode(b [16]byte) string {
	// 128 bits -> 26 chars (130 bits, top 2 bits zero).
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = alphabet[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// Valid reports whether s has the shape of an identifier produced by New.
func Valid(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := false
		for j := 0; j < len(alphabet); j++ {
			if alphabet[j] == c {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
