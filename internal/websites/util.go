package websites

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sortEntries(es []fileEntry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
}
