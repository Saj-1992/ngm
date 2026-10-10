package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are Argon2id cost parameters (SECURITY_MODEL.md).
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultArgon2 is the production default: 64 MiB, t=3, p=2.
var DefaultArgon2 = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2}

// hashSlots bounds concurrent Argon2 evaluations so login bursts cannot
// exhaust memory on small (1 GiB) hosts.
var hashSlots = make(chan struct{}, 2)

// HashPassword returns a PHC-format Argon2id hash.
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, 32)
	<-hashSlots
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// VerifyPassword checks pw against a PHC Argon2id hash in constant time.
func VerifyPassword(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return false, errBadHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, errBadHash
	}
	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 1024*1024 || p.Time < 1 || p.Time > 20 || p.Threads < 1 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false, errBadHash
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	<-hashSlots
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// commonPasswords is a small deny-list of the most frequent leaked passwords
// that still satisfy the length rule.
var commonPasswords = map[string]bool{
	"password1234": true, "123456789012": true, "qwertyuiop12": true, "administrator": true,
	"passwordpassword": true, "letmein123456": true, "iloveyou1234": true, "welcome12345": true,
	"changeme1234": true, "adminadmin12": true, "qwerty123456": true, "111111111111": true,
}

// ErrWeakPassword describes a policy violation (message is safe to show).
type ErrWeakPassword struct{ Reason string }

func (e *ErrWeakPassword) Error() string { return "weak password: " + e.Reason }

// CheckPasswordPolicy enforces: 12–256 characters, not trivially derived from
// the username, not on the deny-list, at least 3 distinct character classes
// or 16+ characters (passphrases).
func CheckPasswordPolicy(pw, username string) error {
	n := utf8.RuneCountInString(pw)
	if n < 12 {
		return &ErrWeakPassword{"must be at least 12 characters"}
	}
	if n > 256 {
		return &ErrWeakPassword{"must be at most 256 characters"}
	}
	lp := strings.ToLower(pw)
	if username != "" && strings.Contains(lp, strings.ToLower(username)) {
		return &ErrWeakPassword{"must not contain the username"}
	}
	if commonPasswords[lp] {
		return &ErrWeakPassword{"is too common"}
	}
	var lower, upper, digit, other bool
	distinct := map[rune]bool{}
	for _, r := range pw {
		distinct[r] = true
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if len(distinct) < 6 {
		return &ErrWeakPassword{"has too few distinct characters"}
	}
	if classes < 3 && n < 16 {
		return &ErrWeakPassword{"needs 3 character classes, or 16+ characters"}
	}
	return nil
}
