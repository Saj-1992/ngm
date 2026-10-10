// Package dnsq is a minimal DNS client (RFC 1035 wire format) used to
// observe records with their TTLs and to tell authoritative answers from
// resolver (cache) answers. It supports A, AAAA, CNAME, NS, TXT, CAA and SOA,
// UDP with TCP fallback on truncation, and name compression. It never
// follows referrals itself; callers decide which server to ask.
package dnsq

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Record types.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeCAA   uint16 = 257
)

// TypeByName maps "A".."CAA" to a type code.
var TypeByName = map[string]uint16{"A": TypeA, "NS": TypeNS, "CNAME": TypeCNAME, "SOA": TypeSOA, "TXT": TypeTXT, "AAAA": TypeAAAA, "CAA": TypeCAA}

// TypeName returns the mnemonic of a type code.
func TypeName(t uint16) string {
	for n, v := range TypeByName {
		if v == t {
			return n
		}
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// RR is one answer record with a normalised text value.
type RR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

// Response is a parsed reply.
type Response struct {
	Rcode         string `json:"rcode"` // NOERROR | NXDOMAIN | SERVFAIL | REFUSED | ...
	Authoritative bool   `json:"authoritative"`
	Truncated     bool   `json:"-"`
	Answers       []RR   `json:"answers"`
	Authority     []RR   `json:"authority"`
}

var rcodes = map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

// ErrBadName rejects names that are not valid DNS names.
var ErrBadName = errors.New("invalid DNS name")

// ValidName reports whether s is a syntactically valid DNS name (no wildcards).
func ValidName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// BuildQuery encodes a single-question query.
func BuildQuery(id uint16, name string, qtype uint16, recursion bool) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrBadName
	}
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], id)
	if recursion {
		b[2] = 0x01 // RD
	}
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, strings.ToLower(l)...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b, nil
}

type parser struct {
	msg []byte
	off int
}

var errShort = errors.New("truncated DNS message")

func (p *parser) u16() (uint16, error) {
	if p.off+2 > len(p.msg) {
		return 0, errShort
	}
	v := binary.BigEndian.Uint16(p.msg[p.off:])
	p.off += 2
	return v, nil
}

func (p *parser) u32() (uint32, error) {
	if p.off+4 > len(p.msg) {
		return 0, errShort
	}
	v := binary.BigEndian.Uint32(p.msg[p.off:])
	p.off += 4
	return v, nil
}

// nameAt decodes a (possibly compressed) name starting at off; it returns
// the name and the offset after the name in the original position.
func nameAt(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for hops := 0; ; hops++ {
		if hops > 127 || off >= len(msg) {
			return "", 0, errors.New("bad name compression")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			n := strings.Join(labels, ".")
			if len(n) > 253 {
				return "", 0, errors.New("name too long")
			}
			return strings.ToLower(n), end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
			if end < 0 {
				end = off + 2
			}
			if ptr >= off { // only backward pointers (prevents loops)
				return "", 0, errors.New("bad name compression")
			}
			off = ptr
		case l&0xC0 != 0:
			return "", 0, errors.New("unsupported label type")
		default:
			if off+1+l > len(msg) {
				return "", 0, errShort
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func (p *parser) name() (string, error) {
	n, next, err := nameAt(p.msg, p.off)
	if err != nil {
		return "", err
	}
	p.off = next
	return n, nil
}

// Parse decodes a reply to the query with the given id.
func Parse(msg []byte, id uint16) (*Response, error) {
	if len(msg) < 12 {
		return nil, errShort
	}
	if binary.BigEndian.Uint16(msg) != id {
		return nil, errors.New("DNS reply id mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return nil, errors.New("not a DNS response")
	}
	r := &Response{Authoritative: flags&0x0400 != 0, Truncated: flags&0x0200 != 0}
	rc := int(flags & 0x000F)
	r.Rcode = rcodes[rc]
	if r.Rcode == "" {
		r.Rcode = "RCODE" + strconv.Itoa(rc)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	p := &parser{msg: msg, off: 12}
	for i := 0; i < qd; i++ {
		if _, err := p.name(); err != nil {
			return nil, err
		}
		p.off += 4
	}
	read := func(n int) ([]RR, error) {
		var out []RR
		for i := 0; i < n; i++ {
			name, err := p.name()
			if err != nil {
				return nil, err
			}
			t, err := p.u16()
			if err != nil {
				return nil, err
			}
			if _, err := p.u16(); err != nil { // class
				return nil, err
			}
			ttl, err := p.u32()
			if err != nil {
				return nil, err
			}
			rdlen, err := p.u16()
			if err != nil {
				return nil, err
			}
			start := p.off
			if start+int(rdlen) > len(msg) {
				return nil, errShort
			}
			v, err := rdata(msg, start, int(rdlen), t)
			if err != nil {
				return nil, err
			}
			p.off = start + int(rdlen)
			if v != "" {
				out = append(out, RR{Name: name, Type: TypeName(t), TTL: ttl, Value: v})
			}
		}
		return out, nil
	}
	var err error
	if r.Answers, err = read(an); err != nil {
		return nil, err
	}
	if r.Authority, err = read(ns); err != nil {
		return nil, err
	}
	return r, nil
}

func rdata(msg []byte, off, n int, t uint16) (string, error) {
	d := msg[off : off+n]
	switch t {
	case TypeA:
		if n != 4 {
			return "", errors.New("bad A record")
		}
		return netip.AddrFrom4([4]byte(d)).String(), nil
	case TypeAAAA:
		if n != 16 {
			return "", errors.New("bad AAAA record")
		}
		return netip.AddrFrom16([16]byte(d)).String(), nil
	case TypeCNAME, TypeNS:
		name, _, err := nameAt(msg, off)
		return name, err
	case TypeTXT:
		var parts []string
		for i := 0; i < n; {
			l := int(d[i])
			if i+1+l > n {
				return "", errors.New("bad TXT record")
			}
			parts = append(parts, string(d[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(parts, ""), nil
	case TypeCAA:
		if n < 2 || 2+int(d[1]) > n {
			return "", errors.New("bad CAA record")
		}
		tag := string(d[2 : 2+int(d[1])])
		return fmt.Sprintf("%d %s %q", d[0], strings.ToLower(tag), string(d[2+int(d[1]):])), nil
	case TypeSOA:
		mname, _, err := nameAt(msg, off)
		return mname, err
	}
	return "", nil // other types are ignored
}

// Client sends queries.
type Client struct {
	Timeout time.Duration
	// Dial overrides the network dialer (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Query asks server (ip or ip:port, port 53 by default) for name/qtype.
func (c *Client) Query(ctx context.Context, server, name string, qtype uint16, recursion bool) (*Response, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	to := c.Timeout
	if to == 0 {
		to = 3 * time.Second
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := BuildQuery(id, name, qtype, recursion)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	conn, err := c.dial(cctx, "udp", server)
	if err != nil {
		return nil, err
	}
	dl, _ := cctx.Deadline()
	_ = conn.SetDeadline(dl)
	if _, err := conn.Write(q); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	var resp *Response
	for {
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp, err = Parse(buf[:n], id)
		if err == nil {
			break // ignore stray datagrams with other ids
		}
		if !strings.Contains(err.Error(), "id mismatch") {
			conn.Close()
			return nil, err
		}
	}
	conn.Close()
	if !resp.Truncated {
		return resp, nil
	}
	// TCP retry (RFC 7766).
	tc, err := c.dial(cctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	_ = tc.SetDeadline(dl)
	if _, err := tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := readFull(tc, lb[:]); err != nil {
		return nil, err
	}
	m := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := readFull(tc, m); err != nil {
		return nil, err
	}
	return Parse(m, id)
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// SystemResolvers returns nameservers from resolv.conf content.
func SystemResolvers(resolvConf string) []string {
	var out []string
	for _, line := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.String())
			}
		}
	}
	return out
}
