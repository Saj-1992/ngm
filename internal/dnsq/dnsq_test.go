package dnsq

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// reply builds a DNS response to q with the given answer RRs (raw rdata).
type ans struct {
	name  string
	t     uint16
	ttl   uint32
	rdata []byte
}

func encName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func reply(q []byte, aa, tc bool, rcode int, answers []ans) []byte {
	b := append([]byte(nil), q...)
	flags := uint16(0x8000 | rcode)
	if aa {
		flags |= 0x0400
	}
	if tc {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[6:], uint16(len(answers)))
	for _, a := range answers {
		if a.name == "" {
			b = append(b, 0xC0, 12) // compressed pointer to the question name
		} else {
			b = append(b, encName(a.name)...)
		}
		b = binary.BigEndian.AppendUint16(b, a.t)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, a.ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.rdata)))
		b = append(b, a.rdata...)
	}
	return b
}

func TestParseAllTypes(t *testing.T) {
	q, err := BuildQuery(0x1234, "Example.COM", TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	txt := []byte{5, 'h', 'e', 'l', 'l', 'o', 6, ' ', 'w', 'o', 'r', 'l', 'd'}
	caa := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
	// CNAME target uses a compression pointer back into the question.
	cname := []byte{3, 'w', 'w', 'w', 0xC0, 12}
	msg := reply(q, true, false, 0, []ans{
		{"", TypeA, 300, []byte{203, 0, 113, 7}},
		{"", TypeAAAA, 60, net.ParseIP("2001:db8::1").To16()},
		{"", TypeTXT, 120, txt},
		{"", TypeCAA, 3600, caa},
		{"alias.example.com", TypeCNAME, 30, cname},
		{"", 99, 1, []byte{1, 2}}, // unknown type ignored
	})
	r, err := Parse(msg, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Authoritative || r.Rcode != "NOERROR" || len(r.Answers) != 5 {
		t.Fatalf("%+v", r)
	}
	want := []string{"203.0.113.7", "2001:db8::1", "hello world", `0 issue "letsencrypt.org"`, "www.example.com"}
	for i, w := range want {
		if r.Answers[i].Value != w || r.Answers[i].Name == "" {
			t.Fatalf("answer %d = %+v want %q", i, r.Answers[i], w)
		}
	}
	if r.Answers[0].TTL != 300 || r.Answers[0].Name != "example.com" {
		t.Fatalf("%+v", r.Answers[0])
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	q, _ := BuildQuery(7, "a.example", TypeA, true)
	good := reply(q, false, false, 3, nil)
	if r, err := Parse(good, 7); err != nil || r.Rcode != "NXDOMAIN" {
		t.Fatalf("nxdomain: %v %+v", err, r)
	}
	if _, err := Parse(good, 8); err == nil {
		t.Fatal("id mismatch accepted")
	}
	// Forward compression pointer (loop risk) rejected.
	bad := reply(q, false, false, 0, nil)
	bad = append(bad, 0xC0, 0xFF)
	binary.BigEndian.PutUint16(bad[6:], 1)
	if _, err := Parse(bad, 7); err == nil {
		t.Fatal("bad pointer accepted")
	}
	// Truncated rdata.
	tr := reply(q, false, false, 0, []ans{{"", TypeA, 1, []byte{1, 2, 3, 4}}})
	if _, err := Parse(tr[:len(tr)-2], 7); err == nil {
		t.Fatal("truncated rdata accepted")
	}
	for _, n := range []string{"", "-a.example", "a..b", strings.Repeat("a", 64) + ".com", "a b.com"} {
		if _, err := BuildQuery(1, n, TypeA, true); err == nil {
			t.Fatalf("accepted name %q", n)
		}
	}
}

// fakeServer answers over UDP (truncated) and TCP (full), like a real server.
func TestQueryUDPWithTCPFallback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("cannot bind tcp on the same port:", err)
	}
	defer ln.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(reply(buf[:n], false, true, 0, nil), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var lb [2]byte
			readFull(c, lb[:])
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			readFull(c, q)
			r := reply(q, true, false, 0, []ans{{"", TypeA, 42, []byte{192, 0, 2, 1}}})
			c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
			c.Close()
		}
	}()
	cl := &Client{Timeout: 2 * time.Second}
	r, err := cl.Query(context.Background(), addr, "example.com", TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answers) != 1 || r.Answers[0].Value != "192.0.2.1" || r.Answers[0].TTL != 42 {
		t.Fatalf("%+v", r)
	}
}

func TestSystemResolvers(t *testing.T) {
	got := SystemResolvers("# c\nnameserver 127.0.0.53\noptions edns0\nnameserver 2001:db8::53\nnameserver bogus\n")
	if strings.Join(got, ",") != "127.0.0.53,2001:db8::53" {
		t.Fatal(got)
	}
}
