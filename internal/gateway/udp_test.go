package gateway

import (
	"strings"
	"testing"
)

func udpModel() *Model {
	return &Model{
		Listeners: []Listener{
			{ID: "LU", Name: "dns-udp", Kind: KindStream, Address: "0.0.0.0", Port: 5353, Family: "ipv4", Enabled: true, Options: ListenerOptions{UDP: true}},
		},
		Endpoints: []Endpoint{ep("EU", "10.0.0.9", 5353, "tcp")},
		Routes: []Route{
			{ID: "RU", Name: "dns", ListenerID: "LU", Protocol: ProtoTCP, DestKind: DestEndpoint, DestID: "EU", Enabled: true},
		},
	}
}

func TestUDPListenerCompiles(t *testing.T) {
	p := mustValid(t, udpModel())
	out := compile(t, p)
	s := string(out.Files[FileStream])
	if !strings.Contains(s, "listen 0.0.0.0:5353 udp;") {
		t.Fatalf("expected a udp listen directive:\n%s", s)
	}
}

func TestUDPAndTCPShareAPort(t *testing.T) {
	m := udpModel()
	// Add a TCP stream listener and route on the SAME port — must not conflict.
	m.Listeners = append(m.Listeners, Listener{ID: "LT", Name: "dns-tcp", Kind: KindStream, Address: "0.0.0.0", Port: 5353, Family: "ipv4", Enabled: true})
	m.Routes = append(m.Routes, Route{ID: "RT", Name: "dns-t", ListenerID: "LT", Protocol: ProtoTCP, DestKind: DestEndpoint, DestID: "EU", Enabled: true})
	if _, is := build(t, m); hasIssue(is, "listener_stream_overlap") || hasIssue(is, "listener_module_conflict") {
		t.Fatalf("udp and tcp on the same port must not conflict: %+v", is)
	}
}

func TestUDPOnlyOnStream(t *testing.T) {
	m := udpModel()
	m.Listeners[0].Kind = KindStreamTLSFront
	expectCode(t, m, "listener_udp")
}
