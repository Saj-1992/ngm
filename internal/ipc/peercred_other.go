//go:build !linux

package ipc

import (
	"errors"
	"net"
)

// peerCred is unsupported off Linux: the helper refuses every request.
func peerCred(net.Conn) (Peer, error) {
	return Peer{}, errors.New("peer credentials unsupported on this platform")
}
