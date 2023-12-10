package utils

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"
)

type Key [32]byte
type Peer [38]byte

var DefaultKey Key

func NewPeerFromAddr(key Key, addr *net.UDPAddr) Peer {
	var peer Peer
	copy(peer[:], key[:])
	copy(peer[32:], addr.IP.To4())
	copy(peer[36:], []byte{byte(addr.Port >> 8), byte(addr.Port & 0xff)})
	return peer
}

func ParsePeers(buf []byte) []Peer {
	peers := make([]Peer, 0, len(buf)/38)
	for i := 0; i < len(buf); i += 38 {
		var peer Peer
		copy(peer[:], buf[i:i+38])
		peers = append(peers, peer)
	}
	return peers
}

func (t Peer) Parse() (key Key, addr string) {
	copy(key[:], t[:32])
	ip := net.IPv4(t[32], t[33], t[34], t[35]).String()
	port := int(t[36])<<8 + int(t[37])
	addr = fmt.Sprintf("%s:%d", ip, port)
	return
}

func (t Peer) String() string {
	key := base64.StdEncoding.EncodeToString(t[:32])
	ip := net.IPv4(t[32], t[33], t[34], t[35]).String()
	return fmt.Sprintf("%s  %s:%d", key, ip, int(t[36])<<8+int(t[37]))
}

func (t Key) String() string {
	return base64.StdEncoding.EncodeToString(t[:])
}

func DelayExe(sl time.Duration, f func()) {
	time.Sleep(sl)
	f()
}
