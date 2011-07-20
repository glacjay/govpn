package main

import (
	"fmt"
	"log"
	"net"
)

const GOVPN_PORT = 1194

type sockPacket struct {
	buf  []byte
	from *net.UDPAddr
}

type socket struct {
	remote    *net.UDPAddr
	connected bool

	conn *net.UDPConn

	in  chan *sockPacket
	out chan []byte
}

func newSocket(o *options) *socket {
	s := new(socket)
	s.in = make(chan *sockPacket, 1)
	s.out = make(chan []byte, 1)

	s.createSocket(o)
	s.resolveRemote(o)

	return s
}

func (s *socket) createSocket(o *options) {
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: o.ce.localHost, Port: o.ce.localPort})
	if err != nil {
		log.Fatalf("UDP: Cannot create UDP socket: %v.", err)
	}
	s.conn = conn
}

func (s *socket) resolveRemote(o *options) {
	if o.ce.remoteHost != nil {
		s.remote = getaddr(o.ce.remoteHost, o.ce.remotePort)
	}
}

func (s *socket) run() {
	go s.inLoop()
	go s.outLoop()
}

func (s *socket) inLoop() {
	for {
		buf := make([]byte, 4096)
		nread, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalf("UDPv4: read failed: %v", err)
		}
		if s.remote == nil {
			s.remote = addr
		}
		if s.remote.String() != addr.String() {
			log.Printf("TCP/UDP: Incoming packet rejected from %s[%s], expected peer address: %s (allow this incoming source address/port by removing --remote)", addr.String(), addr.Network(), s.remote.String())
			continue
		}
		if !s.connected {
			s.connected = true
			log.Printf("Peer Connection Initiated with %s", addr.String())
		}

		s.in <- &sockPacket{buf[:nread], addr}
	}
}

func (s *socket) outLoop() {
	for {
		buf := <-s.out
		if s.remote == nil {
			continue
		}
		_, err := s.conn.WriteToUDP(buf, s.remote)
		if err != nil {
			log.Fatalf("UDPv4: write failed: %v", err)
		}
	}
}

func validHost(addr string) bool {
	return net.ParseIP(addr) != nil
}

func validPort(port int) bool {
	return port > 0 && port < 65536
}

func getaddr(host []byte, port int) *net.UDPAddr {
	str := fmt.Sprintf("%s:%d", string(host), port)
	addr, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		log.Fatalf("RESOLVE: Cannot resolve host address %s: %v.", str, err)
	}
	return addr
}
