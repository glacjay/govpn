package main

import (
	"govpn/utils"
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

	out chan *sockPacket
	in  chan []byte
}

func newSocket(o *options) *socket {
	s := new(socket)
	s.out = make(chan *sockPacket, 1)
	s.in = make(chan []byte, 1)

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
		s.remote = utils.GetAddress(o.ce.remoteHost, o.ce.remotePort)
	}
}

func (s *socket) run() {
	go s.inLoop()
	go s.outLoop()
}

func (s *socket) outLoop() {
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
			log.Printf("Initialization Sequence Completed.")
		}

		s.out <- &sockPacket{buf[:nread], addr}
	}
}

func (s *socket) inLoop() {
	for {
		buf := <-s.in
		if s.remote == nil {
			continue
		}
		_, err := s.conn.WriteToUDP(buf, s.remote)
		if err != nil {
			log.Fatalf("UDPv4: write failed: %v", err)
		}
	}
}
