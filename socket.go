package main

import (
	"fmt"
	"log"
	"net"
)

const GOVPN_PORT = 1194

type linkPacket struct {
	buf  []byte
	from *net.UDPAddr
}

type linkSocket struct {
	localHost  []byte
	localPort  int
	remoteHost []byte
	remotePort int

	local  *net.UDPAddr
	remote *net.UDPAddr

	conn *net.UDPConn

	in  chan *linkPacket
	out chan []byte
}

func newLinkSocket(o *options) *linkSocket {
	s := new(linkSocket)

	s.localHost = o.ce.local
	s.localPort = o.ce.localPort
	s.remoteHost = o.ce.remote
	s.remotePort = o.ce.remotePort

	s.createSocket()
	s.resolveBindLocal()
	s.resolveRemote()

	s.in = make(chan *linkPacket, 1)
	s.out = make(chan []byte, 1)

	return s
}

func (s *linkSocket) createSocket() {
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: s.localHost, Port: s.localPort})
	if err != nil {
		log.Fatalf("UDP: Cannot create UDP socket: %v.", err)
	}
	s.conn = conn
}

func (s *linkSocket) resolveBindLocal() {
	if s.local == nil {
		s.local = getaddr(s.localHost, s.localPort)
	}
}

func (s *linkSocket) resolveRemote() {
	if s.remoteHost != nil {
		s.remote = getaddr(s.remoteHost, s.remotePort)
	}
}

func (s *linkSocket) run() {
	go s.inLoop()
	go s.outLoop()
}

func (s *linkSocket) inLoop() {
	for {
		buf := make([]byte, 4096)
		nread, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalf("UDPv4: read failed: %v", err)
		}
		if s.remote == nil {
			s.remote = addr
		}
		if s.remote.String() == addr.String() {
			s.in <- &linkPacket{buf[:nread], addr}
		}
	}
}

func (s *linkSocket) outLoop() {
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

func isValidIpOrDns(addr string) bool {
	return net.ParseIP(addr) != nil
}

func isValidIpv4Port(port int) bool {
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
