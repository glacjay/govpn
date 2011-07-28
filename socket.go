package main

import (
	"govpn/e"
	"govpn/utils"
	"net"
)

const GOVPN_PORT = 1194

type sockPacket struct {
	buf  []byte
	from *net.UDPAddr
}

type socket struct {
	input  <-chan []byte
	output chan<- []byte

	conn *net.UDPConn

	remote    *net.UDPAddr
	connected bool
}

func newSocket(o *options, input <-chan []byte, output chan<- []byte) *socket {
	s := new(socket)
	s.input = input
	s.output = output

	s.createSocket(o)
	s.resolveRemote(o)

	return s
}

func (s *socket) createSocket(o *options) {
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: o.ce.localHost, Port: o.ce.localPort})
	if err != nil {
		e.Msg(e.MErrorSock, "UDP: Cannot create UDP socket: %v.", err)
	}
	s.conn = conn
}

func (s *socket) resolveRemote(o *options) {
	if o.ce.remoteHost != nil {
		s.remote = utils.GetAddress(o.ce.remoteHost, o.ce.remotePort)
	}
}

func (s *socket) run() {
	go s.inputLoop()
	go s.outputLoop()
}

func (s *socket) inputLoop() {
	for {
		buf := <-s.input
		if s.remote == nil {
			continue
		}
		_, err := s.conn.WriteToUDP(buf, s.remote)
		if err != nil {
			e.Msg(e.DLinkErrors, "UDPv4: write failed: %v", err)
		}
	}
}

func (s *socket) outputLoop() {
	for {
		buf := make([]byte, 4096)
		nread, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			e.Msg(e.DLinkErrors, "UDPv4: read failed: %v", err)
		}
		if s.remote == nil {
			s.remote = addr
		}
		if s.remote.String() != addr.String() {
			e.Msg(e.DLinkErrors, "TCP/UDP: Incoming packet rejected from %s[%s], expected peer address: %s (allow this incoming source address/port by removing --remote)", addr.String(), addr.Network(), s.remote.String())
			continue
		}
		if !s.connected {
			s.connected = true
			e.Msg(e.MInfo, "Peer Connection Initiated with %s", addr.String())
			e.Msg(e.MInfo, "Initialization Sequence Completed.")
		}

		s.output <- buf[:nread]
	}
}
