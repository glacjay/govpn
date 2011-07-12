package main

import (
	"fmt"
	"log"
	"net"
)

const GOVPN_PORT = 1194

type linkSocket struct {
	localHost  string
	localPort  int
	remoteHost string
	remotePort int

	local  *net.UDPAddr
	remote *net.UDPAddr

	sd *net.UDPConn

	connectionEstablished bool
}

func (sock *linkSocket) initPhrase1(o *options) {
	sock.localHost = string(o.ce.local)
	sock.localPort = o.ce.localPort
	sock.remoteHost = string(o.ce.remote)
	sock.remotePort = o.ce.remotePort

	sock.createSocket()
	sock.resolveBindLocal()
	sock.resolveRemote()
}

func (sock *linkSocket) createSocket() {
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: []byte(sock.localHost), Port: sock.localPort})
	if err != nil {
		log.Fatalf("UDP: Cannot create UDP socket: %v.", err)
	}
	sock.sd = conn
}

func (sock *linkSocket) resolveBindLocal() {
	if sock.local == nil {
		sock.local = getaddr(sock.localHost, sock.localPort)
	}
}

func (sock *linkSocket) resolveRemote() {
	if sock.remote == nil {
		sock.remote = getaddr(sock.remoteHost, sock.remotePort)
	}
}

func isValidIpOrDns(addr string) bool {
	return net.ParseIP(addr) != nil
}

func isValidIpv4Port(port int) bool {
	return port > 0 && port < 65536
}

func getaddr(host string, port int) *net.UDPAddr {
	str := fmt.Sprintf("%s:%d", host, port)
	addr, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		log.Fatalf("RESOLVE: Cannot resolve host address %s: %v.", str, err)
	}
	return addr
}
