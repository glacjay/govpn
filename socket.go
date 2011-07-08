package main

import (
	"fmt"
	"log"
	"net"
)

const GOVPN_PORT = 1194

type linkSocket struct {
	info linkSocketInfo

	sd *net.UDPConn

	localHost  string
	localPort  int
	remoteHost string
	remotePort int

	sndbuf int
	rcvbuf int

	didResolveRemote bool
}

func (sock *linkSocket) initPhrase1(o *options, lsa *linkSocketAddr) {
	sock.localHost = string(o.ce.local)
	sock.localPort = o.ce.localPort
	sock.remoteHost = string(o.ce.remote)
	sock.remotePort = o.ce.remotePort

	sock.sndbuf = o.sndbuf
	sock.rcvbuf = o.rcvbuf

	sock.info.lsa = lsa

	sock.createSocket()
	sock.resolveBindLocal()
	sock.resolveRemote()
}

func (sock *linkSocket) createSocket() {
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: nil, Port: sock.localPort})
	if err != nil {
		log.Fatalf("UDP: Cannot create UDP socket: %v.", err)
	}
	sock.sd = conn
}

func (sock *linkSocket) resolveBindLocal() {
	if sock.info.lsa.local == nil {
		sock.info.lsa.local = getaddr(sock.localHost, sock.localPort)
	}
}

func (sock *linkSocket) resolveRemote() {
	if sock.didResolveRemote {
		return
	}
	if sock.info.lsa.remote == nil {
		sock.info.lsa.remote = getaddr(sock.remoteHost,
			sock.remotePort)
		if sock.info.lsa.actual != nil {
			log.Printf("TCP/UDP: Preserving recently used remote address: %s",
				sock.info.lsa.actual.String())
		} else {
			sock.info.lsa.actual = sock.info.lsa.remote
		}
	}
}

func (sock *linkSocket) initPhrase2(f *frame) {
	f.initSocket(sock)
	sock.setBuffers()
	local := "[undef]"
	if sock.info.lsa.local != nil {
		local = sock.info.lsa.local.IP.String()
	}
	log.Printf("UDPv4 link local: %s", local)
	actual := "[NULL]"
	if sock.info.lsa.actual != nil {
		actual = sock.info.lsa.actual.String()
	}
	log.Printf("UDPv4 link remote: %s", actual)
}

func (sock *linkSocket) setBuffers() {
	err := sock.sd.SetReadBuffer(sock.rcvbuf)
	if err != nil {
		log.Printf("Set Receive Buffer failed: %v", err)
	}
	err = sock.sd.SetWriteBuffer(sock.sndbuf)
	if err != nil {
		log.Printf("Set Send Buffer failed: %v", err)
	}
}

type linkSocketInfo struct {
	lsa                   *linkSocketAddr
	connectionEstablished bool
}

type linkSocketAddr struct {
	local  *net.UDPAddr
	remote *net.UDPAddr
	actual *net.UDPAddr
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
