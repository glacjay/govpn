package link

import (
	"github.com/glacjay/govpn/e"
	"github.com/glacjay/govpn/opt"
	"github.com/glacjay/govpn/sig"
	"github.com/glacjay/govpn/utils"
	"net"
	"syscall"
)

type Link struct {
	inputChan  <-chan []byte
	outputChan chan<- []byte

	conn *net.UDPConn

	remote    *net.UDPAddr
	connected bool
}

func New(o *opt.Options, inputChan <-chan []byte, outputChan chan<- []byte) *Link {
	link := new(Link)
	link.inputChan = inputChan
	link.outputChan = outputChan

	addr := utils.GetAddress(o.Conn.LocalHost, o.Conn.LocalPort)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		e.Msg(e.MErrorSock, "UDP: Cannot create UDP socket: %v.", err)
	}
	link.conn = conn

	if o.Conn.RemoteHost != "" {
		link.remote = utils.GetAddress(o.Conn.RemoteHost, o.Conn.RemotePort)
	}

	return link
}

func (link *Link) Start() {
	go link.inputLoop()
	go link.outputLoop()
}

func (link *Link) inputLoop() {
	for {
		buf := <-link.inputChan
		if link.remote == nil {
			continue
		}
		_, err := link.conn.WriteToUDP(buf, link.remote)
		if err != nil {
			e.Msg(e.DLinkErrors, "UDPv4: write failed: %v", err)
		}
	}
}

func (link *Link) outputLoop() {
	for {
		buf := make([]byte, 4096)
		nread, addr, err := link.conn.ReadFromUDP(buf)
		if err != nil {
			if err.(net.Error).Temporary() {
				continue
			} else {
				e.Msg(e.DLinkErrors, "UDPv4: read failed: %v", err)
				sig.ThrowSignalSoft(syscall.SIGUSR1, "socket read failed")
				break
			}
		}
		if link.remote == nil {
			link.remote = addr
		}
		if link.remote.String() != addr.String() {
			e.Msg(e.DLinkErrors, "TCP/UDP: Incoming packet rejected from %s[%s], expected peer address: %s (allow this incoming source address/port by removing --remote)", addr.String(), addr.Network(), link.remote.String())
			continue
		}
		if !link.connected {
			link.connected = true
			e.Msg(e.MInfo, "Peer Connection Initiated with %s", addr.String())
			e.Msg(e.MInfo, "Initialization Sequence Completed.")
		}

		link.outputChan <- buf[:nread]
	}
}

func (link *Link) Stop() {
	link.conn.Close()
}
