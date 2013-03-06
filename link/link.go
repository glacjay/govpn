package link

import (
	"github.com/glacjay/govpn/opt"
	"github.com/glacjay/govpn/utils"
	"log"
	"net"
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
		log.Fatalf("[CRIT] UDP: Cannot create UDP socket: %v.", err)
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
			log.Printf("[EROR] UDPv4: write failed: %v", err)
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
				log.Printf("[EROR] UDPv4: read failed: %v", err)
			}
		}
		if link.remote == nil {
			link.remote = addr
		}
		if link.remote.String() != addr.String() {
			log.Printf("[WARN] TCP/UDP: Incoming packet rejected from %s[%s], expected peer address: %s (allow this incoming source address/port by removing --remote)", addr.String(), addr.Network(), link.remote.String())
			continue
		}
		if !link.connected {
			link.connected = true
			log.Printf("[INFO] Peer Connection Initiated with %s", addr.String())
			log.Printf("[INFO] Initialization Sequence Completed.")
		}

		link.outputChan <- buf[:nread]
	}
}

func (link *Link) Stop() {
	link.conn.Close()
}
