package main

import (
	"flag"
	"github.com/glacjay/govpn/tun"
	"log"
	"net"
	"strconv"
	"strings"
)

var (
	flagVirtAddr   = flag.String("virt-addr", "10.8.0.1/24", "virtual IP address of my TUN/TAP device")
	flagRemoteHost = flag.String("remote-host", "localhost", "remote peer's hostname or IP address")
)

func main() {
	flag.Parse()

	remoteAddrs, err := net.LookupIP(*flagRemoteHost)
	if err != nil || len(remoteAddrs) == 0 {
		log.Fatalf("Failed to resolve remote's hostname or address: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: remoteAddrs[0], Port: 1194})
	if err != nil {
		log.Fatalf("Failed to connect to remote's UDP port: %v", err)
	}
	defer conn.Close()

	tokens := strings.Split(*flagVirtAddr, "/")
	if len(tokens) < 2 {
		log.Fatalf("Malformed virt-addr: %s", *flagVirtAddr)
	}
	virtMaskOnes, err := strconv.ParseUint(tokens[1], 10, 8)
	if err != nil {
		log.Fatalf("Malformed virt-mask: %s", *flagVirtAddr)
	}
	virtAddr := tokens[0]
	virtMask := net.IP(net.CIDRMask(int(virtMaskOnes), 32)).String()

	tunDevice := tun.New()
	tunDevice.Open()
	tunDevice.SetupAddress(virtAddr, virtMask)
	tunDevice.Start()

	go linkToTunLoop(conn, tunDevice)
	for {
		packet := <-tunDevice.ReadCh
		_, err := conn.Write(packet)
		if err != nil {
			log.Printf("[EROR] Failed to write to UDP socket: %v", err)
			return
		}
	}
}

func linkToTunLoop(conn *net.UDPConn, tunDevice *tun.Tun) {
	defer conn.Close()
	defer tunDevice.Stop()

	var buf [4096]byte
	for {
		nread, err := conn.Read(buf[:])
		if nread > 0 {
			packet := make([]byte, nread)
			copy(packet, buf[:nread])
			tunDevice.WriteCh <- packet
		}
		if nread == 0 {
			return
		}
		if err != nil {
			log.Printf("[EROR] Failed to read from UDP socket: %v", err)
			return
		}
	}
}
