package main

import (
	"govpn/utils"
	"log"
	"net"
	"os"
)

type tunPacket struct {
	buf []byte
}

type tuntap struct {
	actualName string

	address *net.UDPAddr
	netmask *net.UDPAddr

	fd *os.File

	out chan *tunPacket
	in  chan []byte
}

func newTuntap(o *options) *tuntap {
	tt := new(tuntap)
	tt.out = make(chan *tunPacket, 1)
	tt.in = make(chan []byte, 1)

	if o.ifconfigAddress != nil && o.ifconfigNetmask != nil {
		tt.address = utils.GetAddress(o.ifconfigAddress, 0)
		tt.netmask = utils.GetAddress(o.ifconfigNetmask, 0)
	} else {
		log.Fatalf("Must specify TAP device's IP and netmask.")
	}

	return tt
}

func (tt *tuntap) run() {
	go tt.inLoop()
	go tt.outLoop()
}

func (tt *tuntap) outLoop() {
	for {
		buf := make([]byte, 4096)
		nread, err := tt.fd.Read(buf)
		if err != nil {
			log.Fatalf("TUN/TAP: read failed: %v", err)
		}
		tt.out <- &tunPacket{buf[:nread]}
	}
}

func (tt *tuntap) inLoop() {
	for {
		buf := <-tt.in
		_, err := tt.fd.Write(buf)
		if err != nil {
			log.Fatalf("TUN/TAP: write failed: %v", err)
		}
	}
}
