package main

import (
	"govpn/e"
	"govpn/utils"
	"net"
	"os"
)

type tunPacket struct {
	buf []byte
}

type tuntap struct {
	input  <-chan []byte
	output chan<- []byte

	fd         *os.File
	actualName string

	address *net.UDPAddr
	netmask *net.UDPAddr
}

func newTuntap(o *options, input <-chan []byte, output chan<- []byte) *tuntap {
	tt := new(tuntap)
	tt.input = input
	tt.output = output

	if o.ifconfigAddress != nil && o.ifconfigNetmask != nil {
		tt.address = utils.GetAddress(o.ifconfigAddress, 0)
		tt.netmask = utils.GetAddress(o.ifconfigNetmask, 0)
	} else {
		e.Msg(e.MUsage, "Must specify TAP device's IP and netmask.")
	}

	return tt
}

func (tt *tuntap) run() {
	go tt.inputLoop()
	go tt.outputLoop()
}

func (tt *tuntap) inputLoop() {
	for {
		buf := <-tt.input
		_, err := tt.fd.Write(buf)
		if err != nil {
			e.Msg(e.DLinkErrors, "TUN/TAP: write failed: %v", err)
		}
	}
}

func (tt *tuntap) outputLoop() {
	for {
		buf := make([]byte, 4096)
		nread, err := tt.fd.Read(buf)
		if err != nil {
			e.Msg(e.DLinkErrors, "TUN/TAP: read failed: %v", err)
		}
		tt.output <- buf[:nread]
	}
}

func (tt *tuntap) stop() {
	tt.fd.Close()
}
