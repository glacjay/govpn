package main

import (
	"exec"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type tunPacket struct {
	buf []byte
}

type tuntap struct {
	actualName string

	address *net.UDPAddr
	netmask *net.UDPAddr

	fd *os.File

	in  chan *tunPacket
	out chan []byte
}

func newTuntap(o *options) *tuntap {
	tt := new(tuntap)
	tt.in = make(chan *tunPacket, 1)
	tt.out = make(chan []byte, 1)

	if o.ifconfigAddress != nil && o.ifconfigNetmask != nil {
		tt.address = getaddr(o.ifconfigAddress, 0)
		tt.netmask = getaddr(o.ifconfigNetmask, 0)
	} else {
		log.Fatalf("Must specify TAP device's IP and netmask.")
	}

	return tt
}

func (tt *tuntap) openTun() {
	deviceFile := "/dev/net/tun"
	fd, err := os.OpenFile(deviceFile, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Note: Cannot open TUN/TAP dev %s: %v", deviceFile, err)
	}
	tt.fd = fd

	ifr := make([]byte, 18)
	ifr[17] = 0x10 // IFF_NO_PI
	ifr[16] = 0x02 // IFF_TAP

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(tt.fd.Fd()), uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		log.Fatalf("Cannot ioctl TUNSETIFF: %v", os.Errno(errno))
	}

	log.Printf("TUN/TAP device %s opened.", string(ifr))
	tt.actualName = string(ifr)
}

func (tt *tuntap) doIfconfig() {
	address := tt.address.IP.String()
	netmask := tt.netmask.IP.String()

	var cmd *exec.Cmd
	cmd = exec.Command("/sbin/ifconfig", tt.actualName, address,
		"netmask", netmask, "mtu", "1500")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Linux ifconfig failed: %v.", err)
	}
}

func (tt *tuntap) run() {
	go tt.inLoop()
	go tt.outLoop()
}

func (tt *tuntap) inLoop() {
	for {
		buf := make([]byte, 4096)
		nread, err := tt.fd.Read(buf)
		if err != nil {
			log.Fatalf("TUN/TAP: read failed: %v", err)
		}
		tt.in <- &tunPacket{buf[:nread]}
	}
}

func (tt *tuntap) outLoop() {
	for {
		buf := <-tt.out
		_, err := tt.fd.Write(buf)
		if err != nil {
			log.Fatalf("TUN/TAP: write failed: %v", err)
		}
	}
}
