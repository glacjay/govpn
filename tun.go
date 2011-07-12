package main

import (
	"exec"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// tuntap.type_
const (
	DEV_TYPE_UNDEF = iota
	DEV_TYPE_NULL
	DEV_TYPE_TUN
	DEV_TYPE_TAP
)

type tuntap struct {
	type_ int

	didIfconfig      bool
	didIfconfigSetup bool

	actualName string

	local         *net.UDPAddr
	remoteNetmask *net.UDPAddr

	fd *os.File
}

func newTuntap(dev string, localParm, remoteParm []byte) *tuntap {
	tt := new(tuntap)
	tt.type_ = devTypeEnum(dev)

	if localParm != nil && remoteParm != nil {
		tt.local = getaddr(string(localParm), 0)
		tt.remoteNetmask = getaddr(string(remoteParm), 0)
		tt.didIfconfigSetup = true
	}

	return tt
}

func (tt *tuntap) openTun(dev string) {
	if tt.type_ == DEV_TYPE_NULL {
		tt.openNull()
	} else {
		node := "/dev/net/tun"
		fd, err := os.OpenFile(node, os.O_RDWR, 0)
		if err != nil {
			log.Fatalf("Note: Cannot open TUN/TAP dev %s: %v", node, err)
		}
		tt.fd = fd

		ifr := make([]byte, 18)
		ifr[17] = 0x10 // IFF_NO_PI

		if tt.type_ == DEV_TYPE_TUN {
			ifr[16] = 0x01 // IFF_TUN
		} else if tt.type_ == DEV_TYPE_TAP {
			ifr[16] = 0x02 // IFF_TAP
		} else {
			log.Fatalf("I don't recognize device %s as a tun or tap device.", dev)
		}

		if dev != "tun" && dev != "tap" {
			copy(ifr, dev[:15]) // IFNAMSIZ-1
		}

		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(tt.fd.Fd()), uintptr(0x400454ca), // TUNSETIFF
			uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			log.Fatalf("Note: Cannot ioctl TUNSETIFF %s: %v", dev, os.Errno(errno))
		}

		log.Printf("TUN/TAP device %s opened.", string(ifr))
		tt.actualName = string(ifr)
	}
}

func (tt *tuntap) openNull() {
	tt.actualName = "null"
}

func (tt *tuntap) doIfconfig() {
	if !tt.didIfconfigSetup {
		return
	}

	tun := tt.isTunP2p()
	local := tt.local.IP.String()
	remoteNetmask := tt.remoteNetmask.IP.String()

	var cmd *exec.Cmd
	if tun {
		cmd = exec.Command("/sbin/ifconfig", tt.actualName, local,
			"pointopoint", remoteNetmask, "mtu", "1500")
	} else {
		cmd = exec.Command("/sbin/ifconfig", tt.actualName, local,
			"netmask", remoteNetmask, "mtu", "1500")
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Linux ifconfig failed: %v.", err)
	}

	tt.didIfconfig = true
}

func (tt *tuntap) isTunP2p() bool {
	tun := false
	if tt.type_ == DEV_TYPE_TAP {
		tun = false
	} else if tt.type_ == DEV_TYPE_TUN {
		tun = true
	} else {
		log.Fatalf("Error: problem with tun vs. tap setting.")
	}
	return tun
}

func devTypeEnum(dev string) int {
	if isDevType(dev, "tun") {
		return DEV_TYPE_TUN
	} else if isDevType(dev, "tap") {
		return DEV_TYPE_TAP
	} else if isDevType(dev, "null") {
		return DEV_TYPE_NULL
	}
	return DEV_TYPE_UNDEF
}

func isDevType(dev, matchType string) bool {
	return dev[:len(matchType)] == matchType
}
