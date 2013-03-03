package tap

import (
	l4g "code.google.com/p/log4go"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func (tap *Tap) Open() {
	deviceFile := "/dev/net/tun"
	fd, err := os.OpenFile(deviceFile, os.O_RDWR, 0)
	if err != nil {
		l4g.Critical("Note: Cannot open TUN/TAP dev %s: %v", deviceFile, err)
		os.Exit(1)
	}
	tap.fd = fd

	ifr := make([]byte, 18)
	ifr[17] = 0x10 // IFF_NO_PI
	ifr[16] = 0x02 // IFF_TAP

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(tap.fd.Fd()), uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		l4g.Critical("Cannot ioctl TUNSETIFF: %v", errno)
		os.Exit(1)
	}

	tap.actualName = string(ifr)
	tap.actualName = tap.actualName[:strings.Index(tap.actualName, "\000")]
	l4g.Info("TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("ifconfig", tap.actualName, tap.ip.IP.String(),
		"netmask", tap.mask.IP.String(), "mtu", "1500")
	l4g.Debug("ifconfig command: %v", strings.Join(cmd.Args, " "))
	err := cmd.Run()
	if err != nil {
		l4g.Error("Linux ifconfig failed: %v.", err)
	}
}
