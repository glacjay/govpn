package tap

import (
	"exec"
	"govpn/e"
	"os"
	"syscall"
	"unsafe"
)

func (tap *Tap) Open() {
	deviceFile := "/dev/net/tun"
	fd, err := os.OpenFile(deviceFile, os.O_RDWR, 0)
	if err != nil {
		e.Msg(e.MWarning, "Note: Cannot open TUN/TAP dev %s: %v", deviceFile, err)
	}
	tap.fd = fd

	ifr := make([]byte, 18)
	ifr[17] = 0x10 // IFF_NO_PI
	ifr[16] = 0x02 // IFF_TAP

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(tap.fd.Fd()), uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		e.Msg(e.MWarning, "Cannot ioctl TUNSETIFF: %v", os.Errno(errno))
	}

	tap.actualName = string(ifr)
	e.Msg(e.MInfo, "TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tap.actualName,
		tap.ip.IP.String(), "netmask",
		tap.mask.IP.String(), "mtu", "1500")
	err := cmd.Run()
	if err != nil {
		e.Msg(e.MFatal, "Linux ifconfig failed: %v.", err)
	}
}
