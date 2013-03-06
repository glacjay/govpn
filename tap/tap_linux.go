package tap

import (
	"log"
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
		log.Fatalf("[CRIT] Note: Cannot open TUN/TAP dev %s: %v", deviceFile, err)
	}
	tap.fd = fd

	ifr := make([]byte, 18)
	ifr[17] = 0x10 // IFF_NO_PI
	ifr[16] = 0x02 // IFF_TAP

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(tap.fd.Fd()), uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		log.Fatalf("[CRIT] Cannot ioctl TUNSETIFF: %v", errno)
	}

	tap.actualName = string(ifr)
	tap.actualName = tap.actualName[:strings.Index(tap.actualName, "\000")]
	log.Printf("[INFO] TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("ifconfig", tap.actualName, tap.ip.IP.String(),
		"netmask", tap.mask.IP.String(), "mtu", "1500")
	log.Printf("[DEBG] ifconfig command: %v", strings.Join(cmd.Args, " "))
	err := cmd.Run()
	if err != nil {
		log.Printf("[EROR] Linux ifconfig failed: %v.", err)
	}
}
