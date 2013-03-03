package tap

import (
	l4g "code.google.com/p/log4go"
	"fmt"
	"os"
	"os/exec"
)

func (tap *Tap) Open() {
	dynamicOpened := false
	dynamicName := ""
	for i := 0; i < 256; i++ {
		tunName := fmt.Sprintf("/dev/tap%d", i)
		dynamicName = fmt.Sprintf("tap%d", i)
		fd, err := os.OpenFile(tunName, os.O_RDWR, 0)
		if err == nil {
			tap.fd = fd
			dynamicOpened = true
			break
		}
		l4g.Finest("Tried opening %s (failed): %v.", tunName, err)
	}
	if !dynamicOpened {
		l4g.Critical("Cannot allocate TUN/TAP device dynamically.")
		os.Exit(1)
	}

	tap.actualName = dynamicName
	l4g.Info("TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tap.actualName, "delete")
	_ = cmd.Run()
	l4g.Info("NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tap.actualName,
		tap.ip.IP.String(), "netmask",
		tap.mask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		l4g.Error("Mac OS X ifconfig failed: %v.", err)
	}
}
