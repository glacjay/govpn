package tap

import (
	"fmt"
	"github.com/glacjay/govpn/e"
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
		e.Msg(e.DReadWrite, "Tried opening %s (failed): %v.", tunName, err)
	}
	if !dynamicOpened {
		e.Msg(e.MError, "Cannot allocate TUN/TAP device dynamically.")
	}

	tap.actualName = dynamicName
	e.Msg(e.MInfo, "TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tap.actualName, "delete")
	_ = cmd.Run()
	e.Msg(e.MInfo, "NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tap.actualName,
		tap.ip.IP.String(), "netmask",
		tap.mask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		e.Msg(e.MFatal, "Mac OS X ifconfig failed: %v.", err)
	}
}
