package main

import (
	"exec"
	"fmt"
	"govpn/e"
	"os"
)

func (tt *tuntap) open() {
	dynamicOpened := false
	dynamicName := ""
	for i := 0; i < 256; i++ {
		tunName := fmt.Sprintf("/dev/tap%d", i)
		dynamicName = fmt.Sprintf("tap%d", i)
		fd, err := os.OpenFile(tunName, os.O_RDWR, 0)
		if err == nil {
			tt.fd = fd
			dynamicOpened = true
			break
		}
		e.Msg(e.DReadWrite, "Tried opening %s (failed): %v.", tunName, err)
	}
	if !dynamicOpened {
		e.Msg(e.MError, "Cannot allocate TUN/TAP device dynamically.")
	}

	tt.actualName = dynamicName
	e.Msg(e.MInfo, "TUN/TAP device %s opened.", tt.actualName)
}

func (tt *tuntap) ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tt.actualName, "delete")
	_ = cmd.Run()
	e.Msg(e.MInfo, "NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tt.actualName,
		tt.address.IP.String(), "netmask",
		tt.netmask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		e.Msg(e.MFatal, "Mac OS X ifconfig failed: %v.", err)
	}
}
