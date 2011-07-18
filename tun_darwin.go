package main

import (
	"exec"
	"fmt"
	"log"
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
		log.Printf("Tried opening %s (failed).", tunName)
	}
	if !dynamicOpened {
		log.Fatalf("Cannot allocate TUN/TAP device dynamically.")
	}

	tt.actualName = dynamicName
	log.Printf("TUN/TAP device %s opened.", tt.actualName)
}

func (tt *tuntap) ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tt.actualName, "delete")
	_ = cmd.Run()
	log.Printf("NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tt.actualName,
		tt.address.IP.String(), "netmask",
		tt.netmask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Mac OS X ifconfig failed: %v.", err)
	}
}
