package tun

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func (tun *Tun) Open() {
	dynamicOpened := false
	dynamicName := ""
	for i := 0; i < 256; i++ {
		tunName := fmt.Sprintf("/dev/tun%d", i)
		dynamicName = fmt.Sprintf("tun%d", i)
		fd, err := os.OpenFile(tunName, os.O_RDWR, 0)
		if err == nil {
			tun.fd = fd
			dynamicOpened = true
			break
		}
	}
	if !dynamicOpened {
		log.Fatalf("[CRIT] Cannot allocate TUN/TAP device dynamically.")
	}

	tun.actualName = dynamicName
	log.Printf("[INFO] TUN/TAP device %s opened.", tun.actualName)
}

func (tun *Tun) Ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tun.actualName, "delete")
	_ = cmd.Run()
	log.Printf("[INFO] NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tun.actualName,
		tun.ip.IP.String(), "netmask",
		tun.mask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		log.Printf("[EROR] Mac OS X ifconfig failed: %v.", err)
	}
}
