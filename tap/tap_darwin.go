package tap

import (
	"fmt"
	"log"
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
	}
	if !dynamicOpened {
		log.Fatalf("[CRIT] Cannot allocate TUN/TAP device dynamically.")
	}

	tap.actualName = dynamicName
	log.Printf("[INFO] TUN/TAP device %s opened.", tap.actualName)
}

func (tap *Tap) Ifconfig() {
	cmd := exec.Command("/sbin/ifconfig", tap.actualName, "delete")
	_ = cmd.Run()
	log.Printf("[INFO] NOTE: Tried to delete pre-existing TUN/TAP instance -- no problem if failed.")

	cmd = exec.Command("/sbin/ifconfig", tap.actualName,
		tap.ip.IP.String(), "netmask",
		tap.mask.IP.String(), "mtu", "1500", "up")
	err := cmd.Run()
	if err != nil {
		log.Printf("[EROR] Mac OS X ifconfig failed: %v.", err)
	}
}
