package main

import (
	"exec"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Can't open linux TUN device file: %v\n", err)
	}

	ifr := make([]byte, 18)
	copy(ifr, "tun0")
	ifr[16] = 0x01
	ifr[17] = 0x10
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tun.Fd()),
		uintptr(0x400454ca), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		log.Fatalf("Failed to ioctl the TUN device: %v", os.Errno(errno))
	}

	cmd := exec.Command("ifconfig", "tun0", "192.168.7.1", "pointopoint",
		"192.168.7.2", "up")
	err = cmd.Run()
	if err != nil {
		log.Fatalf("Can't set tun0's address by ifconfig command: %v\n", err)
	}

	buf := make([]byte, 2048)
	for {
		nread, err := tun.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read from TUN device: %v\n", err)
		}

		log.Printf("Read %d bytes from the TUN device.\n", nread)

		_, err = tun.Write(buf[:nread])
		if err != nil {
			log.Fatalf("Failed to write to TUN device: %v\n", err)
		}
	}
}
