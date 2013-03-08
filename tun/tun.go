package tun

import (
	"log"
	"os"
)

type Tun struct {
	fd         *os.File
	actualName string
	ReadCh     chan []byte
	WriteCh    chan []byte
}

func New() *Tun {
	tun := &Tun{ReadCh: make(chan []byte), WriteCh: make(chan []byte)}
	return tun
}

func (tun *Tun) Start() {
	go tun.readLoop()
	go tun.writeLoop()
}

func (tun *Tun) writeLoop() {
	for {
		buf := <-tun.WriteCh
		_, err := tun.fd.Write(buf)
		if err != nil {
			log.Printf("[EROR] TUN/TAP: write failed: %v", err)
			tun.fd.Close()
			return
		}
	}
}

func (tun *Tun) readLoop() {
	var buf [4096]byte
	for {
		nread, err := tun.fd.Read(buf[:])
		if nread > 0 {
			b := make([]byte, nread)
			copy(b, buf[:nread])
			tun.ReadCh <- b
		}
		if nread == 0 {
			tun.fd.Close()
			return
		}
		if err != nil {
			log.Printf("[EROR] TUN/TAP: read failed: %v", err)
			tun.fd.Close()
			return
		}
	}
}

func (tun *Tun) Stop() {
	tun.fd.Close()
}
