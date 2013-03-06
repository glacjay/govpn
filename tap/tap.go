package tap

import (
	"log"
	"github.com/glacjay/govpn/opt"
	"github.com/glacjay/govpn/utils"
	"net"
	"os"
)

type Tap struct {
	inputChan  <-chan []byte
	outputChan chan<- []byte

	fd         *os.File
	actualName string

	ip   *net.UDPAddr
	mask *net.UDPAddr
}

func New(o *opt.Options, inputChan <-chan []byte, outputChan chan<- []byte) *Tap {
	tap := new(Tap)
	tap.inputChan = inputChan
	tap.outputChan = outputChan

	if o.IfconfigAddress != "" && o.IfconfigNetmask != "" {
		tap.ip = utils.GetAddress(o.IfconfigAddress, 0)
		tap.mask = utils.GetAddress(o.IfconfigNetmask, 0)
	} else {
		log.Printf("[EROR] Must specify TAP device's IP and netmask.")
		os.Exit(1)
	}

	return tap
}

func (tap *Tap) Start() {
	go tap.inputLoop()
	go tap.outputLoop()
}

func (tap *Tap) inputLoop() {
	for {
		buf := <-tap.inputChan
		_, err := tap.fd.Write(buf)
		if err != nil {
			log.Printf("[EROR] TUN/TAP: write failed: %v", err)
		}
	}
}

func (tap *Tap) outputLoop() {
	for {
		buf := make([]byte, 4096)
		nread, err := tap.fd.Read(buf)
		if err != nil {
			log.Printf("[EROR] TUN/TAP: read failed: %v", err)
		}
		tap.outputChan <- buf[:nread]
	}
}

func (tap *Tap) Stop() {
	tap.fd.Close()
}
