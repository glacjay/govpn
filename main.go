package main

import (
	"github.com/glacjay/govpn/e"
	"github.com/glacjay/govpn/link"
	"github.com/glacjay/govpn/occ"
	"github.com/glacjay/govpn/opt"
	"github.com/glacjay/govpn/tap"
)

func tunnelP2P(o *opt.Options) {
	fromSock := make(chan []byte, 10)
	toSock := make(chan []byte, 10)
	toTun := make(chan []byte, 10)

	link := link.New(o, toSock, fromSock)
	link.Start()

	tap := tap.New(o, toTun, toSock)
	tap.Open()
	tap.Ifconfig()
	tap.Start()

	occ := occ.New(o, toSock)
	if o.EnableOCC {
		occ.StartSendingRequest()
	}

	fromSockDispatch(occ, fromSock, toTun)

	occ.Stop()
	tap.Stop()
	link.Stop()
}

func fromSockDispatch(occ *occ.OCC, input <-chan []byte, output chan<- []byte) {
	for {
		msg := <-input

		if occ.CheckOccMessage(msg) {
			continue
		}

		output <- msg
	}
}

func main() {
	o := opt.NewOptions()

	e.SetDebugLevel(o.Verbosity)
	e.SetMuteCutoff(o.Mute)

	tunnelP2P(o)
}
