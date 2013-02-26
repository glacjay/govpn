package main

import (
	"github.com/glacjay/govpn/e"
	"github.com/glacjay/govpn/link"
	"github.com/glacjay/govpn/occ"
	"github.com/glacjay/govpn/opt"
	"github.com/glacjay/govpn/sig"
	"github.com/glacjay/govpn/tap"
	"syscall"
)

func tunnelP2P(o *opt.Options) *sig.Signal {
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

	go fromSockDispatch(occ, fromSock, toTun)

	var s *sig.Signal
	for {
		s = <-sig.Signals
		if s.Signo == syscall.SIGTERM || s.Signo == syscall.SIGINT {
			break
		}
	}

	occ.Stop()
	tap.Stop()
	link.Stop()

	return s
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
	var s *sig.Signal
	for {
		o := opt.NewOptions()

		e.SetDebugLevel(o.Verbosity)
		e.SetMuteCutoff(o.Mute)

		for {
			s = tunnelP2P(o)
			if s.Signo != syscall.SIGUSR1 {
				break
			}
		}

		if s.Signo != syscall.SIGHUP {
			break
		}
	}
}
