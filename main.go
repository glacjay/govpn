package main

import (
	"govpn/e"
	"govpn/sig"
	"syscall"
)

func tunnelP2P(o *options) *sig.Signal {
	fromSock := make(chan []byte, 10)
	toSock := make(chan []byte, 10)
	toTun := make(chan []byte, 10)

	socket := newSocket(o, toSock, fromSock)
	socket.run()

	tuntap := newTuntap(o, toTun, toSock)
	tuntap.open()
	tuntap.ifconfig()
	tuntap.run()

	occ := newOCCStruct(o, toSock)
	occ.run()

	go fromSockDispatch(occ, fromSock, toTun)

	var s *sig.Signal
	for {
		s = <-sig.Signals
		if s.Signo == syscall.SIGTERM || s.Signo == syscall.SIGINT {
			break
		}
	}

	occ.Stop()
	tuntap.stop()
	socket.stop()

	return s
}

func fromSockDispatch(occ *occStruct, input <-chan []byte, output chan<- []byte) {
	for {
		msg := <-input
		if isOCCMsg(msg) {
			occ.processReceivedMsg(msg)
		} else {
			output <- msg
		}
	}
}

func main() {
	var s *sig.Signal
	for {
		o := newOptions()
		o.parseArgs(e.MUsage)
		o.postProcess()
		e.SetDebugLevel(o.verbosity)

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
