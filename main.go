package main

import (
	"govpn/e"
	"govpn/opt"
	"govpn/sig"
	"syscall"
)

func tunnelP2P(o *opt.Options) *sig.Signal {
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
			go occ.processReceivedMsg(msg)
		} else {
			output <- msg
		}
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
