package main

import (
	"govpn/e"
	"os/signal"
	"os"
	"syscall"
)

func tunnelP2P(o *options) {
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

	for {
		select {
		case sig := <-signal.Incoming:
			s := sig.(os.UnixSignal)
			if s == syscall.SIGTERM || s == syscall.SIGINT {
				e.Msg(e.MInfo, "Received signal: %v", sig)
				e.Exit(e.ExitGood)
			}
		}
	}
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
	o := newOptions()
	o.parseArgs(e.MUsage)
	o.postProcess()
	e.SetDebugLevel(o.verbosity)
	tunnelP2P(o)
}
