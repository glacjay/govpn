package main

import (
	"govpn/e"
)

func tunnelP2P(o *options) {
	socket := newSocket(o)
	socket.run()

	tuntap := newTuntap(o)
	tuntap.open()
	tuntap.ifconfig()
	tuntap.run()

	occ := newOCCStruct(o)
	occ.localString = o.optionsString()
	e.Msg(e.MInfo, "Local Options String: '%s'", occ.localString)
	occ.remoteString = o.optionsString()
	e.Msg(e.MInfo, "Expected Remote Options String: '%s'", occ.remoteString)
	occ.out = socket.in
	occ.run()

	for {
		select {
		case p := <-socket.out:
			if isOCCMsg(p.buf) {
				occ.processReceivedMsg(p.buf, socket.in)
				continue
			}
			tuntap.in <- p.buf
		case p := <-tuntap.out:
			socket.in <- p.buf
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
