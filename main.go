package main

func tunnelPointToPoint(o *options) {
	socket := newLinkSocket(o)
	socket.run()

	tuntap := newTuntap(string(o.dev), o.ifconfigLocal,
		o.ifconfigRemoteNetmask)
	tuntap.openTun(string(o.dev))
	tuntap.doIfconfig()
	tuntap.run()

	for {
		select {
		case p := <-socket.in:
			tuntap.out <- p.buf
		case p := <-tuntap.in:
			socket.out <- p.buf
		}
	}
}

func main() {
	o := newOptions()
	o.parseArgs()
	o.postProcess()

	tunnelPointToPoint(o)
}
