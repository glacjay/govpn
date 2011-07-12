package main

func tunnelPointToPoint(o *options) {
	socket := newLinkSocket(o)
	go socket.run()

	tuntap := newTuntap(string(o.dev), o.ifconfigLocal,
		o.ifconfigRemoteNetmask)
	tuntap.openTun(string(o.dev))
	tuntap.doIfconfig()
	go tuntap.run()

	for {
		select {
		case p := <-socket.queue:
			tuntap.write(p.buf)
		case p := <-tuntap.queue:
			socket.write(p.buf)
		}
	}
}

func main() {
	o := newOptions()
	o.parseArgs()
	o.postProcess()

	tunnelPointToPoint(o)
}
