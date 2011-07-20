package main

func tunnelP2P(o *options) {
	socket := newSocket(o)
	socket.run()

	tuntap := newTuntap(o)
	tuntap.open()
	tuntap.ifconfig()
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

	tunnelP2P(o)
}
