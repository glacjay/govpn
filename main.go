package main

func tunnelPointToPoint(o *options) {
	sock := new(linkSocket)
	sock.initPhrase1(o)

	tuntap := newTuntap(string(o.dev), o.ifconfigLocal,
		o.ifconfigRemoteNetmask)
	tuntap.openTun(string(o.dev))
	tuntap.doIfconfig()

	for {
	}
}

func main() {
	o := newOptions()
	o.parseArgs()
	o.postProcess()

	tunnelPointToPoint(o)
}
