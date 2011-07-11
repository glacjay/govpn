package main

import (
	"bytes"
	"log"
)

type context struct {
	options *options

	c1 context1
	c2 context2
}

type context1 struct {
	linkSocketAddr linkSocketAddr

	tuntap *tuntap
}

type context2 struct {
	frame   frame
	buffers *contextBuffers

	linkSocket *linkSocket

	didOpenTun bool
}

func (c *context) initContext1() {
	// TODO clear c.c1
}

func (c *context) tunnelPointToPoint() {
	// TODO clear c.c2
	c.initInstance()
	for {
	}
}

func (c *context) initInstance() {
	c.doOptionWarnings()
	c.c2.linkSocket = new(linkSocket)
	c.c2.frame.finalizeOptions(c.options)
	c.c2.buffers = newContextBuffers(&c.c2.frame)
	c.initSocket1()
	c.c2.didOpenTun = c.openTun()
	c.c2.frame.print_(false, "Data Channel MTU parms")
	c.initSocket2()
}

func (c *context) doOptionWarnings() {
	o := c.options
	if o.ce.localPort == GOVPN_PORT && o.ce.remotePort == GOVPN_PORT {
		log.Printf("IMPORTANT: GoVPN's default port number is now %d, based on an offical port number assignment by IANA.  OpenVPN 2.0-beta16 and earlier used 5000 as the default port.", GOVPN_PORT)
	}
}

func (c *context) initSocket1() {
	c.c2.linkSocket.initPhrase1(c.options, &c.c1.linkSocketAddr)
}

func (c *context) openTun() bool {
	if c.c1.tuntap == nil {
		c.initTun()
		c.c1.tuntap.openTun(string(c.options.dev))
		c.c1.tuntap.doIfconfig(c.c2.frame.tunMtuSize())
	}
	return false
}

func (c *context) initTun() {
	c.c1.tuntap = newTuntap(string(c.options.dev),
		c.options.ifconfigLocal, c.options.ifconfigRemoteNetmask,
		c.c1.linkSocketAddr.local, c.c1.linkSocketAddr.remote)
}

func (c *context) initSocket2() {
	c.c2.linkSocket.initPhrase2(&c.c2.frame)
}

type contextBuffers struct {
	auxBuf *bytes.Buffer

	readLinkBuf *bytes.Buffer
	readTunBuf  *bytes.Buffer
}

func newContextBuffers(f *frame) *contextBuffers {
	b := new(contextBuffers)
	b.readLinkBuf = bytes.NewBuffer(make([]byte, f.bufSize()))
	b.readTunBuf = bytes.NewBuffer(make([]byte, f.bufSize()))
	b.auxBuf = bytes.NewBuffer(make([]byte, f.bufSize()))
	return b
}

func main() {
	c := new(context)
	c.options = newOptions()
	c.options.parseArgs()
	c.options.postProcess()
	log.Printf("%s.", titleString)
	c.initContext1()
	c.tunnelPointToPoint()
}
