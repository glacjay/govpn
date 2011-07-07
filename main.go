package main

import (
	"log"
)

type context struct {
	options *options

	eventSet *eventSet

	linkSocket *linkSocket

	c1 context1
	c2 context2
}

type context1 struct {

}

type context2 struct {
	frame frame
}

func (c *context) initContext1() {
	// TODO clear c.c1
}

func (c *context) tunnelPointToPoint() {
	// TODO clear c.c2
	c.initInstance()
}

func (c *context) initInstance() {
	c.doOptionWarnings()
	c.eventSet = new(eventSet)
	c.linkSocket = new(linkSocket)
	c.c2.frame.finalizeOptions(c.options)
}

func (c *context) doOptionWarnings() {
	o := c.options
	if o.ce.localPort == GOVPN_PORT && o.ce.remotePort == GOVPN_PORT {
		log.Printf("IMPORTANT: GoVPN's default port number is now %d, based on an offical port number assignment by IANA.  OpenVPN 2.0-beta16 and earlier used 5000 as the default port.", GOVPN_PORT)
	}
}

func main() {
	err := initStatic()
	if err != nil {
		log.Fatalf("Can't init statically: %v\n", err)
	}
	defer exitStatic()

	c := new(context)
	c.options = newOptions()
	c.options.parseArgs()
	c.options.postProcess()
	log.Printf("%s.", titleString)
	c.initContext1()
	c.tunnelPointToPoint()
}
