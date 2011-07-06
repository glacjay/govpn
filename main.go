package main

import (
	"os"
	"rand"
	"time"
)

type context struct {
	options *options

	c1 *context1
	c2 *context2
}

type context1 struct {

}

type context2 struct {
	eventSet *eventSet
}

type eventSet struct {

}

func (c *context) newContext1() *context1 {
	return new(context1)
}

func (c *context) tunnelP2P() {
	c.c2 = new(context2)
	c.initInstance()
}

func (c *context) initInstance() {
}

func initRandomSeed() {
	rand.Seed(time.Nanoseconds())
}

func initStatic() os.Error {
	initRandomSeed()
	return nil
}

func exitStatic() {
}

func main() {
	var c context
	if err := initStatic(); err == nil {
		c.options = newOptions()
		c.options.parseArgs()
		c.options.initDev()
		c.c1 = c.newContext1()
	}
	exitStatic()
}
