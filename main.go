package main

import (
	"os"
)

type context struct {
	firstTime bool
}

func initStatic() os.Error {
	return nil
}

func exitStatic() {
}

func main() {
	var c context
	c.firstTime = true
	if err := initStatic(); err == nil {
	}
	exitStatic()
}
