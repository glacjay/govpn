package main

import (
	"os"
)

func initStatic() os.Error {
	initRandomSeed()
	updateTime()
	return nil
}

func exitStatic() {
}
