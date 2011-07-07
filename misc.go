package main

import (
	"rand"
	"time"
)

func initRandomSeed() {
	rand.Seed(time.Seconds() ^ time.Nanoseconds())
}
