package main

import (
	"time"
)

var now int64 = 0

func updateTime() {
	realTime := time.Seconds()
	if now != realTime {
		now = realTime
	}
}
