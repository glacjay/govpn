package sig

import (
	"os"
	ossignal "os/signal"
)

type Signal struct {
	Signo int32
	Hard  bool
	Text  string
}

var Signals chan *Signal

func init() {
	Signals = make(chan *Signal, 1)
	go signalLoop()
}

func signalLoop() {
	for {
		s := <-ossignal.Incoming
		Signals <- &Signal{Signo: int32(s.(os.UnixSignal)),
			Hard: true, Text: s.String()}
	}
}
