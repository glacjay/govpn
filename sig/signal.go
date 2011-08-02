package sig

import (
	"os"
	ossignal "os/signal"
	"syscall"
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
		signal := <-ossignal.Incoming
		signo := int32(signal.(os.UnixSignal))
		if signo == syscall.SIGINT || signo == syscall.SIGTERM ||
			signo == syscall.SIGHUP ||
			signo == syscall.SIGUSR1 || signo == syscall.SIGUSR2 {
			Signals <- &Signal{Signo: signo,
				Hard: true, Text: signal.String()}
		}
	}
}
