package sig

import (
	"os"
	ossignal "os/signal"
	"syscall"
)

type Signal struct {
	Signo syscall.Signal
	Hard  bool
	Text  string
}

var Signals = make(chan *Signal, 1)

func init() {
	signalsFromOS := make(chan os.Signal, 1)
	ossignal.Notify(signalsFromOS, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	go signalLoop(signalsFromOS)
}

func signalLoop(signalsFromOS <-chan os.Signal) {
	for {
		signal := <-signalsFromOS
		signo := signal.(syscall.Signal)
		Signals <- &Signal{Signo: signo, Hard: true, Text: signal.String()}
	}
}

func ThrowSignalSoft(signo syscall.Signal, text string) {
	Signals <- &Signal{Signo: signo, Hard: false, Text: text}
}
