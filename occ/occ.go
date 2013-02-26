package occ

import (
	"github.com/glacjay/govpn/e"
	"github.com/glacjay/govpn/opt"
	"time"
)

// const, actually
var messageHeader = [16]byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}

// OCC Message Types
const (
	requestOpcode = 0
	replyOpcode   = 1
)

type OCC struct {
	commandChan chan int
	outputChan  chan<- []byte

	localString  string
	remoteString string
}

func New(o *opt.Options, outputChan chan<- []byte) *OCC {
	occ := new(OCC)
	occ.commandChan = make(chan int, 1)
	occ.outputChan = outputChan

	occ.localString = o.OptionsString()
	e.Msg(e.MInfo, "Local Options String: '%s'", occ.localString)
	occ.remoteString = o.OptionsString()
	e.Msg(e.MInfo, "Expected Remote Options String: '%s'", occ.remoteString)

	return occ
}

func (occ *OCC) StartSendingRequest() {
	go occ.outputLoop()
}

func (occ *OCC) outputLoop() {
	for i := 0; i < 12; i++ {
		select {
		case _ = <-occ.commandChan:
			return
		case _ = <-time.After(1e9 * 10):
			occ.outputChan <- occ.requestMessage()
		}
	}
}

func (occ *OCC) Stop() {
	occ.commandChan <- 1
}

func (occ *OCC) requestMessage() []byte {
	msg := make([]byte, 17)
	copy(msg, messageHeader[:])
	msg[16] = requestOpcode
	return msg
}

func (occ *OCC) replyMessage() []byte {
	msg := make([]byte, 18+len(occ.localString))
	copy(msg, messageHeader[:])
	msg[16] = replyOpcode
	copy(msg[17:], occ.localString)
	msg[len(msg)-1] = 0
	return msg
}

func (occ *OCC) CheckOccMessage(msg []byte) bool {
	if msg == nil || len(msg) <= 16 || string(msg[:16]) != string(messageHeader[:]) {
		return false
	}

	msg = msg[16:]
	switch msg[0] {
	case requestOpcode:
		occ.outputChan <- occ.replyMessage()
	case replyOpcode:
		occ.Stop()
		remoteString := string(msg[1 : len(msg)-1])
		if remoteString != occ.remoteString {
			e.Msg(e.DShowOCC, "NOTE: Options consistency check may be skewed by version differences.")
			// TODO More detailed check
		}
	default:
	}
	return true
}
