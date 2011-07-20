package main

import (
	"log"
	"time"
)

// const, actually
var occMagic = [16]byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}

// OCC Message Types
const (
	OCC_REQUEST = 0
	OCC_REPLY   = 1
)

type occ struct {
	request bool

	localString  string
	remoteString string

	stop chan bool
	out  chan<- []byte
}

func newOCC(o *options) *occ {
	occ := new(occ)
	occ.request = true
	occ.stop = make(chan bool, 1)
	return occ
}

func (occ *occ) run() {
	go occ.outLoop()
}

func (occ *occ) outLoop() {
	for i := 0; i < 12; i++ {
		select {
		case _ = <-occ.stop:
			return
		case _ = <-time.After(1e9 * 10):
			occ.out <- occ.reqMsg()
		}
	}
}

func (occ *occ) reqMsg() []byte {
	msg := make([]byte, 17)
	copy(msg, occMagic[:])
	msg[16] = OCC_REQUEST
	return msg
}

func (occ *occ) replyMsg() []byte {
	msg := make([]byte, 18+len(occ.localString))
	copy(msg, occMagic[:])
	msg[16] = OCC_REPLY
	copy(msg[17:], occ.localString)
	msg[len(msg)-1] = 0
	return msg
}

func (occ *occ) processReceivedMsg(msg []byte, out chan<- []byte) {
	msg = msg[16:]
	switch msg[0] {
	case OCC_REQUEST:
		out <- occ.replyMsg()
	case OCC_REPLY:
		occ.stop <- true
		remoteString := string(msg[1 : len(msg)-1])
		if remoteString != occ.remoteString {
			log.Printf("NOTE: Options consistency check may be skewed by version differences.")
			// TODO More detailed check
		}
	default:
	}
}

func isOCCMsg(msg []byte) bool {
	return msg != nil && len(msg) > 16 &&
		string(msg[:16]) == string(occMagic[:])
}
