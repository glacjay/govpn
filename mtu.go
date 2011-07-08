package main

import (
	"log"
)

const (
	TUN_MTU_DEFAULT  = 1500
	LINK_MTU_DEFAULT = 1500

	TUN_MTU_MIN = 100

	PAYLOAD_ALIGN = 4
)

// frame.alignFlags
const (
	FRAME_HEADROOM_MARKER_DECRYPT uint = 1 << iota
	FRAME_HEADROOM_MARKER_FRAGMENT
	FRAME_HEADROOM_MARKER_READ_LINK
	FRAME_HEADROOM_MARKER_READ_STREAM
)

type frame struct {
	linkMtu        int
	linkMtuDynamic int

	extraFrame  int
	extraBuffer int
	extraTun    int
	extraLink   int

	alignFlags  uint
	alignAdjust int
}

func (f *frame) finalizeOptions(o *options) {
	f.alignToExtraFrame()
	f.orAlignFlags(FRAME_HEADROOM_MARKER_FRAGMENT |
		FRAME_HEADROOM_MARKER_READ_LINK |
		FRAME_HEADROOM_MARKER_READ_STREAM)

	f.finalize(o)
}

func (f *frame) alignToExtraFrame() {
	f.alignAdjust = f.extraFrame + f.extraLink
}

func (f *frame) orAlignFlags(flagMask uint) {
	f.alignFlags |= flagMask
}

func (f *frame) finalize(o *options) {
	if o.tunMtuDefined {
		f.linkMtu = o.tunMtu + f.tunLinkDelta()
	}
	if f.tunMtuSize() < TUN_MTU_MIN {
		log.Printf("TUN MTU value (%d) must be at least %d.",
			f.tunMtuSize(), TUN_MTU_MIN)
		f.print_(true, "MTU is too small")
	}
	f.linkMtuDynamic = f.linkMtu
	f.extraBuffer += PAYLOAD_ALIGN
}

func (f *frame) tunLinkDelta() int {
	return f.extraFrame + f.extraTun
}

func (f *frame) tunMtuSize() int {
	return f.linkMtu - f.tunLinkDelta()
}

func (f *frame) print_(exit bool, prefix string) {
	fn := log.Printf
	if exit {
		fn = log.Fatalf
	}
	if len(prefix) > 0 {
		prefix += " "
	}
	fn("%s[L:%d D:%d EF:%d EB:%d ET:%d EL:%d AF:%d/%d]\n", prefix,
		f.linkMtu, f.linkMtuDynamic, f.extraFrame, f.extraBuffer,
		f.extraTun, f.extraLink, f.alignFlags, f.alignAdjust)
}

func (f *frame) bufSize() int {
	return f.tunMtuSize() + 2*f.headroomBase()
}

func (f *frame) headroomBase() int {
	return f.tunLinkDelta() + f.extraBuffer + f.extraLink
}

func (f *frame) initSocket(sock *linkSocket) {
}
