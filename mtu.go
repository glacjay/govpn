package main

import (
	"log"
)

const (
	TUN_MTU_DEFAULT  = 1500
	LINK_MTU_DEFAULT = 1500

	TUN_MTU_MIN = 100
)

const (
	FRAME_HEADROOM_MARKER_DECRYPT uint = 1 << iota
	FRAME_HEADROOM_MARKER_FRAGMENT
	FRAME_HEADROOM_MARKER_READ_LINK
	FRAME_HEADROOM_MARKER_READ_STREAM
)

type frame struct {
	linkMtu int

	extraFrame int
	extraTun   int
	extraLink  int

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
	}
}

func (f *frame) tunLinkDelta() int {
	return f.extraFrame + f.extraTun
}

func (f *frame) tunMtuSize() int {
	return f.linkMtu - f.tunLinkDelta()
}
