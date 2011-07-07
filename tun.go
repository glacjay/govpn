package main

import (
	"net"
	"os"
)

// tuntap.type_
const (
	DEV_TYPE_UNDEF = iota
	DEV_TYPE_NULL
	DEV_TYPE_TUN
	DEV_TYPE_TAP
)

type tuntap struct {
	type_ int

	didIfconfig      bool
	didIfconfigSetup bool

	local         *net.UDPAddr
	remoteNetmask *net.UDPAddr

	fd *os.File
}

func newTuntap(dev string, localParm, remoteParm []byte,
localPublic, remotePublic *net.UDPAddr) *tuntap {
	tt := new(tuntap)
	tt.type_ = devTypeEnum(dev)

	if localParm != nil && remoteParm != nil {
		tt.local = getaddr(string(localParm), 0)
		tt.remoteNetmask = getaddr(string(remoteParm), 0)
		tt.didIfconfigSetup = true
	}

	return tt
}

func devTypeEnum(dev string) int {
	if isDevType(dev, "tun") {
		return DEV_TYPE_TUN
	} else if isDevType(dev, "tap") {
		return DEV_TYPE_TAP
	} else if isDevType(dev, "null") {
		return DEV_TYPE_NULL
	}
	return DEV_TYPE_UNDEF
}

func isDevType(dev, matchType string) bool {
	return dev[:len(matchType)] == matchType
}
