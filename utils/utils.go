package utils

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

// number class helpers

func Atoi(str string) int {
	i, err := strconv.Atoi(str)
	if err != nil {
		i = 0
	}
	return i
}

func PosAtoi(str string) int {
	i, err := strconv.Atoi(str)
	if err != nil || i < 0 {
		i = 0
	}
	return i
}

// string class helpers

func NotNull(arg []byte, what string) {
	if arg == nil {
		log.Fatalf("You must define %s.", what)
	}
}

func StringDefinedEqual(s1, s2 []byte) bool {
	if s1 != nil && s2 != nil {
		return string(s1) == string(s2)
	}
	return false
}

// network address class helpers

func IsValidHost(addr string) bool {
	return net.ParseIP(addr) != nil
}

func IsValidPort(port int) bool {
	return port > 0 && port < 65536
}

func GetAddress(host []byte, port int) *net.UDPAddr {
	str := fmt.Sprintf("%s:%d", string(host), port)
	addr, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		log.Fatalf("RESOLVE: Cannot resolve host address %s: %v.", str, err)
	}
	return addr
}

func GetNetwork(address, netmask []byte) string {
	addr := net.ParseIP(string(address))
	mask := net.ParseIP(string(netmask))
	for i := 0; i < len(addr); i++ {
		addr[i] &= mask[i]
	}
	return addr.String()
}
