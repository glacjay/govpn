package main

import (
	"log"
	"net"
	"os"
	"strconv"
)

const MAX_PARAMS = 16

type connectionEntry struct {
	localHost  []byte
	localPort  int
	remoteHost []byte
	remotePort int
}

type options struct {
	ce connectionEntry

	ifconfigAddress []byte
	ifconfigNetmask []byte

	occ *occ
}

func newOptions() *options {
	o := new(options)
	o.ce.localPort = GOVPN_PORT
	o.ce.remotePort = GOVPN_PORT
	o.occ = newOCC(o)
	return o
}

func (o *options) parseArgs() {
	args := os.Args
	if len(args) < 1 {
		usage()
	}
	for i := 1; i < len(args); i++ {
		p := make([]string, 0, MAX_PARAMS)
		p = append(p, args[i])
		if p[0][:2] != "--" {
			log.Printf("I'm trying to parse '%s' as an option parameter but I don't see a leading '--'.", p[0])
		} else {
			p[0] = p[0][2:]
		}
		var j int
		for j = 1; j < MAX_PARAMS; j++ {
			if i+j < len(args) {
				arg := args[i+j]
				if arg[:2] != "--" {
					p = append(p, arg)
				} else {
					break
				}
			}
		}
		o.addOption(p)
		i += j - 1
	}
}

func (o *options) addOption(p []string) {
	switch p[0] {
	case "help":
		usage()
	case "version":
		usageVersion()
	case "ifconfig":
		if validHost(p[1]) && validHost(p[2]) {
			o.ifconfigAddress = []byte(p[1])
			o.ifconfigNetmask = []byte(p[2])
		} else {
			log.Printf("ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	case "remote":
		o.ce.remoteHost = []byte(p[1])
		if len(p) > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !validPort(port) {
				log.Printf("remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.ce.remotePort = port
		}
	case "disable-occ":
		o.occ.request = false
	default:
		log.Printf("unrecognized option or missing parameter(s): --%s.", p[0])
	}
}

func (o *options) postProcess() {
	o.postProcessVerify()
}

func (o *options) postProcessVerify() {
	o.postProcessVerifyCe(&o.ce)
}

func (o *options) postProcessVerifyCe(ce *connectionEntry) {
	if stringDefinedEqual(ce.localHost, ce.remoteHost) &&
		ce.localPort == ce.remotePort {
		log.Fatalf("--remote and --local addresses are the same.")
	}
	if stringDefinedEqual(ce.remoteHost, o.ifconfigAddress) ||
		stringDefinedEqual(ce.remoteHost, o.ifconfigNetmask) {
		log.Fatalf("--remote address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(ce.localHost, o.ifconfigAddress) ||
		stringDefinedEqual(ce.localHost, o.ifconfigNetmask) {
		log.Fatalf("--local address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(o.ifconfigAddress, o.ifconfigNetmask) {
		log.Fatalf("local and remote/netmask --ifconfig addresses must be different.")
	}
}

func (o *options) optionsString() string {
	out := "V4"
	if o.ifconfigAddress != nil {
		out += ",ifconfig " + o.ifconfigOptionsString()
	}
	return out
}

func (o *options) ifconfigOptionsString() string {
	return getNetworkIP(o.ifconfigAddress, o.ifconfigNetmask) + " " +
		string(o.ifconfigNetmask)
}

func usage() {
	log.Printf("Usage: ...\n")
	os.Exit(1)
}

func usageVersion() {
	log.Printf("Version: ...\n")
	os.Exit(1)
}

func positiveAtoi(str string) int {
	i, err := strconv.Atoi(str)
	if err != nil || i < 0 {
		i = 0
	}
	return i
}

func notNull(arg []byte, desc string) {
	if arg == nil {
		log.Fatalf("You must define %s.", desc)
	}
}

func stringDefinedEqual(s1, s2 []byte) bool {
	if s1 != nil && s2 != nil {
		return string(s1) == string(s2)
	}
	return false
}

func getNetworkIP(address, netmask []byte) string {
	addr := net.ParseIP(string(address))
	mask := net.ParseIP(string(netmask))
	for i := 0; i < len(addr); i++ {
		addr[i] &= mask[i]
	}
	return addr.String()
}
