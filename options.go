package main

import (
	"log"
	"os"
	"strconv"
)

const titleString = "GoVPN 0.1 i686-pc-linux-gnu built on ... someday"

const MAX_PARAMS = 16

type connectionEntry struct {
	localPort  int
	remotePort int
	local      []byte
	remote     []byte
}

type options struct {
	ce connectionEntry

	dev []byte

	ifconfigLocal         []byte
	ifconfigRemoteNetmask []byte

	sndbuf int
	rcvbuf int

	tunMtu        int
	tunMtuDefined bool
	linkMtu       int
}

func newOptions() *options {
	o := new(options)
	o.ce.localPort = GOVPN_PORT
	o.ce.remotePort = GOVPN_PORT
	o.sndbuf = 65536
	o.rcvbuf = 65536
	o.tunMtu = TUN_MTU_DEFAULT
	o.linkMtu = LINK_MTU_DEFAULT
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
	case "dev":
		o.dev = []byte(p[1])
	case "ifconfig":
		if isValidIpOrDns(p[1]) && isValidIpOrDns(p[2]) {
			o.ifconfigLocal = []byte(p[1])
			o.ifconfigRemoteNetmask = []byte(p[2])
		} else {
			log.Printf("ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	case "remote":
		o.ce.remote = []byte(p[1])
		if len(p) > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !isValidIpv4Port(port) {
				log.Printf("remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.ce.remotePort = port
		}
	case "sndbuf":
		o.sndbuf = positiveAtoi(p[1])
	case "rcvbuf":
		o.rcvbuf = positiveAtoi(p[1])
	default:
		log.Printf("unrecognized option or missing parameter(s): --%s.", p[0])
	}
}

func (o *options) postProcess() {
	o.postProcessMutate()
	o.postProcessVerify()
}

func (o *options) postProcessMutate() {
	o.postProcessMutateInvariant()
}

func (o *options) postProcessMutateInvariant() {
	o.tunMtuDefined = true
}

func (o *options) postProcessVerify() {
	o.postProcessVerifyCe(&o.ce)
}

func (o *options) postProcessVerifyCe(ce *connectionEntry) {
	notNull(o.dev, "TUN/TAP device (--dev)")

	if stringDefinedEqual(ce.local, ce.remote) &&
		ce.localPort == ce.remotePort {
		log.Fatalf("--remote and --local addresses are the same.")
	}
	if stringDefinedEqual(ce.remote, o.ifconfigLocal) ||
		stringDefinedEqual(ce.remote, o.ifconfigRemoteNetmask) {
		log.Fatalf("--remote address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(ce.local, o.ifconfigLocal) ||
		stringDefinedEqual(ce.local, o.ifconfigRemoteNetmask) {
		log.Fatalf("--local address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(o.ifconfigLocal, o.ifconfigRemoteNetmask) {
		log.Fatalf("local and remote/netmask --ifconfig addresses must be different.")
	}
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
