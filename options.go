package main

import (
	"log"
	"os"
	"path"
	"strconv"
)

const MAX_PARAMS = 16

// pingRecvTimeoutAction
const (
	PING_UNDEF = iota
	PING_EXIT
	PING_RESTART
)

type connectionEntry struct {
	localPort  int
	remotePort int
	local      string
	remote     string
}

type options struct {
	config string

	ce connectionEntry

	dev     string
	devType string
	devNode string

	ifconfigLocal         string
	ifconfigRemoteNetmask string

	keepalivePing         int
	keepaliveTimeout      int
	pingSendTimeout       int
	pingRecvTimeout       int
	pingRecvTimeoutAction int

	tuntapOptions tuntapOptions

	sendbuf int
	recvbuf int
}

func newOptions() *options {
	o := new(options)
	o.ce.localPort = GOVPN_PORT
	o.ce.remotePort = GOVPN_PORT
	o.sendbuf = 65536
	o.recvbuf = 65536
	o.tuntapOptions.txQueueLen = 100
	o.keepalivePing = 10
	o.keepaliveTimeout = 3 * o.keepalivePing
	o.pingSendTimeout = o.keepalivePing
	o.pingRecvTimeout = o.keepaliveTimeout
	o.pingRecvTimeoutAction = PING_RESTART
	return o
}

func (o *options) parseArgs() {
	if len(os.Args) < 1 {
		usage()
	}
	if len(os.Args) == 2 && os.Args[1][:2] != "--" {
		o.addOption([]string{"config", os.Args[1]})
	} else {
		for i := 1; i < len(os.Args); i++ {
			p := make([]string, MAX_PARAMS)
			p[0] = os.Args[i]
			if p[0][:2] != "--" {
				log.Printf("I'm trying to parse \"%s\" as an option parameter but I don't see a leading '--'.", p[0])
			} else {
				p[0] = p[0][2:]
			}
			var j int
			for j = 1; j < MAX_PARAMS; j++ {
				if i+j < len(os.Args) {
					arg := os.Args[i+j]
					if arg[:2] != "--" {
						p[j] = arg
					} else {
						break
					}
				}
			}
			p = p[:j]
			o.addOption(p)
			i += j - 1
		}
	}
}

func (o *options) readConfigFile(filename string) {
}

func (o *options) addOption(p []string) {
	switch p[0] {
	case "help":
		usage()
	case "version":
		usageVersion()
	case "config":
		if len(o.config) == 0 {
			o.config = p[1]
		}
		o.readConfigFile(p[1])
	case "dev":
		o.dev = p[1]
	case "dev-type":
		o.devType = p[1]
	case "dev-node":
		o.devNode = p[1]
	case "ifconfig":
		if isValidIpOrDns(p[1]) && isValidIpOrDns(p[2]) {
			o.ifconfigLocal = p[1]
			o.ifconfigRemoteNetmask = p[2]
		} else {
			log.Printf("ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	case "remote":
		o.ce.remote = p[1]
		if len(p) > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !isValidIpv4Port(port) {
				log.Printf("remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.ce.remotePort = port
		}
	case "sndbuf":
		o.sendbuf = positiveAtoi(p[1])
	case "rcvbuf":
		o.recvbuf = positiveAtoi(p[1])
	case "txqueuelen":
		o.tuntapOptions.txQueueLen = positiveAtoi(p[1])
	default:
		log.Printf("unrecognized option or missing parameter(s): --%s.", p[0])
	}
}

func (o *options) initDev() {
	if len(o.dev) == 0 {
		o.dev = path.Base(o.devNode)
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
