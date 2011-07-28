package main

import (
	"govpn/e"
	"govpn/utils"
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

	occ bool

	verbosity uint
}

func newOptions() *options {
	o := new(options)
	o.ce.localPort = GOVPN_PORT
	o.ce.remotePort = GOVPN_PORT
	o.occ = true
	o.verbosity = 1
	return o
}

func (o *options) parseArgs(msglevel uint) {
	args := os.Args
	if len(args) < 1 {
		usage()
	}
	for i := 1; i < len(args); i++ {
		p := make([]string, 0, MAX_PARAMS)
		p = append(p, args[i])
		if p[0][:2] != "--" {
			e.Msg(msglevel, "I'm trying to parse '%s' as an option parameter but I don't see a leading '--'.", p[0])
		} else {
			p[0] = p[0][2:]
		}
		var j int
		for j = 1; j < MAX_PARAMS; j++ {
			if i+j < len(args) {
				arg := args[i+j]
				if len(arg) < 2 || arg[:2] != "--" {
					p = append(p, arg)
				} else {
					break
				}
			}
		}
		o.addOption(p, msglevel)
		i += j - 1
	}
}

func (o *options) addOption(p []string, msglevel uint) {
	switch p[0] {
	case "help":
		usage()
	case "version":
		usageVersion()
	case "ifconfig":
		if utils.IsValidHost(p[1]) && utils.IsValidHost(p[2]) {
			o.ifconfigAddress = []byte(p[1])
			o.ifconfigNetmask = []byte(p[2])
		} else {
			e.Msg(msglevel, "ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	case "remote":
		o.ce.remoteHost = []byte(p[1])
		if len(p) > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !utils.IsValidPort(port) {
				e.Msg(msglevel, "remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.ce.remotePort = port
		}
	case "disable-occ":
		o.occ = false
	case "verb":
		o.verbosity = uint(utils.PosAtoi(p[1]))
	default:
		e.Msg(msglevel, "unrecognized option or missing parameter(s): --%s.", p[0])
	}
}

func (o *options) postProcess() {
	o.postProcessVerify()
}

func (o *options) postProcessVerify() {
	o.postProcessVerifyCe(&o.ce)
}

func (o *options) postProcessVerifyCe(ce *connectionEntry) {
	if utils.StringDefinedEqual(ce.localHost, ce.remoteHost) &&
		ce.localPort == ce.remotePort {
		e.Msg(e.MUsage, "--remote and --local addresses are the same.")
	}
	if utils.StringDefinedEqual(ce.remoteHost, o.ifconfigAddress) ||
		utils.StringDefinedEqual(ce.remoteHost, o.ifconfigNetmask) {
		e.Msg(e.MUsage, "--remote address must be distinct from --ifconfig addresses.")
	}
	if utils.StringDefinedEqual(ce.localHost, o.ifconfigAddress) ||
		utils.StringDefinedEqual(ce.localHost, o.ifconfigNetmask) {
		e.Msg(e.MUsage, "--local address must be distinct from --ifconfig addresses.")
	}
	if utils.StringDefinedEqual(o.ifconfigAddress, o.ifconfigNetmask) {
		e.Msg(e.MUsage, "local and remote/netmask --ifconfig addresses must be different.")
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
	return utils.GetNetwork(o.ifconfigAddress, o.ifconfigNetmask) + " " +
		string(o.ifconfigNetmask)
}

func usage() {
	e.Msg(e.MUsage, "Usage: ...\n")
	os.Exit(1)
}

func usageVersion() {
	e.Msg(e.MInfo|e.MNoPrefix, "Version: ...\n")
	os.Exit(1)
}
