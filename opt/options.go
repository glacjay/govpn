package opt

import (
	"govpn/e"
	"govpn/utils"
	"os"
	"strconv"
)

const MAX_PARAMS = 16

const GOVPN_PORT = 1194

type Connection struct {
	LocalHost  []byte
	LocalPort  int
	RemoteHost []byte
	RemotePort int
}

type Options struct {
	Conn Connection

	IfconfigAddress []byte
	IfconfigNetmask []byte

	OCC bool

	Verbosity uint
}

func NewOptions() *Options {
	o := new(Options)
	o.Conn.LocalPort = GOVPN_PORT
	o.Conn.RemotePort = GOVPN_PORT
	o.OCC = true
	o.Verbosity = 1

	o.parseArgs()
	o.postProcess()
	return o
}

func (o *Options) parseArgs() {
	args := os.Args
	if len(args) < 1 {
		usage()
	}
	for i := 1; i < len(args); i++ {
		p := make([]string, 0, MAX_PARAMS)
		p = append(p, args[i])
		if p[0][:2] != "--" {
			e.Msg(e.MUsage, "I'm trying to parse '%s' as an option parameter but I don't see a leading '--'.", p[0])
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
		o.AddOption(p, e.MUsage)
		i += j - 1
	}
}

func (o *Options) AddOption(p []string, msglevel uint) {
	switch p[0] {
	case "help":
		usage()
	case "version":
		usageVersion()
	case "ifconfig":
		if utils.IsValidHost(p[1]) && utils.IsValidHost(p[2]) {
			o.IfconfigAddress = []byte(p[1])
			o.IfconfigNetmask = []byte(p[2])
		} else {
			e.Msg(msglevel, "ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	case "remote":
		o.Conn.RemoteHost = []byte(p[1])
		if len(p) > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !utils.IsValidPort(port) {
				e.Msg(msglevel, "remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.Conn.RemotePort = port
		}
	case "disable-occ":
		o.OCC = false
	case "verb":
		o.Verbosity = uint(utils.PosAtoi(p[1]))
	default:
		e.Msg(msglevel, "unrecognized option or missing parameter(s): --%s.", p[0])
	}
}

func (o *Options) postProcess() {
	o.postProcessVerify()
}

func (o *Options) postProcessVerify() {
	o.postProcessVerifyCe(&o.Conn)
}

func (o *Options) postProcessVerifyCe(Conn *Connection) {
	if utils.StringDefinedEqual(Conn.LocalHost, Conn.RemoteHost) &&
		Conn.LocalPort == Conn.RemotePort {
		e.Msg(e.MUsage, "--remote and --local addresses are the same.")
	}
	if utils.StringDefinedEqual(Conn.RemoteHost, o.IfconfigAddress) ||
		utils.StringDefinedEqual(Conn.RemoteHost, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "--remote address must be distinct from --ifconfig addresses.")
	}
	if utils.StringDefinedEqual(Conn.LocalHost, o.IfconfigAddress) ||
		utils.StringDefinedEqual(Conn.LocalHost, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "--local address must be distinct from --ifconfig addresses.")
	}
	if utils.StringDefinedEqual(o.IfconfigAddress, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "local and remote/netmask --ifconfig addresses must be different.")
	}
}

func (o *Options) OptionsString() string {
	out := "V4"
	if o.IfconfigAddress != nil {
		out += ",ifconfig " + o.ifconfigOptionsString()
	}
	return out
}

func (o *Options) ifconfigOptionsString() string {
	return utils.GetNetwork(o.IfconfigAddress, o.IfconfigNetmask) + " " +
		string(o.IfconfigNetmask)
}

func usage() {
	e.Msg(e.MUsage, "Usage: ...\n")
	os.Exit(1)
}

func usageVersion() {
	e.Msg(e.MInfo|e.MNoPrefix, "Version: ...\n")
	os.Exit(1)
}
