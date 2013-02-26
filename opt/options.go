package opt

import (
	"github.com/glacjay/govpn/e"
	"github.com/glacjay/govpn/utils"
	"os"
	"strconv"
)

const MAX_PARAMS = 16

const GOVPN_PORT = 1194

func usage() {
	e.Msg(e.MUsage, "Usage: ...\n")
	os.Exit(1)
}

func usageVersion() {
	e.Msg(e.MInfo|e.MNoPrefix, "Version: ...\n")
	os.Exit(1)
}

func stringDefinedEqual(s1, s2 string) bool {
	return s1 != "" && s2 != "" && s1 == s2
}

type Connection struct {
	LocalHost  string
	LocalPort  int
	RemoteHost string
	RemotePort int
}

type Options struct {
	Conn Connection

	IfconfigAddress string
	IfconfigNetmask string

	EnableOCC bool

	Verbosity uint
	Mute      int
}

func NewOptions() *Options {
	o := new(Options)
	o.Conn.LocalPort = GOVPN_PORT
	o.Conn.RemotePort = GOVPN_PORT
	o.EnableOCC = true
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

func (o *Options) postProcess() {
	o.postProcessVerify()
}

func (o *Options) postProcessVerify() {
	o.postProcessVerifyCe(&o.Conn)
}

func (o *Options) postProcessVerifyCe(Conn *Connection) {
	if stringDefinedEqual(Conn.LocalHost, Conn.RemoteHost) &&
		Conn.LocalPort == Conn.RemotePort {
		e.Msg(e.MUsage, "--remote and --local addresses are the same.")
	}
	if stringDefinedEqual(Conn.RemoteHost, o.IfconfigAddress) ||
		stringDefinedEqual(Conn.RemoteHost, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "--remote address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(Conn.LocalHost, o.IfconfigAddress) ||
		stringDefinedEqual(Conn.LocalHost, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "--local address must be distinct from --ifconfig addresses.")
	}
	if stringDefinedEqual(o.IfconfigAddress, o.IfconfigNetmask) {
		e.Msg(e.MUsage, "local and remote/netmask --ifconfig addresses must be different.")
	}
}

func (o *Options) OptionsString() string {
	out := "V4"
	if o.IfconfigAddress != "" {
		out += ",ifconfig " + o.ifconfigOptionsString()
	}
	return out
}

func (o *Options) ifconfigOptionsString() string {
	return utils.GetNetwork(o.IfconfigAddress, o.IfconfigNetmask) + " " +
		string(o.IfconfigNetmask)
}

func (o *Options) AddOption(p []string, msglevel uint) {
	name := p[0]
	num := len(p)
	if name == "help" {
		usage()
	} else if name == "version" {
		usageVersion()
	} else if name == "ifconfig" && num > 2 {
		if utils.IsValidHost(p[1]) && utils.IsValidHost(p[2]) {
			o.IfconfigAddress = p[1]
			o.IfconfigNetmask = p[2]
		} else {
			e.Msg(msglevel, "ifconfig params '%s' and '%s' must be valid addresses.", p[1], p[2])
			return
		}
	} else if name == "remote" && num > 1 {
		o.Conn.RemoteHost = p[1]
		if num > 2 {
			port, err := strconv.Atoi(p[2])
			if err != nil || !utils.IsValidPort(port) {
				e.Msg(msglevel, "remote: port number associated with host %s is out of range.", p[1])
				return
			}
			o.Conn.RemotePort = port
		}
	} else if name == "disable-occ" {
		o.EnableOCC = false
	} else if name == "verb" && num > 1 {
		o.Verbosity = uint(utils.PosAtoi(p[1]))
	} else if name == "mute" && num > 1 {
		o.Mute = utils.PosAtoi(p[1])
	} else {
		e.Msg(msglevel, "unrecognized option or missing parameter(s): --%s.", p[0])
	}
}
