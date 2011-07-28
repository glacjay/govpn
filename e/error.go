package e

import (
	"fmt"
	"io"
	"os"
	"syslog"
	"time"
)

// exit status codes
const (
	ExitGood = iota
	ExitError
	ExitUsage
	ExitOpenDebug
)

var debugLevel uint = 1

const debugLevelMask = 0x0F

// msg() flags
const (
	MFatal    = 1 << 4 // fatal error, exit program
	MNonFatal = 1 << 5 // non-fatal error
	MWarning  = 1 << 6 // call syslog() with LOG_WARNING
	MDebug    = 1 << 7

	// MErrno      = 1 << 8  // show errno description
	// MErrnoSock  = 1 << 9  // show socket errno description
	// MSSL        = 1 << 10 // show SSL error
	MNoMute     = 1 << 11 // don't do mute processing
	MNoPrefix   = 1 << 12 // don't show date/time prefix
	MUsageSmall = 1 << 13 // fatal options error, call usage_small()
	// MVirtOut    = 1 << 14 // output message through msg_status_output() callback
	MOptErr = 1 << 15 // print "Options error:" prefix
	// MNoLF       = 1 << 16
	// MNoIPrefix  = 1 << 17
)

// flag combinations which are frequently used
const (
	MError     = MFatal // | MErrno
	MErrorSock = MFatal // | MErrnoSock
	MErrorSSL  = MFatal // | MSSL
	MUsage     = MUsageSmall | MNoPrefix | MOptErr
	// MClient = MVirtOut | MNoMute // | MNoIPrefix
)

// Mute levels are designed to avoid large numbers of mostly similar messages
// clogging the log file.
const (
	muteLevelMask  = 24
	muteLevelShift = 0xFF
)

// logLevel:  verbosity level n (--verb n) must be >= logLevel to print.
// muteLevel: don't print more than n (--mute n) consecutive messages at a
//            given muteLevel, or if 0 disable muting and print everything.
//
// Mask map:
//   Bits 00-03: log level
//   Bits 04-23: M_x flags
//   Bits 24-31: mute level
func loglev(logLevel, muteLevel, other uint) uint {
	return logLevel |
		((muteLevel & muteLevelMask) << muteLevelShift) |
		other
}

var (
	muteCutoff   int
	muteCount    int
	muteCategory uint
)

func doMute(flags uint) bool {
	ret := false
	if muteCutoff > 0 && flags&MNoMute == 0 {
		muteLevel := (flags >> muteLevelShift) & muteLevelMask
		if muteLevel > 0 && muteLevel == muteCategory {
			if muteCount == muteCutoff {
				Msg(MInfo|MNoMute, "NOTE: --mute triggered...")
			}
			muteCount++
			if muteCount > muteCutoff {
				ret = true
			}
		} else {
			suppressed := muteCount - muteCutoff
			if suppressed > 0 {
				Msg(MInfo|MNoMute, "%d variation(s) on previous %d message(s) suppressed by --mute.", suppressed, muteCutoff)
			}
			muteCount = 1
			muteCategory = muteLevel
		}
	}
	return ret
}

type message struct {
	flags uint
	msg   string
}

var messages chan *message

func init() {
	messages = make(chan *message, 100)
	go msgLoop()
}

func Msg(flags uint, format string, v ...interface{}) {
	if flags&debugLevelMask <= debugLevel && !doMute(flags) {
		m := fmt.Sprintf(format, v...)
		messages <- &message{flags: flags, msg: m}
	}
}

var (
	logger *syslog.Writer

	useSyslog          bool
	redirectStd        bool
	suppressTimestamps bool
)

func init() {
	logger, _ = syslog.New(syslog.LOG_DEBUG, "")
}

func msgLoop() {
	for {
		m := <-messages
		xMsg(m.flags, m.msg)
	}
}

func xMsg(flags uint, m string) {
	if flags&MOptErr > 0 {
		m = "Options error: " + m
	}

	if useSyslog && !redirectStd && logger != nil {
		if flags&(MFatal|MNonFatal|MUsageSmall) > 0 {
			logger.Err(m)
		} else if flags&MWarning > 0 {
			logger.Warning(m)
		} else {
			logger.Notice(m)
		}
	} else {
		wr := msgWr(flags)
		showUsec := checkDebugLevel(debugLevelUsecTime)
		if flags&MNoPrefix > 0 || suppressTimestamps {
			fmt.Fprintf(wr, "%s\n", m)
		} else {
			fmt.Fprintf(wr, "%s %s\n", timeString(showUsec), m)
		}
	}

	if flags&MFatal > 0 {
		xMsg(MInfo, "Exiting.")
		Exit(ExitError)
	}

	if flags&MUsageSmall > 0 {
		xMsg(MWarning|MNoPrefix, "Use --help for more information.")
		Exit(ExitUsage)
	}
}

var (
	msgwr      io.Writer
	defaultOut io.Writer
	defaultErr io.Writer
)

func init() {
	msgwr = os.Stdout
	defaultOut = os.Stdout
	defaultErr = os.Stderr
}

func msgWr(flags uint) io.Writer {
	wr := msgwr
	if wr == nil {
		if flags&(MFatal|MUsageSmall) > 0 {
			wr = defaultErr
		} else {
			wr = defaultOut
		}
	}
	if wr == nil {
		Exit(ExitOpenDebug)
	}
	return wr
}

func Exit(status int) {
	if logger != nil {
		logger.Close()
	}

	os.Exit(status)
}

func checkDebugLevel(level uint) bool {
	return level&debugLevelMask <= debugLevel
}

func timeString(showUsec bool) string {
	buf := time.LocalTime().Format("2006-01-02 15:04:05")
	if showUsec {
		buf += fmt.Sprintf(" us=%06d", (time.Nanoseconds()/1e3)%1e6)
	}
	return buf
}

func SetDebugLevel(level uint) {
	debugLevel = level
}
