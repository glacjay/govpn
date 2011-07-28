package e

const debugLevelUsecTime = 4

var (
	MVerb0 = loglev(0, 0, 0) // messages displayed even at --verb 0 (fatal errors only)

	MInfo = loglev(1, 0, 0) // default informational messages

	DLinkErrors    = loglev(1, 1, MNonFatal)  // show link errors from main event loop
	DCryptErrors   = loglev(1, 2, MNonFatal)  // show encrypt/decrypt errors
	DTLSErrors     = loglev(1, 3, MNonFatal)  // show TLS control channel errors
	DResolveErrors = loglev(1, 4, MNonFatal)  // show hostname resolve errors
	DCompErrors    = loglev(1, 5, MNonFatal)  // show compression errors
	DReplayErrors  = loglev(1, 6, MNonFatal)  // show packet replay errors
	DStreamErrors  = loglev(1, 7, MNonFatal)  // TCP stream error requiring restart
	DImportErrors  = loglev(1, 8, MNonFatal)  // show server import option errors
	DMultiErrors   = loglev(1, 9, MNonFatal)  // show multi-client server errors
	DEventErrors   = loglev(1, 10, MNonFatal) // show event.[ch] errors
	DPushErrors    = loglev(1, 11, MNonFatal) // show push/pull errors
	DPidPersist    = loglev(1, 12, MNonFatal) // show packet_id persist errors
	DFragErrors    = loglev(1, 13, MNonFatal) // show fragmentation errors
	DAlignErrors   = loglev(1, 14, MNonFatal) // show bad struct alignments

	DHandshake   = loglev(2, 20, 0) // show data & control channel handshakes
	DMTUInfo     = loglev(2, 21, 0) // show terse MTU info
	DClose       = loglev(2, 22, 0) // show socket and TUN/TAP close
	DShowOCCHash = loglev(2, 23, 0) // show MD5 hash of option compatibility string
	DProxy       = loglev(2, 24, 0) // show http proxy control packets
	DArgv        = loglev(2, 25, 0) // show struct argv errors

	DTLSDebugLow  = loglev(3, 20, 0) // low frequency info from tls_session routines
	DGremlin      = loglev(3, 30, 0) // show simulated outage info from gremlin module
	DGenKey       = loglev(3, 31, 0) // print message after key generation
	DRoute        = loglev(3, 0, 0)  // show routes added and deleted (don't mute)
	DTUNTAPInfo   = loglev(3, 32, 0) // show debugging info from TUN/TAP driver
	DRestart      = loglev(3, 33, 0) // show certain restart messages
	DPush         = loglev(3, 34, 0) // show push/pull info
	DIfconfigPool = loglev(3, 35, 0) // show ifconfig pool info
	DBacktrack    = loglev(3, 36, 0) // show replay backtracks
	DAuth         = loglev(3, 37, 0) // show user/pass auth info
	DMultiLow     = loglev(3, 38, 0) // show point-to-multipoint low-freq debug info
	DPlugin       = loglev(3, 39, 0) // show plugin calls
	DManagement   = loglev(3, 40, 0) // show --management info
	DSchedExit    = loglev(3, 41, 0) // show arming of scheduled exit
	DRouteQuota   = loglev(3, 42, 0) // show route quota exceeded messages
	DOSBuf        = loglev(3, 43, 0) // show socket/tun/tap buffer sizes
	DPSProxy      = loglev(3, 44, 0) // messages related to --port-share option
	DPFInfo       = loglev(3, 45, 0) // packet filter informational messages

	DShowParms        = loglev(4, 50, 0) // show all parameters on program initiation
	DShowOCC          = loglev(4, 51, 0) // show options compatibility string
	DLow              = loglev(4, 52, 0) // miscellaneous low-frequency debug info
	DDHCPOpt          = loglev(4, 53, 0) // show DHCP options binary string
	DMbuf             = loglev(4, 54, 0) // mbuf.[ch] routines
	DPacketTruncError = loglev(4, 55, 0) // PACKET_TRUNCATION_CHECK
	DPFDropped        = loglev(4, 56, 0) // packet filter dropped a packet
	DMultiDropped     = loglev(4, 57, 0) // show point-to-multipoint packet drops

	DLogRW = loglev(5, 0, 0) // Print 'R' or 'W' to stdout for read/write

	DLinkRW        = loglev(6, 60, MDebug) // show TCP/UDP reads/writes (terse)
	DTUNRW         = loglev(6, 60, MDebug) // show TUN/TAP reads/writes
	DTAPWin32Debug = loglev(6, 60, MDebug) // show TAP-Win32 driver debug info

	DShowKeys         = loglev(7, 70, MDebug) // show data channel encryption keys
	DShowKeySource    = loglev(7, 70, MDebug) // show data channel key source entropy
	DRelLow           = loglev(7, 70, MDebug) // show low frequency info from reliable layer
	DFragDebug        = loglev(7, 70, MDebug) // show fragment debugging info
	DWin32IOLow       = loglev(7, 70, MDebug) // low freq win32 I/O debugging info
	DMTUDebug         = loglev(7, 70, MDebug) // show MTU debugging info
	DPidDebugLow      = loglev(7, 70, MDebug) // show low-freq packet-id debugging info
	DMultiDebug       = loglev(7, 70, MDebug) // show medium-freq multi debugging info
	DMSS              = loglev(7, 70, MDebug) // show MSS adjustments
	DCompLow          = loglev(7, 70, MDebug) // show adaptive compression state changes
	DConnectionList   = loglev(7, 70, MDebug) // show <connection> list info
	DScript           = loglev(7, 70, MDebug) // show parms & env vars passed to scripts
	DShowNet          = loglev(7, 70, MDebug) // show routing table and adapter list
	DRouteDebug       = loglev(7, 70, MDebug) // show verbose route.[ch] output
	DTLSStateErrors   = loglev(7, 70, MDebug) // no TLS state for client
	DSemaphoreLow     = loglev(7, 70, MDebug) // show Win32 semaphore waits (low freq)
	DSemaphore        = loglev(7, 70, MDebug) // show Win32 semaphore waits
	DTestFile         = loglev(7, 70, MDebug) // show test_file() calls
	DManagementDebug  = loglev(3, 70, MDebug) // show --management debug info
	DPluginDebug      = loglev(7, 70, MDebug) // show verbose plugin calls
	DSocketDebug      = loglev(7, 70, MDebug) // show socket.[ch] debugging info
	DShowPKCS11       = loglev(7, 70, MDebug) // show PKCS#11 actions
	DAlignDebug       = loglev(7, 70, MDebug) // show verbose struct alignment info
	DPacketTruncDebug = loglev(7, 70, MDebug) // PACKET_TRUNCATION_CHECK verbose
	DPing             = loglev(7, 70, MDebug) // PING send/receive messages
	DPSProxyDebug     = loglev(7, 70, MDebug) // port share proxy debug
	DAutoUserID       = loglev(7, 70, MDebug) // AUTO_USERID debugging
	DTLSKeySelect     = loglev(7, 70, MDebug) // show information on key selection for data channel
	DArgvParseCmd     = loglev(7, 70, MDebug) // show parse_line() errors in argv_printf %sc
	DCryptoDebug      = loglev(7, 70, MDebug) // show detailed info from crypto.c routines
	DPFDroppedBcast   = loglev(7, 71, MDebug) // packet filter dropped a broadcast packet
	DPFDebug          = loglev(7, 72, MDebug) // packet filter debugging, must also define PF_DEBUG in pf.h

	DHandshakeVerbose = loglev(8, 70, MDebug) // show detailed description of each handshake
	DTLSDebugMed      = loglev(8, 70, MDebug) // limited info from tls_session routines
	DInterval         = loglev(8, 70, MDebug) // show interval.h debugging info
	DScheduler        = loglev(8, 70, MDebug) // show scheduler debugging info
	DGremlinVerbose   = loglev(8, 70, MDebug) // show verbose info from gremlin module
	DRelDebug         = loglev(8, 70, MDebug) // show detailed info from reliable routines
	DEventWait        = loglev(8, 70, MDebug) // show detailed info from event waits
	DMultiTCP         = loglev(8, 70, MDebug) // show debug info from mtcp.c

	DTLSDebug        = loglev(9, 70, MDebug) // show detailed info from TLS routines
	DComp            = loglev(9, 70, MDebug) // show compression info
	DReadWrite       = loglev(9, 70, MDebug) // show all tun/tcp/udp reads/writes/opens
	DPacketContent   = loglev(9, 70, MDebug) // show before/after encryption packet content
	DTLSNoSendKey    = loglev(9, 70, MDebug) // show when no data channel send-key exists
	DPidDebug        = loglev(9, 70, MDebug) // show packet-id debugging info
	DPidPersistDebug = loglev(9, 70, MDebug) // show packet-id persist debugging info
	DLinkRWVerbose   = loglev(9, 70, MDebug) // show link reads/writes with greater verbosity
	DStreamDebug     = loglev(9, 70, MDebug) // show TCP stream debug info
	DWin32IO         = loglev(9, 70, MDebug) // win32 I/O debugging info
	DPKCS11Debug     = loglev(9, 70, MDebug) // show PKCS#11 debugging

	DShaperDebug = loglev(10, 70, MDebug) // show traffic shaper info

	DRegistry    = loglev(11, 70, MDebug) // win32 registry debugging info
	DOpenSSLLock = loglev(11, 70, MDebug) // show OpenSSL locks

	DThreadDebug = loglev(4, 70, MDebug) // show pthread debug information
)
