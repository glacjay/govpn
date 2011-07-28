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
	D_EVENT_ERRORS = loglev(1, 10, MNonFatal) // show event.[ch] errors
	D_PUSH_ERRORS  = loglev(1, 11, MNonFatal) // show push/pull errors
	D_PID_PERSIST  = loglev(1, 12, MNonFatal) // show packet_id persist errors
	D_FRAG_ERRORS  = loglev(1, 13, MNonFatal) // show fragmentation errors
	D_ALIGN_ERRORS = loglev(1, 14, MNonFatal) // show bad struct alignments

	D_HANDSHAKE     = loglev(2, 20, 0) // show data & control channel handshakes
	D_MTU_INFO      = loglev(2, 21, 0) // show terse MTU info
	D_CLOSE         = loglev(2, 22, 0) // show socket and TUN/TAP close
	D_SHOW_OCC_HASH = loglev(2, 23, 0) // show MD5 hash of option compatibility string
	D_PROXY         = loglev(2, 24, 0) // show http proxy control packets
	D_ARGV          = loglev(2, 25, 0) // show struct argv errors

	D_TLS_DEBUG_LOW = loglev(3, 20, 0) // low frequency info from tls_session routines
	D_GREMLIN       = loglev(3, 30, 0) // show simulated outage info from gremlin module
	D_GENKEY        = loglev(3, 31, 0) // print message after key generation
	D_ROUTE         = loglev(3, 0, 0)  // show routes added and deleted (don't mute)
	D_TUNTAP_INFO   = loglev(3, 32, 0) // show debugging info from TUN/TAP driver
	D_RESTART       = loglev(3, 33, 0) // show certain restart messages
	D_PUSH          = loglev(3, 34, 0) // show push/pull info
	D_IFCONFIG_POOL = loglev(3, 35, 0) // show ifconfig pool info
	D_BACKTRACK     = loglev(3, 36, 0) // show replay backtracks
	D_AUTH          = loglev(3, 37, 0) // show user/pass auth info
	D_MULTI_LOW     = loglev(3, 38, 0) // show point-to-multipoint low-freq debug info
	D_PLUGIN        = loglev(3, 39, 0) // show plugin calls
	D_MANAGEMENT    = loglev(3, 40, 0) // show --management info
	D_SCHED_EXIT    = loglev(3, 41, 0) // show arming of scheduled exit
	D_ROUTE_QUOTA   = loglev(3, 42, 0) // show route quota exceeded messages
	D_OSBUF         = loglev(3, 43, 0) // show socket/tun/tap buffer sizes
	D_PS_PROXY      = loglev(3, 44, 0) // messages related to --port-share option
	D_PF_INFO       = loglev(3, 45, 0) // packet filter informational messages

	D_SHOW_PARMS       = loglev(4, 50, 0) // show all parameters on program initiation
	D_SHOW_OCC         = loglev(4, 51, 0) // show options compatibility string
	D_LOW              = loglev(4, 52, 0) // miscellaneous low-frequency debug info
	D_DHCP_OPT         = loglev(4, 53, 0) // show DHCP options binary string
	D_MBUF             = loglev(4, 54, 0) // mbuf.[ch] routines
	D_PACKET_TRUNC_ERR = loglev(4, 55, 0) // PACKET_TRUNCATION_CHECK
	D_PF_DROPPED       = loglev(4, 56, 0) // packet filter dropped a packet
	D_MULTI_DROPPED    = loglev(4, 57, 0) // show point-to-multipoint packet drops

	D_LOG_RW = loglev(5, 0, 0) // Print 'R' or 'W' to stdout for read/write

	D_LINK_RW         = loglev(6, 60, MDebug) // show TCP/UDP reads/writes (terse)
	D_TUN_RW          = loglev(6, 60, MDebug) // show TUN/TAP reads/writes
	D_TAP_WIN32_DEBUG = loglev(6, 60, MDebug) // show TAP-Win32 driver debug info

	D_SHOW_KEYS          = loglev(7, 70, MDebug) // show data channel encryption keys
	D_SHOW_KEY_SOURCE    = loglev(7, 70, MDebug) // show data channel key source entropy
	D_REL_LOW            = loglev(7, 70, MDebug) // show low frequency info from reliable layer
	D_FRAG_DEBUG         = loglev(7, 70, MDebug) // show fragment debugging info
	D_WIN32_IO_LOW       = loglev(7, 70, MDebug) // low freq win32 I/O debugging info
	D_MTU_DEBUG          = loglev(7, 70, MDebug) // show MTU debugging info
	D_PID_DEBUG_LOW      = loglev(7, 70, MDebug) // show low-freq packet-id debugging info
	D_MULTI_DEBUG        = loglev(7, 70, MDebug) // show medium-freq multi debugging info
	D_MSS                = loglev(7, 70, MDebug) // show MSS adjustments
	D_COMP_LOW           = loglev(7, 70, MDebug) // show adaptive compression state changes
	D_CONNECTION_LIST    = loglev(7, 70, MDebug) // show <connection> list info
	D_SCRIPT             = loglev(7, 70, MDebug) // show parms & env vars passed to scripts
	D_SHOW_NET           = loglev(7, 70, MDebug) // show routing table and adapter list
	D_ROUTE_DEBUG        = loglev(7, 70, MDebug) // show verbose route.[ch] output
	D_TLS_STATE_ERRORS   = loglev(7, 70, MDebug) // no TLS state for client
	D_SEMAPHORE_LOW      = loglev(7, 70, MDebug) // show Win32 semaphore waits (low freq)
	D_SEMAPHORE          = loglev(7, 70, MDebug) // show Win32 semaphore waits
	D_TEST_FILE          = loglev(7, 70, MDebug) // show test_file() calls
	D_MANAGEMENT_DEBUG   = loglev(3, 70, MDebug) // show --management debug info
	D_PLUGIN_DEBUG       = loglev(7, 70, MDebug) // show verbose plugin calls
	D_SOCKET_DEBUG       = loglev(7, 70, MDebug) // show socket.[ch] debugging info
	D_SHOW_PKCS11        = loglev(7, 70, MDebug) // show PKCS#11 actions
	D_ALIGN_DEBUG        = loglev(7, 70, MDebug) // show verbose struct alignment info
	D_PACKET_TRUNC_DEBUG = loglev(7, 70, MDebug) // PACKET_TRUNCATION_CHECK verbose
	D_PING               = loglev(7, 70, MDebug) // PING send/receive messages
	D_PS_PROXY_DEBUG     = loglev(7, 70, MDebug) // port share proxy debug
	D_AUTO_USERID        = loglev(7, 70, MDebug) // AUTO_USERID debugging
	D_TLS_KEYSELECT      = loglev(7, 70, MDebug) // show information on key selection for data channel
	D_ARGV_PARSE_CMD     = loglev(7, 70, MDebug) // show parse_line() errors in argv_printf %sc
	D_CRYPTO_DEBUG       = loglev(7, 70, MDebug) // show detailed info from crypto.c routines
	D_PF_DROPPED_BCAST   = loglev(7, 71, MDebug) // packet filter dropped a broadcast packet
	D_PF_DEBUG           = loglev(7, 72, MDebug) // packet filter debugging, must also define PF_DEBUG in pf.h

	D_HANDSHAKE_VERBOSE = loglev(8, 70, MDebug) // show detailed description of each handshake
	D_TLS_DEBUG_MED     = loglev(8, 70, MDebug) // limited info from tls_session routines
	D_INTERVAL          = loglev(8, 70, MDebug) // show interval.h debugging info
	D_SCHEDULER         = loglev(8, 70, MDebug) // show scheduler debugging info
	D_GREMLIN_VERBOSE   = loglev(8, 70, MDebug) // show verbose info from gremlin module
	D_REL_DEBUG         = loglev(8, 70, MDebug) // show detailed info from reliable routines
	D_EVENT_WAIT        = loglev(8, 70, MDebug) // show detailed info from event waits
	D_MULTI_TCP         = loglev(8, 70, MDebug) // show debug info from mtcp.c

	D_TLS_DEBUG         = loglev(9, 70, MDebug) // show detailed info from TLS routines
	D_COMP              = loglev(9, 70, MDebug) // show compression info
	D_READ_WRITE        = loglev(9, 70, MDebug) // show all tun/tcp/udp reads/writes/opens
	D_PACKET_CONTENT    = loglev(9, 70, MDebug) // show before/after encryption packet content
	D_TLS_NO_SEND_KEY   = loglev(9, 70, MDebug) // show when no data channel send-key exists
	D_PID_DEBUG         = loglev(9, 70, MDebug) // show packet-id debugging info
	D_PID_PERSIST_DEBUG = loglev(9, 70, MDebug) // show packet-id persist debugging info
	D_LINK_RW_VERBOSE   = loglev(9, 70, MDebug) // show link reads/writes with greater verbosity
	D_STREAM_DEBUG      = loglev(9, 70, MDebug) // show TCP stream debug info
	D_WIN32_IO          = loglev(9, 70, MDebug) // win32 I/O debugging info
	D_PKCS11_DEBUG      = loglev(9, 70, MDebug) // show PKCS#11 debugging

	D_SHAPER_DEBUG = loglev(10, 70, MDebug) // show traffic shaper info

	D_REGISTRY     = loglev(11, 70, MDebug) // win32 registry debugging info
	D_OPENSSL_LOCK = loglev(11, 70, MDebug) // show OpenSSL locks
)
