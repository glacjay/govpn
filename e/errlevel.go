package e

const debugLevelUsecTime = 4

var (
	MInfo = loglev(1, 0, 0)

	DLinkErrors    = loglev(1, 1, MNonFatal) // show link errors
	DResolveErrors = loglev(1, 4, MNonFatal) // show hostname resolve errors

	DShowOCC = loglev(4, 51, 0) // show options compatibility string

	DReadWrite = loglev(9, 70, MDebug) // show all tun/tcp/udp reads/writes/opens
)
