include $(GOROOT)/src/Make.inc

TARG = govpn
GOFILES = \
	main.go \
	mtu.go \
	options.go \
	socket.go \
	tun.go \

include $(GOROOT)/src/Make.cmd
