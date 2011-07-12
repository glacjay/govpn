include $(GOROOT)/src/Make.inc

TARG = govpn
GOFILES = \
	main.go \
	options.go \
	socket.go \
	tun.go \

include $(GOROOT)/src/Make.cmd
