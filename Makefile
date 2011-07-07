include $(GOROOT)/src/Make.inc

TARG = govpn
GOFILES = \
	event.go \
	init.go \
	main.go \
	misc.go \
	mtu.go \
	options.go \
	otime.go \
	socket.go \
	tun.go \

include $(GOROOT)/src/Make.cmd
