include $(GOROOT)/src/Make.inc

TARG = govpn_$(GOOS)

GOFILES = \
	main.go \
	options.go \
	socket.go \
	tun.go \

GOFILES_linux = \
	tun_linux.go \

GOFILES_darwin = \
	tun_darwin.go \

GOFILES += $(GOFILES_$(GOOS))

include $(GOROOT)/src/Make.cmd
