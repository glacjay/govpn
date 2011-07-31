include $(GOROOT)/src/Make.inc

TARG = govpn
DEPS = e utils opt sig

GOFILES = \
	main.go \
	occ.go \
	socket.go \
	tun.go \

GOFILES_linux = \
	tun_linux.go \

GOFILES_darwin = \
	tun_darwin.go \

GOFILES += $(GOFILES_$(GOOS))

include $(GOROOT)/src/Make.cmd

CLEANFILES += `find . -name '*.a'`
