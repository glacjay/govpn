include $(GOROOT)/src/Make.inc

TARG = govpn
DEPS = e utils opt sig occ link tap

GOFILES = \
	main.go \

include $(GOROOT)/src/Make.cmd

CLEANFILES += `find . -name '*.a'` `find . -name '_go_.[568]'`
