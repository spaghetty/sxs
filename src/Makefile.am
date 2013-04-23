GO_DEPS = \
	github.com/akrennmair/gopcap \
	github.com/spaghetty/sip_parser \
	github.com/nsf/termbox-go \
	github.com/spaghetty/sXs

GO_EXECS = sXs \
	sXconsole

CLEANFILES = ${GO_EXECS}

sXs_GOSRC = src/sXmain.go

sXconsole_GOSRC = src/sXconsole.go

$(GO_DEPS):
	export GOPATH=$(realpath $(top_srcdir)) ; $(GOLANG) get $@

$(GO_EXECS): $(GO_DEPS)
	export GOPATH=$(realpath $(top_srcdir)) ; $(GOLANG) build -o ../bin/$@ $(top_srcdir)/$($@_GOSRC)

install: ${GO_EXECS}
	for prog in $(GO_EXECS); do \
	 install -m 755 $$prog ~/bin/; \
	done

bin_SCRIPTS = $(GO_EXECS)
