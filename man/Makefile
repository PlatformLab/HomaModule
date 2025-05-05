# Makefile to build man pages for Homa.

SRCS := homa.7 \
        recvmsg.2 \
        sendmsg.2

PDFS := $(patsubst %.2,%.pdf,$(SRCS))
PDFS := $(patsubst %.3,%.pdf,$(PDFS))
PDFS := $(patsubst %.7,%.pdf,$(PDFS))
all: $(PDFS)

clean:
	rm -f *.pdf

# Note: in the rules below, it doesn't seem to work to eliminate the
# temporary file and use ps2pdf in a pipeline; as of 12/2024, under
# Cygwin, this produces blank output for some man pages under some
# conditions.
%.pdf: %.2
	groff -man -Tps $< > tmp.ps
	ps2pdf tmp.ps $@
	rm tmp.ps

%.pdf: %.3
	groff -man -Tps $< > tmp.ps
	ps2pdf tmp.ps $@
	rm tmp.ps

%.pdf: %.7
	groff -man -Tps $< > tmp.ps
	ps2pdf tmp.ps $@
	rm tmp.ps

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)