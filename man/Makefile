# Makefile to build man pages for Homa.

SRCS := homa.7 \
	homa_abort.3 \
        homa_reply.3 \
        homa_send.3 \
        sendmsg.2

PDFS := $(patsubst %.2,%.pdf,$(SRCS))
PDFS := $(patsubst %.3,%.pdf,$(PDFS))
PDFS := $(patsubst %.7,%.pdf,$(PDFS))
all: $(PDFS)

clean:
	rm -f *.pdf

%.pdf: %.2
	pdfroff -man $< > $@

%.pdf: %.3
	pdfroff -man $< > $@

%.pdf: %.7
	pdfroff -man $< > $@

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)