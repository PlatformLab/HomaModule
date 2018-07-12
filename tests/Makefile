# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -g

BINS := bufferClient bufferServer getTimeTrace homaSend \
        homaServer receiveRaw scratch sendRaw testTimeTrace useMemory

all: $(BINS)
	
%: %.c
	cc $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	