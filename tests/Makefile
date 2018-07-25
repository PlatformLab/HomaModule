# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -Werror -g

BINS := bufferClient bufferServer getTimeTrace homaTest \
        homaServer receiveRaw scratch sendRaw testTimeTrace useMemory

all: $(BINS)
	
%: %.c
	cc $(CFLAGS) $< -o $@
	
%: %.cc
	g++ $(CFLAGS) -std=c++11 -lpthread $< -o $@

clean:
	rm -f $(BINS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	