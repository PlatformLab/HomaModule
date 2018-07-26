# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -Werror -g -I..

BINS := bufferClient bufferServer getTimeTrace homaTest \
        homaServer receiveRaw scratch sendRaw testTimeTrace useMemory

OBJS := $(patsubst %,%.o,$(BINS))

all: $(BINS)

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:
	
%: %.o homa_api.o
	g++ $(CFLAGS) $^ -lpthread -o $@
	
%.o: %.cc
	g++ -c $(CFLAGS) -std=c++11 $< -o $@
	
%.o: %.c
	cc -c $(CFLAGS) $< -o $@
	
homa_api.o: ../homa_api.c
	cc -c $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS) $(OBJS) homa_api.o

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	