# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -Werror -fno-strict-aliasing -O3 -I..

BINS := buffer_client buffer_server cp_node get_time_trace \
	homa_test receive_raw scratch send_raw server \
        test_time_trace use_memory

OBJS := $(patsubst %,%.o,$(BINS))
	
LIB_SRCS := homa_api.c test_utils.cc
LIB_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(LIB_SRCS)))
	
.SECONDARY: $(OBJS) $(LIB_OBJS)

all: $(BINS)
	
cp_node: cp_node.o dist.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:
	
%: %.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@
	
%.o: %.cc test_utils.h ../homa.h
	g++ -c $(CFLAGS) -std=c++11 $< -o $@
	
%.o: %.c test_utils.h ../homa.h
	cc -c $(CFLAGS) $< -o $@
	
homa_api.o: ../homa_api.c
	cc -c $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS) $(OBJS) $(LIB_OBJS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	