# Makefile to build various testing programs for Homa.

CFLAGS := -Wall -Werror -fno-strict-aliasing -g -I..

BINS := buffer_client buffer_server cp_node get_time_trace \
	homa_prio homa_test receive_raw scratch send_raw server \
        test_time_trace use_memory

OBJS := $(patsubst %,%.o,$(BINS))

LIB_SRCS := dist.cc homa_api.c test_utils.cc time_trace.cc
LIB_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(LIB_SRCS)))
LIB_OBJS += homa_receiver.o

HDRS = ../homa_receiver.h ../homa.h dist.h time_trace.h

.SECONDARY: $(OBJS) $(LIB_OBJS)

all: $(BINS)

cp_node: cp_node.o dist.o time_trace.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@

$(OBJS): $(HDRS)

homa_receiver.o: ../homa_receiver.cc ../homa_receiver.h
	g++ -c $(CFLAGS) -std=c++17 $< -o $@

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:

%: %.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@

%.o: %.cc test_utils.h ../homa.h
	g++ -c $(CFLAGS) -std=c++17 $< -o $@

%.o: %.c test_utils.h ../homa.h
	cc -c $(CFLAGS) $< -o $@

homa_api.o: ../homa_api.c ../homa.h
	cc -c $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS) $(OBJS) $(LIB_OBJS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
