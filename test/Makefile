# Makefile to run unit tests for Homa

KDIR ?= /lib/modules/$(shell uname -r)/build
CC ?= gcc
CXX ?= g++
PERL ?= perl
ARCH ?= x86

CINCLUDES := -I. \
	    -I.. \
	    -I$(KDIR)/arch/x86/include \
	    -I$(KDIR)/arch/x86/include/generated \
	    -I$(KDIR)/include \
	    -I$(KDIR)/arch/x86/include/uapi \
	    -I$(KDIR)/arch/x86/include/generated/uapi \
	    -I$(KDIR)/include/uapi \
	    -I$(KDIR)/include/generated/uapi \
	    -include $(KDIR)/include/linux/kconfig.h \
	    -include $(KDIR)/include/linux/compiler-version.h \
	    -include $(KDIR)/include/linux/compiler_types.h
CCINCLUDES := -I. \
	    -I.. \
	    -I$(KDIR)/arch/x86/include \
	    -I$(KDIR)/arch/x86/include/generated \
	    -I$(KDIR)/include \
	    -I$(KDIR)/arch/x86/include/uapi \
	    -I$(KDIR)/arch/x86/include/generated/uapi \
	    -I$(KDIR)/include/uapi \
	    -I$(KDIR)/include/generated/uapi

DEFS :=      -D__KERNEL__ \
	     -D__UNIT_TEST__ \
	     -D KBUILD_MODNAME='"homa"'

WARNS :=     -Wall -Wundef -Wno-trigraphs -Wno-sign-compare \
		-Wno-strict-aliasing -Werror
CFLAGS :=    $(WARNS) -Wstrict-prototypes -MD -g $(CINCLUDES) $(DEFS)
CCFLAGS :=   -std=c++11 $(WARNS) -MD -g $(CCINCLUDES) $(DEFS) -fsanitize=address

TEST_SRCS :=  unit_homa_grant.c \
	      unit_homa_incoming.c \
	      unit_homa_offload.c \
	      unit_homa_metrics.c \
	      unit_homa_outgoing.c \
	      unit_homa_peer.c \
	      unit_homa_pool.c \
	      unit_homa_plumbing.c \
	      unit_homa_rpc.c \
	      unit_homa_skb.c \
	      unit_homa_sock.c \
	      unit_homa_timer.c \
	      unit_homa_utils.c \
	      unit_timetrace.c
TEST_OBJS :=  $(patsubst %.c,%.o,$(TEST_SRCS))

HOMA_SRCS :=  homa_grant.c \
	      homa_incoming.c \
	      homa_metrics.c \
	      homa_offload.c \
	      homa_outgoing.c \
	      homa_peer.c \
	      homa_pool.c \
	      homa_plumbing.c \
	      homa_rpc.c \
	      homa_skb.c \
	      homa_sock.c \
	      homa_timer.c \
	      homa_utils.c \
	      timetrace.c
HOMA_OBJS :=  $(patsubst %.c,%.o,$(HOMA_SRCS))

OTHER_SRCS := ccutils.cc \
	      main.c \
	      mock.c \
	      utils.c

OTHER_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(OTHER_SRCS)))

OBJS := $(TEST_OBJS) $(HOMA_OBJS) $(OTHER_OBJS)

CLEANS = unit $(OBJS) *.d .deps

all: run_tests

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:

%.o: ../%.c
	$(CC) -c $(CFLAGS) $< -o $@
%.e: ../%.c
	$(CC) -E $(CFLAGS) $< -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
%.e: %.c
	$(CC) -E $(CFLAGS) $< -o $@
%.o: %.cc
	$(CXX) -c $(CCFLAGS) $< -o $@
%.e: %.cc
	$(CXX) -E $(CCFLAGS) $< -o $@

unit: $(OBJS)
	$(CXX) $(CFLAGS) $^ -o $@ -lasan

run_tests: unit
	./unit

# The target below shouldn't be needed: theoretically, any code that is
# sensitive to IPv4 vs. IPv6 should be tested explicitly, regardless of
# the --ipv4 argument.
test_both: unit
	@echo "Testing with IPv4 default:"
	./unit --ipv4
	@echo "Testing with IPv6 default:"
	./unit

clean:
	rm -f unit $(CLEANS)

# This magic (along with the -MD gcc option) automatically generates makefile
# dependencies for header files included from C source files we compile,
# and keeps those dependencies up-to-date every time we recompile.
# See 'mergedep.pl' for more information.
.deps: $(wildcard *.d)
	@mkdir -p $(@D)
	$(PERL) mergedep.pl $@ $^
-include .deps

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)

