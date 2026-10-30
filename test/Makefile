# Makefile to run unit tests for Homa

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build
LINUX_SRC_DIR ?= /ouster/linux-stable
CC ?= gcc
CXX ?= g++
PERL ?= perl
ARCH ?= x86

all: test

KERN_INCLUDES := \
	    -I$(KDIR)/arch/x86/include \
	    -I$(KDIR)/arch/x86/include/generated \
	    -I$(KDIR)/include \
	    -I$(KDIR)/arch/x86/include/uapi \
	    -I$(KDIR)/arch/x86/include/generated/uapi \
	    -I$(KDIR)/include/uapi \
	    -I$(KDIR)/include/generated/uapi
CINCLUDES := \
	    -I. \
	    -I.. \
	    $(KERN_INCLUDES) \
	    -include $(KDIR)/include/linux/kconfig.h \
	    -include kconfig_overrides.h
CCINCLUDES := \
	    -I. \
	    -I.. \
	    $(KERN_KINCLUDES)

DEFS :=      -D__KERNEL__ \
	     -D__UNIT_TEST__ \
	     -D KBUILD_MODNAME='"homa"' \
	     -DCC_USING_FENTRY

WARNS :=     -Wall -Wundef -Wno-trigraphs -Wno-sign-compare -Wuninitialized \
		-Wno-strict-aliasing -Wunused-but-set-variable -Werror
CFLAGS :=    -std=gnu11 $(WARNS) -Wstrict-prototypes -MD -no-pie -g \
		$(CINCLUDES) $(DEFS) -fsanitize=address \
		-fno-omit-frame-pointer -fms-extensions
CCFLAGS :=   -std=c++11 $(WARNS) -MD -g $(CCINCLUDES) $(DEFS) \
		-fsanitize=address -fno-omit-frame-pointer

TEST_SRCS :=  unit_homa_incoming.c \
	      unit_homa_interest.c \
	      unit_homa_outgoing.c \
	      unit_homa_peer.c \
	      unit_homa_pool.c \
	      unit_homa_plumbing.c \
	      unit_homa_rpc.c \
	      unit_homa_sock.c \
	      unit_homa_timer.c \
	      unit_homa_tx_pool.c \
	      unit_homa_utils.c \
	      unit_timetrace.c \
	      unit_homa_udp_tunnel.c \
	      unit_homa_grant.c \
	      unit_homa_metrics.c \
	      unit_homa_offload.c \
	      unit_homa_qdisc.c
TEST_OBJS :=  $(patsubst %.c,%.o,$(TEST_SRCS))

HOMA_SRCS :=  homa_devel.c \
	      homa_interest.c \
	      homa_incoming.c \
	      homa_outgoing.c \
	      homa_peer.c \
	      homa_pool.c \
	      homa_plumbing.c \
	      homa_rpc.c \
	      homa_sock.c \
	      homa_timer.c \
	      homa_tx_pool.c \
	      homa_udp_tunnel.c \
	      homa_utils.c \
	      timetrace.c \
	      homa_grant.c \
	      homa_metrics.c \
	      homa_offload.c \
	      homa_qdisc.c

HOMA_OBJS :=  $(patsubst %.c,%.o,$(HOMA_SRCS))

LINUX_OBJS := $(shell ./linux_objs $(KDIR)/include/generated/uapi/linux/version.h)

OTHER_SRCS := ccutils.cc \
	      main.c \
	      mock.c \
	      utils.c
OTHER_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(OTHER_SRCS)))

OBJS := $(TEST_OBJS) $(HOMA_OBJS) $(LINUX_OBJS) $(OTHER_OBJS)

CLEANS = unit $(OBJS) *.d .deps

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

dummyFile:
	$(CXX) -c $(CCFLAGS) \
	-I $(LINUX_SRC_DIR)/include \
	-I $(LINUX_SRC_DIR)/arch/x86/include \
	-I $(LINUX_SRC_DIR)/arch/x86/include/generated \
	-include  $(LINUX_SRC_DIR)/include/linux/kconfig.h \
	-O2 $< -o $@

# Note: Without -O2 there will be strange compiler errors such as
# 'asm operand 2 probably does not match constraints'.
rhashtable%.o: rhashtable%.c
	$(CC) -c $(CFLAGS) -O2 -fno-sanitize=address $< -o $@

xxhash%.o: xxhash%.c
	$(CC) -c $(CFLAGS) -O2 -fno-sanitize=address $< -o $@

unit: $(OBJS)
	$(CXX) $(CFLAGS) $^ -o $@

test: unit
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
	rm -f $(CLEANS)

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
