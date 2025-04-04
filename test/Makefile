# Makefile to run unit tests for Homa

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build
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
	    -include $(KDIR)/include/linux/kconfig.h
CCINCLUDES := \
	    -I. \
	    -I.. \
	    $(KERN_KINCLUDES)

DEFS :=      -D__KERNEL__ \
	     -D__UNIT_TEST__ \
	     -D KBUILD_MODNAME='"homa"'
ifneq ($(__STRIP__),)
DEFS +=      -D__STRIP__
endif

WARNS :=     -Wall -Wundef -Wno-trigraphs -Wno-sign-compare \
		-Wno-strict-aliasing -Wunused-but-set-variable -Werror
CFLAGS :=    $(WARNS) -Wstrict-prototypes -MD -g $(CINCLUDES) $(DEFS)
CCFLAGS :=   -std=c++11 $(WARNS) -MD -g $(CCINCLUDES) $(DEFS) -fsanitize=address

TEST_SRCS :=  unit_homa_incoming.c \
	      unit_homa_interest.c \
	      unit_homa_outgoing.c \
	      unit_homa_pacer.c \
	      unit_homa_peer.c \
	      unit_homa_pool.c \
	      unit_homa_plumbing.c \
	      unit_homa_rpc.c \
	      unit_homa_sock.c \
	      unit_homa_timer.c \
	      unit_homa_utils.c \
	      unit_timetrace.c
ifeq ($(__STRIP__),)
TEST_SRCS +=  unit_homa_grant.c \
	      unit_homa_offload.c \
	      unit_homa_metrics.c \
	      unit_homa_skb.c
endif
TEST_OBJS :=  $(patsubst %.c,%.o,$(TEST_SRCS))

HOMA_SRCS :=  homa_devel.c \
	      homa_interest.c \
	      homa_incoming.c \
	      homa_outgoing.c \
	      homa_pacer.c \
	      homa_peer.c \
	      homa_pool.c \
	      homa_plumbing.c \
	      homa_rpc.c \
	      homa_sock.c \
	      homa_timer.c \
	      homa_utils.c \
	      timetrace.c
ifeq ($(__STRIP__),)
HOMA_SRCS +=  homa_grant.c \
	      homa_metrics.c \
	      homa_offload.c \
	      homa_skb.c
endif
HOMA_OBJS :=  $(patsubst %.c,%.o,$(HOMA_SRCS))

OTHER_SRCS := ccutils.cc \
	      main.c \
	      mock.c \
	      utils.c
OTHER_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(OTHER_SRCS)))

OBJS := $(TEST_OBJS) $(HOMA_OBJS) $(OTHER_OBJS)

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

unit: $(OBJS)
	$(CXX) $(CFLAGS) $^ -o $@ -lasan

test: unit
	./unit

# Additional definitions for running unit tests using stripped sources.

S_HOMA_SRCS := $(patsubst %,stripped/%,$(filter-out timetrace.c, $(HOMA_SRCS)))
S_HOMA_OBJS :=  $(patsubst %.c,%.o,$(S_HOMA_SRCS))
S_HOMA_HDRS := stripped/homa.h \
		stripped/homa_impl.h \
		stripped/homa_peer.h \
		stripped/homa_pool.h \
		stripped/homa_receiver.h \
		stripped/homa_rpc.h \
		stripped/homa_sock.h \
		stripped/homa_stub.h \
		stripped/homa_wire.h
stripped/%.c: ../%.c
	../util/strip.py --alt $< > $@
stripped/%.h: ../%.h
	../util/strip.py --alt $< > $@
S_TEST_OBJS := $(patsubst %,stripped/%,$(filter-out unit_timetrace.o, $(TEST_OBJS)))
S_OBJS := $(S_HOMA_OBJS) $(S_TEST_OBJS) $(patsubst %,stripped/%,$(OTHER_OBJS))

$(S_OBJS): | stripped $(S_HOMA_HDRS)

stripped:
	mkdir -p stripped

stripped/%.o: stripped/%.c
	$(CC) -c $(patsubst -I..,-Istripped,$(CFLAGS)) $< -o $@
stripped/%.o: %.c
	$(CC) -c $(patsubst -I..,-Istripped,$(CFLAGS)) $< -o $@
stripped/%.o: %.cc
	$(CXX) -c $(patsubst -I..,-Istripped,$(CCFLAGS)) $< -o $@

s_unit: $(S_OBJS)
	$(CXX) $(CFLAGS) $^ -o $@ -lasan

s_test: s_unit
	./s_unit

CLEANS += s_unit

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
	rm -rf stripped

# This magic (along with the -MD gcc option) automatically generates makefile
# dependencies for header files included from C source files we compile,
# and keeps those dependencies up-to-date every time we recompile.
# See 'mergedep.pl' for more information.
.deps: $(wildcard *.d stripped/*.d)
	@mkdir -p $(@D)
	$(PERL) mergedep.pl $@ $^
-include .deps

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
