# Makefile to run unit tests for Homa

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PERL ?= perl
ARCH ?= x86
	
CINCLUDES := -I. \
	    -I.. \
	    -I$(KERNEL_DIR)/arch/x86/include \
	    -I$(KERNEL_DIR)/arch/x86/include/generated \
	    -I$(KERNEL_DIR)/include \
	    -I$(KERNEL_DIR)/arch/x86/include/uapi \
	    -I$(KERNEL_DIR)/arch/x86/include/generated/uapi \
	    -I$(KERNEL_DIR)/include/uapi \
	    -I$(KERNEL_DIR)/include/generated/uapi \
	    -include $(KERNEL_DIR)/include/linux/kconfig.h \
	    -include $(KERNEL_DIR)/include/linux/compiler-version.h \
	    -include $(KERNEL_DIR)/include/linux/compiler_types.h
CCINCLUDES := -I. \
	    -I.. \
	    -I$(KERNEL_DIR)/arch/x86/include \
	    -I$(KERNEL_DIR)/arch/x86/include/generated \
	    -I$(KERNEL_DIR)/include \
	    -I$(KERNEL_DIR)/arch/x86/include/uapi \
	    -I$(KERNEL_DIR)/arch/x86/include/generated/uapi \
	    -I$(KERNEL_DIR)/include/uapi \
	    -I$(KERNEL_DIR)/include/generated/uapi 

DEFS :=      -D__KERNEL__ \
	     -D__UNIT_TEST__ \
	     -D KBUILD_MODNAME='"homa"'

WARNS :=     -Wall -Wundef -Wno-trigraphs -Wno-sign-compare -Wno-strict-aliasing
CFLAGS :=    $(WARNS) -Wstrict-prototypes -MD -g $(CINCLUDES) $(DEFS)
CCFLAGS :=   -std=c++11 $(WARNS) -MD -g $(CCINCLUDES) $(DEFS) -fsanitize=address
	
TEST_SRCS :=  unit_homa_incoming.c \
	      unit_homa_lcache.c \
	      unit_homa_offload.c \
	      unit_homa_outgoing.c \
	      unit_homa_peertab.c \
	      unit_homa_plumbing.c \
	      unit_homa_socktab.c \
	      unit_homa_timer.c \
	      unit_homa_utils.c \
	      unit_timetrace.c
TEST_OBJS :=  $(patsubst %.c,%.o,$(TEST_SRCS))
	
HOMA_SRCS :=  homa_incoming.c \
	      homa_offload.c \
	      homa_outgoing.c \
	      homa_peertab.c \
	      homa_plumbing.c \
	      homa_socktab.c \
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
	cc -c $(CFLAGS) $< -o $@
%.e: ../%.c
	cc -E $(CFLAGS) $< -o $@
%.o: %.c
	cc -c $(CFLAGS) $< -o $@
%.e: %.c
	cc -E $(CFLAGS) $< -o $@
%.o: %.cc
	g++ -c $(CCFLAGS) $< -o $@
%.e: %.cc
	g++ -E $(CCFLAGS) $< -o $@
	
unit: $(OBJS)
	g++ $(CFLAGS) $^ -o $@ -lasan
	
run_tests: unit
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
	
