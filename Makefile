# Makefile to build Homa as a Linux module.

HOMA_OBJS := homa_devel.o \
	homa_incoming.o \
	homa_interest.o \
	homa_outgoing.o \
	homa_peer.o \
	homa_pool.o \
	homa_plumbing.o \
	homa_rpc.o \
	homa_sock.o \
	homa_timer.o \
	homa_tx_pool.o \
	homa_udp_tunnel.o \
	homa_utils.o \
	timetrace.o \
	homa_grant.o \
	homa_metrics.o \
	homa_offload.o \
	homa_qdisc.o

CHECK_SRCS := $(patsubst %.o,%.c,$(filter-out homa_devel.o timetrace.o, $(HOMA_OBJS)))
CHECK_SRCS += $(filter-out homa_receiver.h homa_devel.h, $(wildcard *.h))

ifneq ($(KERNEL_SRC),)
# alternatively to variable KDIR accept variable KERNEL_SRC as used in
# PetaLinux/Yocto for example
KDIR ?= $(KERNEL_SRC)
endif

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build

LINUX_SRC_DIR ?= $(KDIR)

ifneq ($(KERNELRELEASE),)

obj-m += homa.o
homa-y = $(HOMA_OBJS)

MY_CFLAGS += -g
ccflags-y += $(MY_CFLAGS)

else

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

kdoc:
	$(LINUX_SRC_DIR)/scripts/kernel-doc -none $(CHECK_SRCS)

checkpatch:
	$(LINUX_SRC_DIR)/scripts/checkpatch.pl --file --strict --codespell $(CHECK_SRCS)

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean

# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)

printBuild-%:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

printClean-%:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

endif
