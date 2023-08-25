# Makefile to build Homa as a Linux module.

ifneq ($(KERNELRELEASE),)

obj-m += homa.o
homa-y = homa_incoming.o \
            homa_offload.o \
            homa_outgoing.o \
            homa_peertab.o \
	    homa_pool.o \
            homa_plumbing.o \
            homa_socktab.o \
            homa_timer.o \
            homa_utils.o \
            timetrace.o

MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

else

ifneq ($(KERNEL_SRC),)
# alternatively to variable KDIR accept variable KERNEL_SRC as used in
# PetaLinux/Yocto for example
KDIR ?= $(KERNEL_SRC)
endif

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

check:
	../homaLinux/scripts/kernel-doc -none *.c

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
