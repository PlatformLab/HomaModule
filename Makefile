# Makefile to build Homa as a Linux module.

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

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

check:
	../homaLinux/scripts/kernel-doc -none *.c

clean:
	make -C $(KDIR) M=$(PWD) clean

# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)

printBuild-%:
	make -C $(KDIR) M=$(PWD) $@

printClean-%:
	make -C $(KDIR) M=$(PWD) $@
