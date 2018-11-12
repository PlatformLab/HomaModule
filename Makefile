# Makefile to build Homa as a Linux module.

obj-m += homa.o
homa-y = homa_incoming.o \
            homa_outgoing.o \
            homa_peertab.o \
            homa_plumbing.o \
            homa_socktab.o \
            homa_timer.o \
            homa_utils.o

MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
check:
	../homaLinux/scripts/kernel-doc -none *.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)
	
printBuild-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	
printClean-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	