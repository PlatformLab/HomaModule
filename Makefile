# Makefile to build Homa as a Linux module.

obj-m += homa.o
homa-objs = homa_input.o \
            homa_output.o \
            homa_plumbing.o \
            homa_socktab.o \
            homa_utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	