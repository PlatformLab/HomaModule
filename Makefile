# Makefile to build Homa as a Linux module.

HOMA_OBJS := homa_devel.o \
	homa_incoming.o \
	homa_interest.o \
	homa_outgoing.o \
	homa_pacer.o \
	homa_peer.o \
	homa_pool.o \
	homa_plumbing.o \
	homa_rpc.o \
	homa_sock.o \
	homa_timer.o \
	homa_utils.o \
	timetrace.o

ifneq ($(KERNELRELEASE),)

obj-m += homa.o
homa-y = $(HOMA_OBJS)

ifneq ($(__STRIP__),)
MY_CFLAGS += -D__STRIP__
else
HOMA_OBJS += homa_grant.o \
	homa_metrics.o \
	homa_offload.o \
	homa_skb.o
endif

MY_CFLAGS += -g
ccflags-y += $(MY_CFLAGS)

else

ifneq ($(KERNEL_SRC),)
# alternatively to variable KDIR accept variable KERNEL_SRC as used in
# PetaLinux/Yocto for example
KDIR ?= $(KERNEL_SRC)
endif

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

check:
	../homaLinux/scripts/kernel-doc -none *.c

# Copy stripped source files to a Linux source tree
LINUX_SRC_DIR ?= ../net-next
HOMA_TARGET ?= $(LINUX_SRC_DIR)/net/homa
CP_HDRS := homa_impl.h \
	   homa_interest.h \
	   homa_pacer.h \
	   homa_peer.h \
	   homa_pool.h \
	   homa_rpc.h \
	   homa_sock.h \
	   homa_stub.h \
	   homa_wire.h
CP_SRCS := $(patsubst %.o,%.c,$(filter-out homa_devel.o timetrace.o, $(HOMA_OBJS)))
CP_EXTRAS := reap.txt \
	     sync.txt \
	     Kconfig \
	     Makefile \
	     strip_decl.py
CP_TARGETS := $(patsubst %,$(HOMA_TARGET)/%,$(CP_HDRS) $(CP_SRCS) $(CP_EXTRAS))
net-next: $(CP_TARGETS) $(LINUX_SRC_DIR)/include/uapi/linux/homa.h
$(HOMA_TARGET)/%: % util/strip.py
	util/strip.py $< > $@
$(HOMA_TARGET)/%.txt: %.txt
	cp $< $@
$(HOMA_TARGET)/Makefile: Makefile.upstream
	cp $< $@
$(HOMA_TARGET)/strip_decl.py: util/strip_decl.py
	cp $< $@
$(LINUX_SRC_DIR)/include/uapi/linux/homa.h: homa.h util/strip.py
	util/strip.py $< > $@

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
