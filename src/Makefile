# Makefile for compiling a kernel module

# Specify the kernel source directory
KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

# The name of the module
MNAME := icewall

# Compiler options (optional)
CC := gcc
EXTRA_CFLAGS := -I$(KDIR)/include

# Make rules
obj-m := $(MNAME).o

# List of objects files for the module
$(MNAME)-objs := main.o net-hook.o rules.o sec.o sentinel.o chrdev.o

all: compile

compile:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean