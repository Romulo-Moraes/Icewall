KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

MNAME := icewall
SHARED_DIR := $(src)/../shared
CC := gcc
EXTRA_CFLAGS := -I$(SHARED_DIR) -I$(KDIR)/include -Iincludes

obj-m := $(MNAME).o

$(MNAME)-objs := main.o net-hook.o rules.o sec.o sentinel.o chrdev.o

all: compile

compile:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
