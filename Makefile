KERNELSRCDIR = /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0
c_flags = -Wall -O0

DEBUG?=no
flag_debug_yes = -DDEBUG
flag_debug_no =

CC = gcc $(c_flags) $(flag_debug_$(DEBUG))

obj-m := nshkmod.o

all:
	make -C $(KERNELSRCDIR) SUBDIRS=$(BUILD_DIR) KBUILD_VERBOSE=$(VERBOSE)  modules

.c.o:
	$(CC) -Iinclude -c $< -o $@

clean:
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
	rm -f *~

