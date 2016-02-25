KERNELSRCDIR := /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0

DEBUG?=no
flag_debug_yes = -DDEBUG
flag_debug_no =

obj-m := nshkmod.o
ccflags-y := $(flag_debug_$(DEBUG))

all:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) V=$(VERBOSE) modules

clean:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) clean
