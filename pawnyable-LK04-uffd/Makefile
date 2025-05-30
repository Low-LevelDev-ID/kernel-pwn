obj-m := fleckvieh.o
KBUILD_DIR := /lib/modules/$(KVERSION)/build

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
