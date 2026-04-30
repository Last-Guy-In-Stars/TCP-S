obj-m += tcps.o
tcps-objs := tcps_main.o tcps_crypto.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod tcps.ko

unload:
	sudo rmmod tcps

info:
	@modinfo tcps.ko 2>/dev/null || echo "Build on Linux first"
