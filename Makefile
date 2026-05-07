obj-m += tcps.o
tcps-objs := tcps_main.o tcps_crypto.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$$(pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
