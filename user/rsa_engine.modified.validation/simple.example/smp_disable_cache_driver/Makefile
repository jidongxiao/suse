obj-m += disableCacheDriver.o
CFLAGS_disableCacheDriver.o := -O0

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod disableCacheDriver.ko
	sudo chmod 0666 /proc/disableCacheDriver
	gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod disableCacheDriver.ko
	rm -f *.o

