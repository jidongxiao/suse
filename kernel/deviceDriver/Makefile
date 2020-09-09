obj-m += deviceDriver.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod deviceDriver.ko
	sudo chmod 0666 /proc/deviceDriver
	gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod deviceDriver.ko
	rm -f *.o

