obj-m += cr0.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	#sudo insmod cr0.ko
	

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod cr0.ko
	rm -f *.o

