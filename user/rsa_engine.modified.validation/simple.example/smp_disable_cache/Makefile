obj-m += disable_cache.o
CFLAGS_disable_cache.o := -O0

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod disable_cache.ko
	#sudo chmod 0666 /proc/invd
	#gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod disable_cache.ko
	rm -f *.o

