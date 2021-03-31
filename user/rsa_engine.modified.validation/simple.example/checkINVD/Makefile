obj-m += invdMod.o
CFLAGS_invdMod.o := -o0
invdMod-objs := disable_cache.o test.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod invdMod.ko
	#sudo chmod 0666 /proc/invd
	#gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod invdMod.ko
	rm -f *.o

