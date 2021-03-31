#obj-m += invd.o

obj-m := invd.o 


invd-objs := test_asm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod invd.ko
	sudo chmod 0666 /proc/invd
	gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod invd.ko
	rm -f *.o

