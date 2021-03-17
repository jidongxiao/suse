obj-m += noSmp8.o
CFLAGS_noSmp8.o := -O0

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod noSmp8.ko
	#sudo chmod 0666 /proc/invd
	#gcc -o userProgram.o userProgram.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod noSmp8.ko
	rm -f *.o

