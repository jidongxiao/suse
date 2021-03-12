obj-m += car_mod14.o
car_mod14-objs := car.o test_asm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod car_mod14.ko
	sudo chmod 0666 /proc/car
	gcc -o userProgram.o userProgram.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod car_mod14.ko
	rm -f *.o

