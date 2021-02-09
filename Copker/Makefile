obj-m := isoToken.o 


isoToken-objs := cacheCryptoMain.o rsa.o bignum.o test_asm.o aes.o file_CCK.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
