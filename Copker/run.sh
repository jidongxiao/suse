#/bin/bash
make clean
make
rmmod isoToken
insmod isoToken.ko
dmesg -c
