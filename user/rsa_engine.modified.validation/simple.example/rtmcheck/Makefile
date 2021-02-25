CC	:= gcc
CFLAGS	:=  -mrtm -Wall -g -MD -O2 -I ../
LDFLAGS := -ldune -lpthread
#MODULE_LIB := /lib/modules/$(shell uname -r)/build

tests_files := rtmCheck

all: $(tests_files)

rtmCheck: rtmCheck.o ../libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L../libdune/ $(LDFLAGS) -o $(@)

clean:
	rm -f *.o test *.d $(tests_files)
	#make -C $(MODULE_LIB) M=$(PWD) clean

-include *.d
