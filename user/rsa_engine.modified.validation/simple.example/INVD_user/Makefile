CC	:= gcc
CFLAGS	:= -Wall -g -MD -O2 -I ../
LDFLAGS := -ldune -lpthread
#MODULE_LIB := /lib/modules/$(shell uname -r)/build

tests_files := hello 


all: $(tests_files)

hello: hello.o ./libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L./libdune/ $(LDFLAGS) -o $(@)

clean:
	rm -f *.o test *.d $(tests_files)

-include *.d
