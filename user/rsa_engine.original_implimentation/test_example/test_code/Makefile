CC=gcc
CFLAGS= -O0 -g -Wall -Wextra -pedantic -fomit-frame-pointer
#CFLAGS= -g -Wall -Wextra -pedantic

testCode: testCode.o
	$(CC) $(CFLAGS) -o testCode testCode.o

#function_as_paprameter: function_as_paprameter.o
	#$(CC) $(CFLAGS) -o function_as_paprameter function_as_paprameter.o

#char_array: char_array.o
	#$(CC) $(CFLAGS) -o char_array char_array.o

clean: 
	rm -f *.o testCode function_as_paprameter char_array
