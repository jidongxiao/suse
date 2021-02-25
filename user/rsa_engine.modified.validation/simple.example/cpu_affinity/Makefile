CC=gcc
CFLAGS= -O0 -std=c99 -Wall -Wextra -pedantic

rtmCheck: cpu_affinity.o
	$(CC) $(CFLAGS) -o cpu_affinity cpu_affinity.o

clean: 
	rm -f *.o cpu_affinity
