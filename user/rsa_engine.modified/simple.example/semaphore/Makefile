CC=gcc
CFLAGS= -O0 -std=c99 -Wall -Wextra -pedantic

semaphore: semaphore.o
	$(CC) $(CFLAGS) -o semaphore semaphore.o -lpthread

clean:
	rm -f *.o semaphore
