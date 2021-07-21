rsa-engine: rsa/rsa.c rsa/bignum.c rsa/aes.c rsa/memory_buffer_alloc.c rsa/platform.c rsa/threading.c
	gcc -g -fPIC -o rsa/rsa.o -c rsa/rsa.c
	gcc -g -fPIC -o rsa/bignum.o -c rsa/bignum.c
	gcc -g -fPIC -o rsa/aes.o -c rsa/aes.c
	gcc -g -fPIC -o rsa/memory_buffer_alloc.o -c rsa/memory_buffer_alloc.c
	gcc -g -fPIC -o rsa/platform.o -c rsa/platform.c
	gcc -g -fPIC -o rsa/threading.o -c rsa/threading.c
	#gcc -g -fPIC -o rsa/cacheCryptoMain.o -c rsa/cacheCryptoMain.c

	gcc -g -fPIC -c -fomit-frame-pointer rsa-engine.c
	gcc -g -shared -o librsa_engine.so -L./libdune rsa-engine.o rsa/rsa.o rsa/bignum.o rsa/aes.o rsa/memory_buffer_alloc.o rsa/platform.o rsa/threading.o -Wl,-Bstatic -ldune -Wl,-Bdynamic -lcrypto -lpthread
	mv librsa_engine.so rsa-engine-new.so
	sudo cp rsa-engine-new.so /opt/openssl/lib/engines-1.1/

clean: 
	rm -f *.o *.d rsa/*.o *.so rsa-engine
