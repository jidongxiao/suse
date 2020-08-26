rsa-engine: rsa-engine.c rsa/rsa.c rsa/bignum.c rsa/aes.c
	    gcc -fPIC -o rsa/rsa.o -c rsa/rsa.c
	    gcc -fPIC -o rsa/bignum.o -c rsa/bignum.c
	    gcc -fPIC -o rsa/aes.o -c rsa/aes.c
	    gcc -fPIC -c rsa-engine.c
	    gcc -shared -o librsa_engine.so -lcrypto rsa-engine.o rsa/rsa.o rsa/bignum.o rsa/aes.o
	    mv librsa_engine.so rsa-engine-new.so
	    sudo cp rsa-engine-new.so /opt/openssl/lib/engines-1.1/
clean: 
	rm -f *.o rsa/*.o *.so rsa-engine
