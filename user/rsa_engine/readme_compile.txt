1. for compile
	gcc -fPIC -c rsa-engine.c
2. Create a shared file 
	gcc -shared -o librsa_engine.so -lcrypto rsa-engine.o

3. Load the engine
	openssl engine -t -c `pwd`/librsa_engine.so

4. Use this engine for encryption and decryption
	a. rename "librsa_engine.so" to "rsa-engine-new.so" (engine_id)
	b. copy "rsa-engine-new.so" to the openssl directory (e.g : /opt/openssl/lib/engines-1.1/rsa-engine-new.so)
	c. generate Keys:
		I. private key --> openssl genrsa -aes128 -out private.pem 1024
	       II. publick key --> openssl rsa -in private.pem -pubout > public.pem
	d. Create a message --> echo "Hack me if you can." > msg.txt 
	e. encryption
		I. openssl rsautl -encrypt -inkey public.pem -pubin -in msg.txt -out msg.enc -engine rsa-engine-new
	f. Decryption:
		I. openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new
		or		
		II. openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine `pwd`/librsa_engine.so
		or
		III. taskset -c 1 sudo openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new


######################## Compile all the RSA related file into one single lib file ############
$ cd rsa/
	gcc -fPIC -o rsa.o -c rsa.c
	gcc -fPIC -o bignum.o -c bignum.c
	gcc -fPIC -o aes.o -c aes.c

rsa_engine/
	gcc -shared -o librsa_engine.so -lcrypto rsa-engine.o rsa/rsa.o rsa/bignum.o rsa/aes.o

