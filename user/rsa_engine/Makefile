rsa-engine: rsa-engine.c rsa/rsa.c rsa/bignum.c rsa/aes.c rsa/x509parse.c rsa/pem.c
	gcc -fPIC -o rsa/rsa.o -c rsa/rsa.c
	gcc -fPIC -o rsa/bignum.o -c rsa/bignum.c
	gcc -fPIC -o rsa/aes.o -c rsa/aes.c
	gcc -fPIC -o rsa/x509parse.o -c rsa/x509parse.c
	gcc -fPIC -o rsa/pem.o -c rsa/pem.c
	gcc -fPIC -o rsa/des.o -c rsa/des.c
	gcc -fPIC -o rsa/asn1parse.o -c rsa/asn1parse.c
	gcc -fPIC -o rsa/md5.o -c rsa/md5.c
	gcc -fPIC -o rsa/certs.o -c rsa/certs.c
	gcc -fPIC -o rsa/sha1.o -c rsa/sha1.c
	gcc -fPIC -o rsa/sha4.o -c rsa/sha4.c
	gcc -fPIC -o rsa/sha2.o -c rsa/sha2.c
	gcc -fPIC -o rsa/dhm.o -c rsa/dhm.c
	gcc -fPIC -o rsa/base64.o -c rsa/base64.c

	gcc -mrtm -fPIC -c rsa-engine.c

	gcc -shared -o librsa_engine.so -lcrypto rsa-engine.o rsa/rsa.o rsa/bignum.o rsa/aes.o rsa/x509parse.o rsa/pem.o rsa/des.o rsa/asn1parse.o rsa/md5.o rsa/certs.o rsa/sha1.o rsa/dhm.o rsa/base64.o rsa/sha4.o rsa/sha2.o
	mv librsa_engine.so rsa-engine-new.so
	sudo cp rsa-engine-new.so /opt/openssl/lib/engines-1.1/
clean: 
	rm -f *.o rsa/*.o *.so rsa-engine
