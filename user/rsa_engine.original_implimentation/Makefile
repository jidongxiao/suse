rsa-engine: rsa/rsa.c rsa/bignum.c rsa/aes.c rsa/x509parse.c rsa/pem.c
	gcc -g -fPIC -o rsa/rsa.o -c rsa/rsa.c
	gcc -g -fPIC -o rsa/bignum.o -c rsa/bignum.c
	gcc -g -fPIC -o rsa/aes.o -c rsa/aes.c
	gcc -g -fPIC -o rsa/x509parse.o -c rsa/x509parse.c
	gcc -g -fPIC -o rsa/pem.o -c rsa/pem.c
	gcc -g -fPIC -o rsa/des.o -c rsa/des.c
	gcc -g -fPIC -o rsa/asn1parse.o -c rsa/asn1parse.c
	gcc -g -fPIC -o rsa/md5.o -c rsa/md5.c
	gcc -g -fPIC -o rsa/certs.o -c rsa/certs.c
	gcc -g -fPIC -o rsa/sha1.o -c rsa/sha1.c
	gcc -g -fPIC -o rsa/sha4.o -c rsa/sha4.c
	gcc -g -fPIC -o rsa/sha2.o -c rsa/sha2.c
	gcc -g -fPIC -o rsa/dhm.o -c rsa/dhm.c
	gcc -g -fPIC -o rsa/base64.o -c rsa/base64.c
	gcc -g -mrtm -fPIC -c -fomit-frame-pointer rsa-engine.c
	gcc -g -shared -o librsa_engine.so -L./libdune rsa-engine.o rsa/rsa.o rsa/bignum.o rsa/aes.o rsa/x509parse.o rsa/pem.o rsa/des.o rsa/asn1parse.o rsa/md5.o rsa/certs.o rsa/sha1.o rsa/dhm.o rsa/base64.o rsa/sha4.o rsa/sha2.o -Wl,-Bstatic -ldune -Wl,-Bdynamic -lcrypto
	mv librsa_engine.so rsa-engine-new.so
	sudo cp rsa-engine-new.so /opt/openssl/lib/engines-1.1/

clean: 
	rm -f *.o *.d rsa/*.o *.so rsa-engine
