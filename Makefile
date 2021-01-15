.DEFAULT_GOAL := all

src/rs_to_openssl.o: src/rs_to_openssl.c include/rs_to_openssl.h
	gcc -c src/rs_to_openssl.c -I include -o src/rs_to_openssl.o

librs_to_openssl.a: src/rs_to_openssl.o
	ar rcs librs_to_openssl.a src/rs_to_openssl.o

test: test/main.c librs_to_openssl.a
	gcc test/main.c -o test/test -L . -l rs_to_openssl -I include

all: librs_to_openssl.a

clean:
	rm -rf librs_to_openssl.a src/rs_to_openssl.o test/test
