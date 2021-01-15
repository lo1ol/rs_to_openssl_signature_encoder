.DEFAULT_GOAL := all

src/asn1.o: src/asn1.c include/asn1.h
	gcc -c src/asn1.c -I include -o src/asn1.o

libasn1.a: src/asn1.o
	ar rcs libasn1.a src/asn1.o

test: test/main.c libasn1.a
	gcc test/main.c -o test/test -L . -l asn1 -I include

all: libasn1.a

clean:
	rm -rf libasn1.a src/asn1.o test/test
