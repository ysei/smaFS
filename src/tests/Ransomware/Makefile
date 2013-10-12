# Example Makefile for the optimised ANSI C Rijndael code
# v2.0 

CFLAGS=-Wall -O2

SUBDIRS = Chacha20


all:
	@for i in $(SUBDIRS); do \
        echo "make all in $$i..."; \
        (cd $$i; $(MAKE) $(MFLAGS) $(MYMAKEFLAGS) all); done
	
	gcc RansomWare.c mysrm.c Chacha20/encrypt.c Chacha20/chacha.c cyassl/ctaocrypt/benchmark/benchmark.o cyassl/src/.libs/libcyassl.a -o test
	strip test
clean:
	rm test
