INCLUDES = -I../include -I../ctaocrypt/include

lib_LTLIBRARIES = libcyassl.la
libcyassl_la_SOURCES = cyassl_int.c cyassl_io.c keys.c ssl.c tls.c \
    ../ctaocrypt/src/asn.c ../ctaocrypt/src/coding.c ../ctaocrypt/src/des3.c \
    ../ctaocrypt/src/hmac.c ../ctaocrypt/src/integer.c ../ctaocrypt/src/md5.c \
    ../ctaocrypt/src/random.c ../ctaocrypt/src/rsa.c ../ctaocrypt/src/sha.c \
    ../ctaocrypt/src/aes.c ../ctaocrypt/src/sha256.c ../ctaocrypt/src/dh.c \
    ../ctaocrypt/src/dsa.c ../ctaocrypt/src/arc4.c ../ctaocrypt/src/hc128.c \
    ../ctaocrypt/src/rabbit.c ../ctaocrypt/src/md4.c
libcyassl_la_LDFLAGS = -no-undefined -version-info 0:0:0
AM_CFLAGS = -Wall
EXTRA_DIST = ../include/*.h ../include/openssl/*.h

