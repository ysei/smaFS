#ifndef hashlib_h
#define hashlib_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

unsigned char *gethash(const char *path);
void printhash(unsigned char *hash);

#endif
