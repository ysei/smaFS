#ifndef translate_h
#define translate_h

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "metadata.h"

char * get_translated_path(const char *path);

#endif
