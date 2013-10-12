#ifndef metadata_h
#define metadata_h

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <deque>

#include "hashlib/hashlib.h"
#include "ziplib/ziplib.h"
#include "restart.h"

/* structure for versioning */
struct version {
    unsigned int revision;         // version number
    unsigned char vfn[256];        // versioned file name
    unsigned char hash[64];        // cryptographic hash
    struct stat stbuf;             // stat backup
    bool isCompressed;
    unsigned int copies;
};

int create_version(const char * path, int opr);
void initialize_versions(const char * path, const char * metadatapath);
char *lookup_version(const char * path, int version);


#include <tr1/unordered_map>
#include <functional>
#include <string>

using namespace std;
using namespace tr1;

typedef unordered_map<string, int> hashmap;
extern hashmap cache;

#endif
