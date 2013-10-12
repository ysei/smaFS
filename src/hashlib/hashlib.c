#include "hashlib.h"

/* http://en.wikipedia.org/wiki/Fletcher's_checksum */

static uint32_t sum1 = 0xffff, sum2 = 0xffff;
static uint32_t checksum = 0;

void fletcher32( uint16_t *data, size_t len)
{
    while (len) {
        unsigned tlen = len > 360 ? 360 : len;
        len -= tlen;
        do {
            sum1 += *data++;
            sum2 += sum1;
        } while (--tlen);
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    }
    /* Second reduction step to reduce sums to 16 bits */
    sum1 = (sum1 & 0xffff) + (sum1 >> 16);
    sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    
}

void printhash(unsigned char *hash)
{
    int i;
    for (i = 0; i < 4; ++i) {
        printf("%02X", hash[i]);
    }
    printf("\n");
}

/* process file in chunks - uses fixed amount of memory */
unsigned char *gethash(const char *path)
{
    FILE *fp;
    size_t size;
    unsigned char *buffer;
    size_t result;
    unsigned int chunk = 64 * 1024; /* 64K chunks */

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fputs("File open error\n", stderr);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    buffer = (unsigned char *)malloc(sizeof(char) * chunk);
    if (buffer == NULL) {
        fputs("Memory allocation error!\n", stderr);
        exit(EXIT_FAILURE);
    }

    sum1 = sum2 = 0;
    while(size >= chunk) {
        result = fread(buffer, 1, chunk, fp);
        fletcher32((uint16_t *)buffer, result/2); 
        size = size-chunk;
    }
    if(size != 0) {
        result = fread(buffer, 1, size, fp);
        fletcher32((uint16_t *)buffer, result/2); 
    }
    
    checksum = sum2 << 16 | sum1;
    
    fclose(fp);
    free(buffer);
    
    return (unsigned char*)&checksum;
}

#ifdef hashlib_DEBUG

int main(int argc, char *argv[]) 
{
    if(argc<2) {
        printf("Usage: %s <filename>\n",argv[0]);
        exit(-1);
    }
    unsigned char *hash = gethash(argv[1]);
    printhash(hash);
    return 0;
}

#endif

