/* http://www.mcs.anl.gov/~kazutomo/rdtsc.html
 * http://cr.yp.to/salsa20.html
 * http://cr.yp.to/snuffle.html
 * http://cr.yp.to/chacha.html
 * http://cr.yp.to/hash.html */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ecrypt-sync.h"

u8 m[4096]; u8 c[4096]; u8 d[4096];u8 k[32];
u8 v[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
u8 FSKS[64]; /* FIXED session key's source, 64 bytes */
u8 FSK[32];  /* FIXED session key, 32 bytes, 256-bit */
u8 iblock[64], cblock[64],pblock[64];

#define MAXBLOCKSIZE 512

/* timing function using the RDTSC instruction */
inline unsigned long long int rdtsc(void)
{
	unsigned long long int x;
	asm volatile (".byte 0x0f, 0x31":"=A" (x));
	return x;
}

/* generate 32 bytes FIXED session key using RDTSC + Chacha20 */
void generate_session_key()
{
	u8 m[64]; u8 d[64];
	ECRYPT_ctx x;
	int i,j;

	unsigned long long int cnt = rdtsc();
	printf("RDTSC value : %llu\n", cnt);
	
	/* copy 64 bit RDSTC value to message array */
	*((unsigned long long int *)m) = cnt;
	*((unsigned long long int *)(m+56)) = cnt; /* repeat at last too! */
	
	ECRYPT_keysetup(&x, k, 256, 64);
	ECRYPT_ivsetup(&x, v);
	ECRYPT_encrypt_bytes(&x, m, FSKS, 64);
	ECRYPT_ivsetup(&x, v);
	ECRYPT_decrypt_bytes(&x, FSKS, d, 64);

	/* Get 256-bit FSK *from* 512 bit FSKS */
	for (i = 0, j = 0; j < 32; j++,i+=2)
		FSK[j] = FSKS[i];

	for (i = 0; i < 64; ++i)
        if (d[i] != m[i])
            printf("Mismatch at position %d/%d\n", i, 64); 

	/* for (i = 0; i < 8; ++i)
		printf("%02x", ((u8*)&cnt)[i]);
	printf("\n");

	for (i = 0; i < 64; ++i)
		printf("%02x", m[i]);
	printf("\n");

	for (i = 0; i < 64; ++i)
		printf("%02x", FSKS[i]);
	printf("\n"); */

	/*for (i = 0; i < 32; ++i)
		printf("%02x", FSK[i]);
	printf("\n"); */

	/* wipe out cnt, FSKS  */
    cnt=0;
    for(i = 0; i < 64; ++i) FSKS[i]=0;
}

void key_save()
{
	/* file handles setup */
	FILE *fdout = fopen("key.txt", "wb");
	fwrite(FSK, 1, 32, fdout);
	fclose(fdout);
}

void decrypt(char *infile, char *outfile)
{
	int size = 0;
	ECRYPT_ctx x;
	FILE *fdin, *fdout;

    /* file handles setup */
    fdin = fopen(infile, "rb");
    fdout = fopen(outfile, "wb");

	ECRYPT_keysetup(&x, FSK, 256, 64);
	ECRYPT_ivsetup(&x, v);


    //read first 64 byte superblock
    /* memset(cblock, 0, 64);
    size = fread(cblock, 1, 64, fdin);
    rewind(fdin); 
    while ( (size = fread(cblock, 1, 64, fdin)) > 0) {
        ECRYPT_ivsetup(&x, v);
        ECRYPT_decrypt_bytes(&x, cblock, pblock, 64);
        fwrite(pblock, size, 1, fdout);
    } */

    while (1) {
		memset(cblock, 0, 64);
		size = fread(cblock, 1, 64, fdin);
		if(size <=0 ) break;
		ECRYPT_ivsetup(&x, v);
		ECRYPT_decrypt_bytes(&x, cblock, pblock, 64);
		if (fwrite(pblock, size, 1, fdout) != 1) {
			printf("** ERROR writing data\n");
			exit(1);
		}
	}
	fclose(fdin); fclose(fdout);
}

void encrypt()
{
	int size = 0;
	
	ECRYPT_ctx x;
	FILE *fdin, *fdout;
	/* file handles setup */
	fdin = fopen("test.txt", "rb");
	fdout = fopen("test.enc", "wb");

	//now we have that header out of the way, 
	//read in 64 byte blocks, encrypt each one
	
	ECRYPT_keysetup(&x, FSK, 256, 64);
	ECRYPT_ivsetup(&x, v);
	while (1) {
		memset(iblock, 0, 64);
		size = fread(iblock, 1, 64, fdin);
		if(size <=0 ) break;
		ECRYPT_ivsetup(&x, v);
		ECRYPT_encrypt_bytes(&x, iblock, cblock, size);	
		//ECRYPT_ivsetup(&x, v);
		//ECRYPT_decrypt_bytes(&x, cblock, pblock, 64);
		if (fwrite(cblock, size, 1, fdout) != 1) {
			printf("** ERROR writing data\n");
			exit(1);
		}
		/*if (fwrite(pblock, size, 1, fdoutp) != 1) {
			printf("** ERROR writing data\n");
			exit(1);
		} */

	}
	/*for (i = 0; i <64; ++i)
		if (ibuff[i] != dbuff[i])
			printf("mismatch at position %d/%d\n",i, bytes); */
	
	fclose(fdin);
	fclose(fdout);
}

#ifdef TESTING
int main(int argc, char *argv[])
{
	generate_session_key();
	encrypt();
	key_save();
    decrypt("test.enc", "test.pt");
	//main1();

	return 0;
} 
#endif


// Released into public domain by Thomas Dixon

#define xorshift0(x, y, z, w, t)  t=x^(x<<13); \
                                  x=y; \
                                  y=z; \
                                  z=w; \
                                  w=(w^(w>>17))^(t^(t>>5));
#define xorshift1(x) x^=(x<<13); \
                     x=(x>>17); \
                     x^=(x<<5);
                     
typedef struct xs_state {
    unsigned int x, y, z, w;
} xs_state;

void initrand(xs_state *s, unsigned int seed) {
    register unsigned int t = seed;
    xorshift1(t);
    s->x = t;
    xorshift1(t);
    s->y = t;
    xorshift1(t);
    s->z = t;
    xorshift1(t);
    s->w = t;
}

unsigned int randint(xs_state *s) {
    register unsigned int x, y, z, w, t;
    x = s->x; y = s->y; z = s->z; w = s->w;
    xorshift0(x, y, z, w, t);
    s->x = x; s->y = y; s->z = z; s->w = w;
    return w;
}

int main1() {
    xs_state s;
    initrand(&s, time(NULL));
    int i;
    for (i = 1; i <= 100; i++)
        printf("%010u%s", randint(&s), !(i%5)?"\n":" ");
    return 0;
}


int encrypt_file( char *filename)
{
	printf("Chach20 here!\n");
	return 0;
}
