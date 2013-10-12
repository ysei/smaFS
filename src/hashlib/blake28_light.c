#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8; 

#define U8TO32(p)					\
  (((u32)((p)[0]) << 24) | ((u32)((p)[1]) << 16) |	\
   ((u32)((p)[2]) <<  8) | ((u32)((p)[3])      ))
#define U32TO8(p, v)					\
  (p)[0] = (u8)((v) >> 24); (p)[1] = (u8)((v) >> 16);	\
  (p)[2] = (u8)((v) >>  8); (p)[3] = (u8)((v)      ); 

typedef struct  { 
  u32 h[8], s[4], t[2];
  int buflen, nullt;
  u8  buf[64];
} state;

const u8 sigma[][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13 ,0 }};

const u32 cst[16] = {
  0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,
  0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89,
  0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,
  0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917};

const u8 padding[] =
  {0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


void blake28_compress( state *S, const u8 *block ) {

  u32 v[16], m[16], i;
#define ROT(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G(a,b,c,d,e)					\
  v[a] += (m[sigma[i][e]] ^ cst[sigma[i][e+1]]) + v[b];	\
  v[d] = ROT( v[d] ^ v[a],16);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c],12);				\
  v[a] += (m[sigma[i][e+1]] ^ cst[sigma[i][e]])+v[b];	\
  v[d] = ROT( v[d] ^ v[a], 8);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c], 7);				
							
  for(i=0; i<16;++i)  m[i] = U8TO32(block + i*4);
  for(i=0; i< 8;++i)  v[i] = S->h[i];
  v[ 8] = S->s[0] ^ 0x243F6A88;
  v[ 9] = S->s[1] ^ 0x85A308D3;
  v[10] = S->s[2] ^ 0x13198A2E;
  v[11] = S->s[3] ^ 0x03707344;
  v[12] =  0xA4093822;
  v[13] =  0x299F31D0;
  v[14] =  0x082EFA98;
  v[15] =  0xEC4E6C89;
  if (S->nullt == 0) { 
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for(i=0; i<10; ++i) {
    G( 0, 4, 8,12, 0);
    G( 1, 5, 9,13, 2);
    G( 2, 6,10,14, 4);
    G( 3, 7,11,15, 6);
    G( 3, 4, 9,14,14);   
    G( 2, 7, 8,13,12);
    G( 0, 5,10,15, 8);
    G( 1, 6,11,12,10);
  }

  
  for(i=0; i<16;++i)  S->h[i%8] ^= v[i]; 
  for(i=0; i<8 ;++i)  S->h[i] ^= S->s[i%4]; 
}


void blake28_init( state *S ) {
  
  S->h[0]=0xC1059ED8;
  S->h[1]=0x367CD507;
  S->h[2]=0x3070DD17;
  S->h[3]=0xF70E5939;
  S->h[4]=0xFFC00B31;
  S->h[5]=0x68581511;
  S->h[6]=0x64F98FA7;
  S->h[7]=0xBEFA4FA4;
  S->t[0]=S->t[1]=S->buflen=S->nullt=0;
  S->s[0]=S->s[1]=S->s[2]=S->s[3] =0;
}


void blake28_update( state *S, const u8 *data, u64 datalen ) {

  int left=S->buflen >> 3; 
  int fill=64 - left;
    
  if( left && ( ((datalen >> 3) & 0x3F) >= fill ) ) {
    memcpy( (void*) (S->buf + left), (void*) data, fill );
    S->t[0] += 512;
    if (S->t[0] == 0) S->t[1]++;      
    blake28_compress( S, S->buf );
    data += fill;
    datalen  -= (fill << 3);       
    left = 0;
  }

  while( datalen >= 512 ) {
    S->t[0] += 512;
    if (S->t[0] == 0) S->t[1]++;
    blake28_compress( S, data );
    data += 64;
    datalen  -= 512;
  }
  
  if( datalen > 0 ) {
    memcpy( (void*) (S->buf + left), (void*) data, datalen>>3 );
    S->buflen = (left<<3) + datalen;
  }
  else S->buflen=0;
}


void blake28_final( state *S, u8 *digest ) {
  
  u8 msglen[8], zz=0x0, oz=0x80;
  u32 lo=S->t[0] + S->buflen, hi=S->t[1];
  if ( lo < S->buflen ) hi++;
  U32TO8(  msglen + 0, hi );
  U32TO8(  msglen + 4, lo );

  if ( S->buflen == 440 ) { /* one padding byte */
    S->t[0] -= 8;
    blake28_update( S, &oz, 8 );
  }
  else {
    if ( S->buflen < 440 ) { /* enough space to fill the block  */
      if ( !S->buflen ) S->nullt=1;
      S->t[0] -= 440 - S->buflen;
      blake28_update( S, padding, 440 - S->buflen );
    }
    else { /* need 2 compressions */
      S->t[0] -= 512 - S->buflen; 
      blake28_update( S, padding, 512 - S->buflen );
      S->t[0] -= 440;
      blake28_update( S, padding+1, 440 );
      S->nullt = 1;
    }
    blake28_update( S, &zz, 8 );
    S->t[0] -= 8;
  }
  S->t[0] -= 64;
  blake28_update( S, msglen, 64 );    
  
  U32TO8( digest + 0, S->h[0]);
  U32TO8( digest + 4, S->h[1]);
  U32TO8( digest + 8, S->h[2]);
  U32TO8( digest +12, S->h[3]);
  U32TO8( digest +16, S->h[4]);
  U32TO8( digest +20, S->h[5]);
  U32TO8( digest +24, S->h[6]);
  U32TO8( digest +28, S->h[7]);
}


void blake28_hash( u8 *out, const u8 *in, u64 inlen ) {

  state S;  
  blake28_init( &S );
  blake28_update( &S, in, inlen*8 );
  blake28_final( &S, out );
}

unsigned char * gethash(const char *path)
{

    FILE *fp;
    size_t size;
    u8 *buffer;
    size_t result;
    int chunk = 64 * 1024; /* 4K chunks */

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fputs("File error", stderr);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    buffer = (u8 *)malloc(sizeof(char) * chunk);
    if (buffer == NULL) {
        fputs("Memory error", stderr);
        exit(2);
    }

    u8 *digest = (u8 *)malloc(64);
    state S;
    blake28_init( &S );

    while(size >= chunk) {
        result = fread(buffer, 1, chunk, fp);
        blake28_update( &S, buffer, chunk*8 );
        size = size-chunk;
    }
    if(size != 0) {
        printf("cool");
        result = fread(buffer, 1, size, fp);
        blake28_update( &S, buffer, size*8 );
    }
    blake28_final( &S, digest );
    fclose(fp);
    free(buffer);
    return digest;
}

void printhash(unsigned char *hash)
{
    int i;
    for (i = 0; i < 64; ++i) {
        printf("%02X", hash[i]);
    }
    printf("\n");
}


int main(int argc, char *argv[]) {

  int i, v;
  u8 data[72], digest[28];
  u8 test1[]= {0x6A, 0x45, 0x4F, 0xCA, 0x6E, 0x34, 0x7E, 0xD3, 0x31, 0xD4, 0x0A, 0x2F, 0x70, 0xF4, 0x9A, 0x2D, \
	       0xD4, 0xFE, 0x28, 0x76, 0x1C, 0xED, 0xC5, 0xAD, 0x67, 0xC3, 0x44, 0x56};
  u8 test2[]= {0x6E, 0xC8, 0xD4, 0xB0, 0xFE, 0xAE, 0xB4, 0x94, 0x50, 0xE1, 0x72, 0x23, 0x4C, 0x0B, 0x17, 0x8E, \
	       0x79, 0x5B, 0xDC, 0x18, 0xD2, 0x24, 0x20, 0xA8, 0x5B, 0x6F, 0x9B, 0xB9};

  for(i=0; i<72; ++i) data[i]=0;  

  blake28_hash( digest, data, 1 );    
  v=0;
  for(i=0; i<28; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test1[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else printf("\nok\n");

  for(i=0; i<72; ++i) data[i]=0;  

  blake28_hash( digest, data, 72 );    
  v=0;
  for(i=0; i<28; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test2[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else printf("\nok\n");

  if(argc<2) {
      printf("Usage: %s <filename>\n",argv[0]);
      exit(-1);
  }
  u8 *hash = gethash(argv[1]);
  printhash(hash);

  return 0;
}

