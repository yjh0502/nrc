/*
version 20080912
D. J. Bernstein
Public domain.
*/

#include "nacl.h"

extern int crypto_stream_salsa20(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_beforenm(unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_afternm(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_xor_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

extern int crypto_stream_xsalsa20(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_xsalsa20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_xsalsa20_beforenm(unsigned char *,const unsigned char *);
extern int crypto_stream_xsalsa20_afternm(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_xsalsa20_xor_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

extern int crypto_scalarmult_curve25519(unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_scalarmult_curve25519_base(unsigned char *,const unsigned char *);

extern int crypto_hash_sha512(unsigned char *,const unsigned char *,unsigned long long);
#define crypto_hash_sha512_BYTES 64

extern int crypto_hashblocks_sha512(unsigned char *,const unsigned char *,unsigned long long);

typedef unsigned int crypto_uint32;

#define ROUNDS 20

typedef unsigned int uint32;

static uint32 rotate(uint32 u,int c)
{
  return (u << c) | (u >> (32 - c));
}

static uint32 load_littleendian(const unsigned char *x)
{
  return
      (uint32) (x[0]) \
  | (((uint32) (x[1])) << 8) \
  | (((uint32) (x[2])) << 16) \
  | (((uint32) (x[3])) << 24)
  ;
}

static void store_littleendian(unsigned char *x,uint32 u)
{
  x[0] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[3] = u;
}

int crypto_core_salsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  int i;

  j0 = x0 = load_littleendian(c + 0);
  j1 = x1 = load_littleendian(k + 0);
  j2 = x2 = load_littleendian(k + 4);
  j3 = x3 = load_littleendian(k + 8);
  j4 = x4 = load_littleendian(k + 12);
  j5 = x5 = load_littleendian(c + 4);
  j6 = x6 = load_littleendian(in + 0);
  j7 = x7 = load_littleendian(in + 4);
  j8 = x8 = load_littleendian(in + 8);
  j9 = x9 = load_littleendian(in + 12);
  j10 = x10 = load_littleendian(c + 8);
  j11 = x11 = load_littleendian(k + 16);
  j12 = x12 = load_littleendian(k + 20);
  j13 = x13 = load_littleendian(k + 24);
  j14 = x14 = load_littleendian(k + 28);
  j15 = x15 = load_littleendian(c + 12);

  for (i = ROUNDS;i > 0;i -= 2) {
     x4 ^= rotate( x0+x12, 7);
     x8 ^= rotate( x4+ x0, 9);
    x12 ^= rotate( x8+ x4,13);
     x0 ^= rotate(x12+ x8,18);
     x9 ^= rotate( x5+ x1, 7);
    x13 ^= rotate( x9+ x5, 9);
     x1 ^= rotate(x13+ x9,13);
     x5 ^= rotate( x1+x13,18);
    x14 ^= rotate(x10+ x6, 7);
     x2 ^= rotate(x14+x10, 9);
     x6 ^= rotate( x2+x14,13);
    x10 ^= rotate( x6+ x2,18);
     x3 ^= rotate(x15+x11, 7);
     x7 ^= rotate( x3+x15, 9);
    x11 ^= rotate( x7+ x3,13);
    x15 ^= rotate(x11+ x7,18);
     x1 ^= rotate( x0+ x3, 7);
     x2 ^= rotate( x1+ x0, 9);
     x3 ^= rotate( x2+ x1,13);
     x0 ^= rotate( x3+ x2,18);
     x6 ^= rotate( x5+ x4, 7);
     x7 ^= rotate( x6+ x5, 9);
     x4 ^= rotate( x7+ x6,13);
     x5 ^= rotate( x4+ x7,18);
    x11 ^= rotate(x10+ x9, 7);
     x8 ^= rotate(x11+x10, 9);
     x9 ^= rotate( x8+x11,13);
    x10 ^= rotate( x9+ x8,18);
    x12 ^= rotate(x15+x14, 7);
    x13 ^= rotate(x12+x15, 9);
    x14 ^= rotate(x13+x12,13);
    x15 ^= rotate(x14+x13,18);
  }

  x0 += j0;
  x1 += j1;
  x2 += j2;
  x3 += j3;
  x4 += j4;
  x5 += j5;
  x6 += j6;
  x7 += j7;
  x8 += j8;
  x9 += j9;
  x10 += j10;
  x11 += j11;
  x12 += j12;
  x13 += j13;
  x14 += j14;
  x15 += j15;

  store_littleendian(out + 0,x0);
  store_littleendian(out + 4,x1);
  store_littleendian(out + 8,x2);
  store_littleendian(out + 12,x3);
  store_littleendian(out + 16,x4);
  store_littleendian(out + 20,x5);
  store_littleendian(out + 24,x6);
  store_littleendian(out + 28,x7);
  store_littleendian(out + 32,x8);
  store_littleendian(out + 36,x9);
  store_littleendian(out + 40,x10);
  store_littleendian(out + 44,x11);
  store_littleendian(out + 48,x12);
  store_littleendian(out + 52,x13);
  store_littleendian(out + 56,x14);
  store_littleendian(out + 60,x15);

  return 0;
}

typedef unsigned int uint32;
int crypto_core_hsalsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  int i;

  x0 = load_littleendian(c + 0);
  x1 = load_littleendian(k + 0);
  x2 = load_littleendian(k + 4);
  x3 = load_littleendian(k + 8);
  x4 = load_littleendian(k + 12);
  x5 = load_littleendian(c + 4);
  x6 = load_littleendian(in + 0);
  x7 = load_littleendian(in + 4);
  x8 = load_littleendian(in + 8);
  x9 = load_littleendian(in + 12);
  x10 = load_littleendian(c + 8);
  x11 = load_littleendian(k + 16);
  x12 = load_littleendian(k + 20);
  x13 = load_littleendian(k + 24);
  x14 = load_littleendian(k + 28);
  x15 = load_littleendian(c + 12);

  for (i = ROUNDS;i > 0;i -= 2) {
     x4 ^= rotate( x0+x12, 7);
     x8 ^= rotate( x4+ x0, 9);
    x12 ^= rotate( x8+ x4,13);
     x0 ^= rotate(x12+ x8,18);
     x9 ^= rotate( x5+ x1, 7);
    x13 ^= rotate( x9+ x5, 9);
     x1 ^= rotate(x13+ x9,13);
     x5 ^= rotate( x1+x13,18);
    x14 ^= rotate(x10+ x6, 7);
     x2 ^= rotate(x14+x10, 9);
     x6 ^= rotate( x2+x14,13);
    x10 ^= rotate( x6+ x2,18);
     x3 ^= rotate(x15+x11, 7);
     x7 ^= rotate( x3+x15, 9);
    x11 ^= rotate( x7+ x3,13);
    x15 ^= rotate(x11+ x7,18);
     x1 ^= rotate( x0+ x3, 7);
     x2 ^= rotate( x1+ x0, 9);
     x3 ^= rotate( x2+ x1,13);
     x0 ^= rotate( x3+ x2,18);
     x6 ^= rotate( x5+ x4, 7);
     x7 ^= rotate( x6+ x5, 9);
     x4 ^= rotate( x7+ x6,13);
     x5 ^= rotate( x4+ x7,18);
    x11 ^= rotate(x10+ x9, 7);
     x8 ^= rotate(x11+x10, 9);
     x9 ^= rotate( x8+x11,13);
    x10 ^= rotate( x9+ x8,18);
    x12 ^= rotate(x15+x14, 7);
    x13 ^= rotate(x12+x15, 9);
    x14 ^= rotate(x13+x12,13);
    x15 ^= rotate(x14+x13,18);
  }

  store_littleendian(out + 0,x0);
  store_littleendian(out + 4,x5);
  store_littleendian(out + 8,x10);
  store_littleendian(out + 12,x15);
  store_littleendian(out + 16,x6);
  store_littleendian(out + 20,x7);
  store_littleendian(out + 24,x8);
  store_littleendian(out + 28,x9);

  return 0;
}


static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_xsalsa20(
        unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char subkey[32];
  crypto_core_hsalsa20(subkey,n,k,sigma);
  return crypto_stream_salsa20(c,clen,n + 16,subkey);
}

int crypto_stream_xsalsa20_xor(
        unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char subkey[32];
  crypto_core_hsalsa20(subkey,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,mlen,n + 16,subkey);
}

int crypto_stream_salsa20(
        unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char in[16];
  unsigned char block[64];
  int i;
  unsigned int u;

  if (!clen) return 0;

  for (i = 0;i < 8;++i) in[i] = n[i];
  for (i = 8;i < 16;++i) in[i] = 0;

  while (clen >= 64) {
    crypto_core_salsa20(c,in,k,sigma);

    u = 1;
    for (i = 8;i < 16;++i) {
      u += (unsigned int) in[i];
      in[i] = u;
      u >>= 8;
    }

    clen -= 64;
    c += 64;
  }

  if (clen) {
    crypto_core_salsa20(block,in,k,sigma);
    for (i = 0;i < clen;++i) c[i] = block[i];
  }
  return 0;
}

int crypto_stream_salsa20_xor(
        unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char in[16];
  unsigned char block[64];
  int i;
  unsigned int u;

  if (!mlen) return 0;

  for (i = 0;i < 8;++i) in[i] = n[i];
  for (i = 8;i < 16;++i) in[i] = 0;

  while (mlen >= 64) {
    crypto_core_salsa20(block,in,k,sigma);
    for (i = 0;i < 64;++i) c[i] = m[i] ^ block[i];

    u = 1;
    for (i = 8;i < 16;++i) {
      u += (unsigned int) in[i];
      in[i] = u;
      u >>= 8;
    }

    mlen -= 64;
    c += 64;
    m += 64;
  }

  if (mlen) {
    crypto_core_salsa20(block,in,k,sigma);
    for (i = 0;i < mlen;++i) c[i] = m[i] ^ block[i];
  }
  return 0;
}


/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/


const unsigned char base[32] = {9};

int crypto_scalarmult_curve25519_base(unsigned char *q,
  const unsigned char *n)
{
  return crypto_scalarmult_curve25519(q,n,base);
}

static void add(unsigned int out[32],const unsigned int a[32],const unsigned int b[32])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 31;++j) { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
  u += a[31] + b[31]; out[31] = u;
}

static void sub(unsigned int out[32],const unsigned int a[32],const unsigned int b[32])
{
  unsigned int j;
  unsigned int u;
  u = 218;
  for (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}

static void squeeze(unsigned int a[32])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

static const unsigned int minusp[32] = {
 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
} ;

static void freeze(unsigned int a[32])
{
  unsigned int aorig[32];
  unsigned int j;
  unsigned int negative;

  for (j = 0;j < 32;++j) aorig[j] = a[j];
  add(a,a,minusp);
  negative = -((a[31] >> 7) & 1);
  for (j = 0;j < 32;++j) a[j] ^= negative & (aorig[j] ^ a[j]);
}

static void mult(unsigned int out[32],const unsigned int a[32],const unsigned int b[32])
{
  unsigned int i;
  unsigned int j;
  unsigned int u;

  for (i = 0;i < 32;++i) {
    u = 0;
    for (j = 0;j <= i;++j) u += a[j] * b[i - j];
    for (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  squeeze(out);
}

static void mult121665(unsigned int out[32],const unsigned int a[32])
{
  unsigned int j;
  unsigned int u;

  u = 0;
  for (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}

static void square(unsigned int out[32],const unsigned int a[32])
{
  unsigned int i;
  unsigned int j;
  unsigned int u;

  for (i = 0;i < 32;++i) {
    u = 0;
    for (j = 0;j < i - j;++j) u += a[j] * a[i - j];
    for (j = i + 1;j < i + 32 - j;++j) u += 38 * a[j] * a[i + 32 - j];
    u *= 2;
    if ((i & 1) == 0) {
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  squeeze(out);
}

static void select(unsigned int p[64],unsigned int q[64],const unsigned int r[64],const unsigned int s[64],unsigned int b)
{
  unsigned int j;
  unsigned int t;
  unsigned int bminus1;

  bminus1 = b - 1;
  for (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}

static void mainloop(unsigned int work[64],const unsigned char e[32])
{
  unsigned int xzm1[64];
  unsigned int xzm[64];
  unsigned int xzmb[64];
  unsigned int xzm1b[64];
  unsigned int xznb[64];
  unsigned int xzn1b[64];
  unsigned int a0[64];
  unsigned int a1[64];
  unsigned int b0[64];
  unsigned int b1[64];
  unsigned int c1[64];
  unsigned int r[32];
  unsigned int s[32];
  unsigned int t[32];
  unsigned int u[32];
  //unsigned int i;
  unsigned int j;
  unsigned int b;
  int pos;

  for (j = 0;j < 32;++j) xzm1[j] = work[j];
  xzm1[32] = 1;
  for (j = 33;j < 64;++j) xzm1[j] = 0;

  xzm[0] = 1;
  for (j = 1;j < 64;++j) xzm[j] = 0;

  for (pos = 254;pos >= 0;--pos) {
    b = e[pos / 8] >> (pos & 7);
    b &= 1;
    select(xzmb,xzm1b,xzm,xzm1,b);
    add(a0,xzmb,xzmb + 32);
    sub(a0 + 32,xzmb,xzmb + 32);
    add(a1,xzm1b,xzm1b + 32);
    sub(a1 + 32,xzm1b,xzm1b + 32);
    square(b0,a0);
    square(b0 + 32,a0 + 32);
    mult(b1,a1,a0 + 32);
    mult(b1 + 32,a1 + 32,a0);
    add(c1,b1,b1 + 32);
    sub(c1 + 32,b1,b1 + 32);
    square(r,c1 + 32);
    sub(s,b0,b0 + 32);
    mult121665(t,s);
    add(u,t,b0);
    mult(xznb,b0,b0 + 32);
    mult(xznb + 32,s,u);
    square(xzn1b,c1);
    mult(xzn1b + 32,r,work);
    select(xzm,xzm1,xznb,xzn1b,b);
  }

  for (j = 0;j < 64;++j) work[j] = xzm[j];
}

static void recip(unsigned int out[32],const unsigned int z[32])
{
  unsigned int z2[32];
  unsigned int z9[32];
  unsigned int z11[32];
  unsigned int z2_5_0[32];
  unsigned int z2_10_0[32];
  unsigned int z2_20_0[32];
  unsigned int z2_50_0[32];
  unsigned int z2_100_0[32];
  unsigned int t0[32];
  unsigned int t1[32];
  int i;

  /* 2 */ square(z2,z);
  /* 4 */ square(t1,z2);
  /* 8 */ square(t0,t1);
  /* 9 */ mult(z9,t0,z);
  /* 11 */ mult(z11,z9,z2);
  /* 22 */ square(t0,z11);
  /* 2^5 - 2^0 = 31 */ mult(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */ square(t0,z2_5_0);
  /* 2^7 - 2^2 */ square(t1,t0);
  /* 2^8 - 2^3 */ square(t0,t1);
  /* 2^9 - 2^4 */ square(t1,t0);
  /* 2^10 - 2^5 */ square(t0,t1);
  /* 2^10 - 2^0 */ mult(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */ square(t0,z2_10_0);
  /* 2^12 - 2^2 */ square(t1,t0);
  /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^20 - 2^0 */ mult(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ square(t0,z2_20_0);
  /* 2^22 - 2^2 */ square(t1,t0);
  /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^40 - 2^0 */ mult(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ square(t1,t0);
  /* 2^42 - 2^2 */ square(t0,t1);
  /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^50 - 2^0 */ mult(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ square(t0,z2_50_0);
  /* 2^52 - 2^2 */ square(t1,t0);
  /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^100 - 2^0 */ mult(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ square(t1,z2_100_0);
  /* 2^102 - 2^2 */ square(t0,t1);
  /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^200 - 2^0 */ mult(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ square(t0,t1);
  /* 2^202 - 2^2 */ square(t1,t0);
  /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^250 - 2^0 */ mult(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ square(t1,t0);
  /* 2^252 - 2^2 */ square(t0,t1);
  /* 2^253 - 2^3 */ square(t1,t0);
  /* 2^254 - 2^4 */ square(t0,t1);
  /* 2^255 - 2^5 */ square(t1,t0);
  /* 2^255 - 21 */ mult(out,t1,z11);
}

int crypto_scalarmult_curve25519(unsigned char *q,
  const unsigned char *n,
  const unsigned char *p)
{
  unsigned int work[96];
  unsigned char e[32];
  unsigned int i;
  for (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  for (i = 0;i < 32;++i) work[i] = p[i];
  mainloop(work,e);
  recip(work + 32,work + 32);
  mult(work + 64,work,work + 32);
  freeze(work + 64);
  for (i = 0;i < 32;++i) q[i] = work[64 + i];
  return 0;
}




/*
20080910
D. J. Bernstein
Public domain.
*/

typedef unsigned char uchar;
typedef int int32;
typedef unsigned int uint32;
typedef long long int64;
typedef unsigned long long uint64;

static const double poly1305_53_constants[] = {
  0.00000000558793544769287109375 /* alpham80 = 3 2^(-29) */
, 24.0 /* alpham48 = 3 2^3 */
, 103079215104.0 /* alpham16 = 3 2^35 */
, 6755399441055744.0 /* alpha0 = 3 2^51 */
, 1770887431076116955136.0 /* alpha18 = 3 2^69 */
, 29014219670751100192948224.0 /* alpha32 = 3 2^83 */
, 7605903601369376408980219232256.0 /* alpha50 = 3 2^101 */
, 124615124604835863084731911901282304.0 /* alpha64 = 3 2^115 */
, 32667107224410092492483962313449748299776.0 /* alpha82 = 3 2^133 */
, 535217884764734955396857238543560676143529984.0 /* alpha96 = 3 2^147 */
, 35076039295941670036888435985190792471742381031424.0 /* alpha112 = 3 2^163 */
, 9194973245195333150150082162901855101712434733101613056.0 /* alpha130 = 3 2^181 */
, 0.0000000000000000000000000000000000000036734198463196484624023016788195177431833298649127735047148490821200539357960224151611328125 /* scale = 5 2^(-130) */
, 6755408030990331.0 /* offset0 = alpha0 + 2^33 - 5 */
, 29014256564239239022116864.0 /* offset1 = alpha32 + 2^65 - 2^33 */
, 124615283061160854719918951570079744.0 /* offset2 = alpha64 + 2^97 - 2^65 */
, 535219245894202480694386063513315216128475136.0 /* offset3 = alpha96 + 2^130 - 2^97 */
} ;

int crypto_onetimeauth_poly1305(unsigned char *out,const unsigned char *m,unsigned long long l,const unsigned char *k)
{
  register const unsigned char *r = k;
  register const unsigned char *s = k + 16;
  double r0high_stack;
  double r1high_stack;
  double r1low_stack;
  double sr1high_stack;
  double r2low_stack;
  double sr2high_stack;
  double r0low_stack;
  double sr1low_stack;
  double r2high_stack;
  double sr2low_stack;
  double r3high_stack;
  double sr3high_stack;
  double r3low_stack;
  double sr3low_stack;
  int64 d0;
  int64 d1;
  int64 d2;
  int64 d3;
  register double scale;
  register double alpha0;
  register double alpha32;
  register double alpha64;
  register double alpha96;
  register double alpha130;
  register double h0;
  register double h1;
  register double h2;
  register double h3;
  register double h4;
  register double h5;
  register double h6;
  register double h7;
  register double y7;
  register double y6;
  register double y1;
  register double y0;
  register double y5;
  register double y4;
  register double x7;
  register double x6;
  register double x1;
  register double x0;
  register double y3;
  register double y2;
  register double r3low;
  register double r0low;
  register double r3high;
  register double r0high;
  register double sr1low;
  register double x5;
  register double r3lowx0;
  register double sr1high;
  register double x4;
  register double r0lowx6;
  register double r1low;
  register double x3;
  register double r3highx0;
  register double r1high;
  register double x2;
  register double r0highx6;
  register double sr2low;
  register double r0lowx0;
  register double sr2high;
  register double sr1lowx6;
  register double r2low;
  register double r0highx0;
  register double r2high;
  register double sr1highx6;
  register double sr3low;
  register double r1lowx0;
  register double sr3high;
  register double sr2lowx6;
  register double r1highx0;
  register double sr2highx6;
  register double r2lowx0;
  register double sr3lowx6;
  register double r2highx0;
  register double sr3highx6;
  register double r1highx4;
  register double r1lowx4;
  register double r0highx4;
  register double r0lowx4;
  register double sr3highx4;
  register double sr3lowx4;
  register double sr2highx4;
  register double sr2lowx4;
  register double r0lowx2;
  register double r0highx2;
  register double r1lowx2;
  register double r1highx2;
  register double r2lowx2;
  register double r2highx2;
  register double sr3lowx2;
  register double sr3highx2;
  register double z0;
  register double z1;
  register double z2;
  register double z3;
  register int64 r0;
  register int64 r1;
  register int64 r2;
  register int64 r3;
  register uint32 r00;
  register uint32 r01;
  register uint32 r02;
  register uint32 r03;
  register uint32 r10;
  register uint32 r11;
  register uint32 r12;
  register uint32 r13;
  register uint32 r20;
  register uint32 r21;
  register uint32 r22;
  register uint32 r23;
  register uint32 r30;
  register uint32 r31;
  register uint32 r32;
  register uint32 r33;
  register int64 m0;
  register int64 m1;
  register int64 m2;
  register int64 m3;
  register uint32 m00;
  register uint32 m01;
  register uint32 m02;
  register uint32 m03;
  register uint32 m10;
  register uint32 m11;
  register uint32 m12;
  register uint32 m13;
  register uint32 m20;
  register uint32 m21;
  register uint32 m22;
  register uint32 m23;
  register uint32 m30;
  register uint32 m31;
  register uint32 m32;
  register uint64 m33;
  register char *constants;
  register int32 lbelow2;
  register int32 lbelow3;
  register int32 lbelow4;
  register int32 lbelow5;
  register int32 lbelow6;
  register int32 lbelow7;
  register int32 lbelow8;
  register int32 lbelow9;
  register int32 lbelow10;
  register int32 lbelow11;
  register int32 lbelow12;
  register int32 lbelow13;
  register int32 lbelow14;
  register int32 lbelow15;
  register double alpham80;
  register double alpham48;
  register double alpham16;
  register double alpha18;
  register double alpha50;
  register double alpha82;
  register double alpha112;
  register double offset0;
  register double offset1;
  register double offset2;
  register double offset3;
  register uint32 s00;
  register uint32 s01;
  register uint32 s02;
  register uint32 s03;
  register uint32 s10;
  register uint32 s11;
  register uint32 s12;
  register uint32 s13;
  register uint32 s20;
  register uint32 s21;
  register uint32 s22;
  register uint32 s23;
  register uint32 s30;
  register uint32 s31;
  register uint32 s32;
  register uint32 s33;
  register uint64 bits32;
  register uint64 f;
  register uint64 f0;
  register uint64 f1;
  register uint64 f2;
  register uint64 f3;
  register uint64 f4;
  register uint64 g;
  register uint64 g0;
  register uint64 g1;
  register uint64 g2;
  register uint64 g3;
  register uint64 g4;

  r00 = *(uchar *) (r + 0);
  constants = (char *) &poly1305_53_constants;

  r01 = *(uchar *) (r + 1);

  r02 = *(uchar *) (r + 2);
  r0 = 2151;

  r03 = *(uchar *) (r + 3); r03 &= 15;
  r0 <<= 51;

  r10 = *(uchar *) (r + 4); r10 &= 252;
  r01 <<= 8;
  r0 += r00;

  r11 = *(uchar *) (r + 5);
  r02 <<= 16;
  r0 += r01;

  r12 = *(uchar *) (r + 6);
  r03 <<= 24;
  r0 += r02;

  r13 = *(uchar *) (r + 7); r13 &= 15;
  r1 = 2215;
  r0 += r03;

  d0 = r0;
  r1 <<= 51;
  r2 = 2279;

  r20 = *(uchar *) (r + 8); r20 &= 252;
  r11 <<= 8;
  r1 += r10;

  r21 = *(uchar *) (r + 9);
  r12 <<= 16;
  r1 += r11;

  r22 = *(uchar *) (r + 10);
  r13 <<= 24;
  r1 += r12;

  r23 = *(uchar *) (r + 11); r23 &= 15;
  r2 <<= 51;
  r1 += r13;

  d1 = r1;
  r21 <<= 8;
  r2 += r20;

  r30 = *(uchar *) (r + 12); r30 &= 252;
  r22 <<= 16;
  r2 += r21;

  r31 = *(uchar *) (r + 13);
  r23 <<= 24;
  r2 += r22;

  r32 = *(uchar *) (r + 14);
  r2 += r23;
  r3 = 2343;

  d2 = r2;
  r3 <<= 51;
  alpha32 = *(double *) (constants + 40);

  r33 = *(uchar *) (r + 15); r33 &= 15;
  r31 <<= 8;
  r3 += r30;

  r32 <<= 16;
  r3 += r31;

  r33 <<= 24;
  r3 += r32;

  r3 += r33;
  h0 = alpha32 - alpha32;

  d3 = r3;
  h1 = alpha32 - alpha32;

  alpha0 = *(double *) (constants + 24);
  h2 = alpha32 - alpha32;

  alpha64 = *(double *) (constants + 56);
  h3 = alpha32 - alpha32;

  alpha18 = *(double *) (constants + 32);
  h4 = alpha32 - alpha32;

  r0low = *(double *) &d0;
  h5 = alpha32 - alpha32;

  r1low = *(double *) &d1;
  h6 = alpha32 - alpha32;

  r2low = *(double *) &d2;
  h7 = alpha32 - alpha32;

  alpha50 = *(double *) (constants + 48);
  r0low -= alpha0;

  alpha82 = *(double *) (constants + 64);
  r1low -= alpha32;

  scale = *(double *) (constants + 96);
  r2low -= alpha64;

  alpha96 = *(double *) (constants + 72);
  r0high = r0low + alpha18;

  r3low = *(double *) &d3;

  alpham80 = *(double *) (constants + 0);
  r1high = r1low + alpha50;
  sr1low = scale * r1low;

  alpham48 = *(double *) (constants + 8);
  r2high = r2low + alpha82;
  sr2low = scale * r2low;

  r0high -= alpha18;
  r0high_stack = r0high;

  r3low -= alpha96;

  r1high -= alpha50;
  r1high_stack = r1high;

  sr1high = sr1low + alpham80;

  alpha112 = *(double *) (constants + 80);
  r0low -= r0high;

  alpham16 = *(double *) (constants + 16);
  r2high -= alpha82;
  sr3low = scale * r3low;

  alpha130 = *(double *) (constants + 88);
  sr2high = sr2low + alpham48;

  r1low -= r1high;
  r1low_stack = r1low;

  sr1high -= alpham80;
  sr1high_stack = sr1high;

  r2low -= r2high;
  r2low_stack = r2low;

  sr2high -= alpham48;
  sr2high_stack = sr2high;

  r3high = r3low + alpha112;
  r0low_stack = r0low;

  sr1low -= sr1high;
  sr1low_stack = sr1low;

  sr3high = sr3low + alpham16;
  r2high_stack = r2high;

  sr2low -= sr2high;
  sr2low_stack = sr2low;

  r3high -= alpha112;
  r3high_stack = r3high;


  sr3high -= alpham16;
  sr3high_stack = sr3high;


  r3low -= r3high;
  r3low_stack = r3low;


  sr3low -= sr3high;
  sr3low_stack = sr3low;

if (l < 16) goto addatmost15bytes;

  m00 = *(uchar *) (m + 0);
  m0 = 2151;

  m0 <<= 51;
  m1 = 2215;
  m01 = *(uchar *) (m + 1);

  m1 <<= 51;
  m2 = 2279;
  m02 = *(uchar *) (m + 2);

  m2 <<= 51;
  m3 = 2343;
  m03 = *(uchar *) (m + 3);

  m10 = *(uchar *) (m + 4);
  m01 <<= 8;
  m0 += m00;

  m11 = *(uchar *) (m + 5);
  m02 <<= 16;
  m0 += m01;

  m12 = *(uchar *) (m + 6);
  m03 <<= 24;
  m0 += m02;

  m13 = *(uchar *) (m + 7);
  m3 <<= 51;
  m0 += m03;

  m20 = *(uchar *) (m + 8);
  m11 <<= 8;
  m1 += m10;

  m21 = *(uchar *) (m + 9);
  m12 <<= 16;
  m1 += m11;

  m22 = *(uchar *) (m + 10);
  m13 <<= 24;
  m1 += m12;

  m23 = *(uchar *) (m + 11);
  m1 += m13;

  m30 = *(uchar *) (m + 12);
  m21 <<= 8;
  m2 += m20;

  m31 = *(uchar *) (m + 13);
  m22 <<= 16;
  m2 += m21;

  m32 = *(uchar *) (m + 14);
  m23 <<= 24;
  m2 += m22;

  m33 = *(uchar *) (m + 15);
  m2 += m23;

  d0 = m0;
  m31 <<= 8;
  m3 += m30;

  d1 = m1;
  m32 <<= 16;
  m3 += m31;

  d2 = m2;
  m33 += 256;

  m33 <<= 24;
  m3 += m32;

  m3 += m33;
  d3 = m3;

  m += 16;
  l -= 16;

  z0 = *(double *) &d0;

  z1 = *(double *) &d1;

  z2 = *(double *) &d2;

  z3 = *(double *) &d3;

  z0 -= alpha0;

  z1 -= alpha32;

  z2 -= alpha64;

  z3 -= alpha96;

  h0 += z0;

  h1 += z1;

  h3 += z2;

  h5 += z3;

if (l < 16) goto multiplyaddatmost15bytes;

multiplyaddatleast16bytes:;

  m2 = 2279;
  m20 = *(uchar *) (m + 8);
  y7 = h7 + alpha130;

  m2 <<= 51;
  m3 = 2343;
  m21 = *(uchar *) (m + 9);
  y6 = h6 + alpha130;

  m3 <<= 51;
  m0 = 2151;
  m22 = *(uchar *) (m + 10);
  y1 = h1 + alpha32;

  m0 <<= 51;
  m1 = 2215;
  m23 = *(uchar *) (m + 11);
  y0 = h0 + alpha32;

  m1 <<= 51;
  m30 = *(uchar *) (m + 12);
  y7 -= alpha130;

  m21 <<= 8;
  m2 += m20;
  m31 = *(uchar *) (m + 13);
  y6 -= alpha130;

  m22 <<= 16;
  m2 += m21;
  m32 = *(uchar *) (m + 14);
  y1 -= alpha32;

  m23 <<= 24;
  m2 += m22;
  m33 = *(uchar *) (m + 15);
  y0 -= alpha32;

  m2 += m23;
  m00 = *(uchar *) (m + 0);
  y5 = h5 + alpha96;

  m31 <<= 8;
  m3 += m30;
  m01 = *(uchar *) (m + 1);
  y4 = h4 + alpha96;

  m32 <<= 16;
  m02 = *(uchar *) (m + 2);
  x7 = h7 - y7;
  y7 *= scale;

  m33 += 256;
  m03 = *(uchar *) (m + 3);
  x6 = h6 - y6;
  y6 *= scale;

  m33 <<= 24;
  m3 += m31;
  m10 = *(uchar *) (m + 4);
  x1 = h1 - y1;

  m01 <<= 8;
  m3 += m32;
  m11 = *(uchar *) (m + 5);
  x0 = h0 - y0;

  m3 += m33;
  m0 += m00;
  m12 = *(uchar *) (m + 6);
  y5 -= alpha96;

  m02 <<= 16;
  m0 += m01;
  m13 = *(uchar *) (m + 7);
  y4 -= alpha96;

  m03 <<= 24;
  m0 += m02;
  d2 = m2;
  x1 += y7;

  m0 += m03;
  d3 = m3;
  x0 += y6;

  m11 <<= 8;
  m1 += m10;
  d0 = m0;
  x7 += y5;

  m12 <<= 16;
  m1 += m11;
  x6 += y4;

  m13 <<= 24;
  m1 += m12;
  y3 = h3 + alpha64;

  m1 += m13;
  d1 = m1;
  y2 = h2 + alpha64;

  x0 += x1;

  x6 += x7;

  y3 -= alpha64;
  r3low = r3low_stack;

  y2 -= alpha64;
  r0low = r0low_stack;

  x5 = h5 - y5;
  r3lowx0 = r3low * x0;
  r3high = r3high_stack;

  x4 = h4 - y4;
  r0lowx6 = r0low * x6;
  r0high = r0high_stack;

  x3 = h3 - y3;
  r3highx0 = r3high * x0;
  sr1low = sr1low_stack;

  x2 = h2 - y2;
  r0highx6 = r0high * x6;
  sr1high = sr1high_stack;

  x5 += y3;
  r0lowx0 = r0low * x0;
  r1low = r1low_stack;

  h6 = r3lowx0 + r0lowx6;
  sr1lowx6 = sr1low * x6;
  r1high = r1high_stack;

  x4 += y2;
  r0highx0 = r0high * x0;
  sr2low = sr2low_stack;

  h7 = r3highx0 + r0highx6;
  sr1highx6 = sr1high * x6;
  sr2high = sr2high_stack;

  x3 += y1;
  r1lowx0 = r1low * x0;
  r2low = r2low_stack;

  h0 = r0lowx0 + sr1lowx6;
  sr2lowx6 = sr2low * x6;
  r2high = r2high_stack;

  x2 += y0;
  r1highx0 = r1high * x0;
  sr3low = sr3low_stack;

  h1 = r0highx0 + sr1highx6;
  sr2highx6 = sr2high * x6;
  sr3high = sr3high_stack;

  x4 += x5;
  r2lowx0 = r2low * x0;
  z2 = *(double *) &d2;

  h2 = r1lowx0 + sr2lowx6;
  sr3lowx6 = sr3low * x6;

  x2 += x3;
  r2highx0 = r2high * x0;
  z3 = *(double *) &d3;

  h3 = r1highx0 + sr2highx6;
  sr3highx6 = sr3high * x6;

  r1highx4 = r1high * x4;
  z2 -= alpha64;

  h4 = r2lowx0 + sr3lowx6;
  r1lowx4 = r1low * x4;

  r0highx4 = r0high * x4;
  z3 -= alpha96;

  h5 = r2highx0 + sr3highx6;
  r0lowx4 = r0low * x4;

  h7 += r1highx4;
  sr3highx4 = sr3high * x4;

  h6 += r1lowx4;
  sr3lowx4 = sr3low * x4;

  h5 += r0highx4;
  sr2highx4 = sr2high * x4;

  h4 += r0lowx4;
  sr2lowx4 = sr2low * x4;

  h3 += sr3highx4;
  r0lowx2 = r0low * x2;

  h2 += sr3lowx4;
  r0highx2 = r0high * x2;

  h1 += sr2highx4;
  r1lowx2 = r1low * x2;

  h0 += sr2lowx4;
  r1highx2 = r1high * x2;

  h2 += r0lowx2;
  r2lowx2 = r2low * x2;

  h3 += r0highx2;
  r2highx2 = r2high * x2;

  h4 += r1lowx2;
  sr3lowx2 = sr3low * x2;

  h5 += r1highx2;
  sr3highx2 = sr3high * x2;
  alpha0 = *(double *) (constants + 24);

  m += 16;
  h6 += r2lowx2;

  l -= 16;
  h7 += r2highx2;

  z1 = *(double *) &d1;
  h0 += sr3lowx2;

  z0 = *(double *) &d0;
  h1 += sr3highx2;

  z1 -= alpha32;

  z0 -= alpha0;

  h5 += z3;

  h3 += z2;

  h1 += z1;

  h0 += z0;

if (l >= 16) goto multiplyaddatleast16bytes;

multiplyaddatmost15bytes:;

  y7 = h7 + alpha130;

  y6 = h6 + alpha130;

  y1 = h1 + alpha32;

  y0 = h0 + alpha32;

  y7 -= alpha130;

  y6 -= alpha130;

  y1 -= alpha32;

  y0 -= alpha32;

  y5 = h5 + alpha96;

  y4 = h4 + alpha96;

  x7 = h7 - y7;
  y7 *= scale;

  x6 = h6 - y6;
  y6 *= scale;

  x1 = h1 - y1;

  x0 = h0 - y0;

  y5 -= alpha96;

  y4 -= alpha96;

  x1 += y7;

  x0 += y6;

  x7 += y5;

  x6 += y4;

  y3 = h3 + alpha64;

  y2 = h2 + alpha64;

  x0 += x1;

  x6 += x7;

  y3 -= alpha64;
  r3low = r3low_stack;

  y2 -= alpha64;
  r0low = r0low_stack;

  x5 = h5 - y5;
  r3lowx0 = r3low * x0;
  r3high = r3high_stack;

  x4 = h4 - y4;
  r0lowx6 = r0low * x6;
  r0high = r0high_stack;

  x3 = h3 - y3;
  r3highx0 = r3high * x0;
  sr1low = sr1low_stack;

  x2 = h2 - y2;
  r0highx6 = r0high * x6;
  sr1high = sr1high_stack;

  x5 += y3;
  r0lowx0 = r0low * x0;
  r1low = r1low_stack;

  h6 = r3lowx0 + r0lowx6;
  sr1lowx6 = sr1low * x6;
  r1high = r1high_stack;

  x4 += y2;
  r0highx0 = r0high * x0;
  sr2low = sr2low_stack;

  h7 = r3highx0 + r0highx6;
  sr1highx6 = sr1high * x6;
  sr2high = sr2high_stack;

  x3 += y1;
  r1lowx0 = r1low * x0;
  r2low = r2low_stack;

  h0 = r0lowx0 + sr1lowx6;
  sr2lowx6 = sr2low * x6;
  r2high = r2high_stack;

  x2 += y0;
  r1highx0 = r1high * x0;
  sr3low = sr3low_stack;

  h1 = r0highx0 + sr1highx6;
  sr2highx6 = sr2high * x6;
  sr3high = sr3high_stack;

  x4 += x5;
  r2lowx0 = r2low * x0;

  h2 = r1lowx0 + sr2lowx6;
  sr3lowx6 = sr3low * x6;

  x2 += x3;
  r2highx0 = r2high * x0;

  h3 = r1highx0 + sr2highx6;
  sr3highx6 = sr3high * x6;

  r1highx4 = r1high * x4;

  h4 = r2lowx0 + sr3lowx6;
  r1lowx4 = r1low * x4;

  r0highx4 = r0high * x4;

  h5 = r2highx0 + sr3highx6;
  r0lowx4 = r0low * x4;

  h7 += r1highx4;
  sr3highx4 = sr3high * x4;

  h6 += r1lowx4;
  sr3lowx4 = sr3low * x4;

  h5 += r0highx4;
  sr2highx4 = sr2high * x4;

  h4 += r0lowx4;
  sr2lowx4 = sr2low * x4;

  h3 += sr3highx4;
  r0lowx2 = r0low * x2;

  h2 += sr3lowx4;
  r0highx2 = r0high * x2;

  h1 += sr2highx4;
  r1lowx2 = r1low * x2;

  h0 += sr2lowx4;
  r1highx2 = r1high * x2;

  h2 += r0lowx2;
  r2lowx2 = r2low * x2;

  h3 += r0highx2;
  r2highx2 = r2high * x2;

  h4 += r1lowx2;
  sr3lowx2 = sr3low * x2;

  h5 += r1highx2;
  sr3highx2 = sr3high * x2;

  h6 += r2lowx2;

  h7 += r2highx2;

  h0 += sr3lowx2;

  h1 += sr3highx2;

addatmost15bytes:;

if (l == 0) goto nomorebytes;

  lbelow2 = l - 2;

  lbelow3 = l - 3;

  lbelow2 >>= 31;
  lbelow4 = l - 4;

  m00 = *(uchar *) (m + 0);
  lbelow3 >>= 31;
  m += lbelow2;

  m01 = *(uchar *) (m + 1);
  lbelow4 >>= 31;
  m += lbelow3;

  m02 = *(uchar *) (m + 2);
  m += lbelow4;
  m0 = 2151;

  m03 = *(uchar *) (m + 3);
  m0 <<= 51;
  m1 = 2215;

  m0 += m00;
  m01 &= ~lbelow2;

  m02 &= ~lbelow3;
  m01 -= lbelow2;

  m01 <<= 8;
  m03 &= ~lbelow4;

  m0 += m01;
  lbelow2 -= lbelow3;

  m02 += lbelow2;
  lbelow3 -= lbelow4;

  m02 <<= 16;
  m03 += lbelow3;

  m03 <<= 24;
  m0 += m02;

  m0 += m03;
  lbelow5 = l - 5;

  lbelow6 = l - 6;
  lbelow7 = l - 7;

  lbelow5 >>= 31;
  lbelow8 = l - 8;

  lbelow6 >>= 31;
  m += lbelow5;

  m10 = *(uchar *) (m + 4);
  lbelow7 >>= 31;
  m += lbelow6;

  m11 = *(uchar *) (m + 5);
  lbelow8 >>= 31;
  m += lbelow7;

  m12 = *(uchar *) (m + 6);
  m1 <<= 51;
  m += lbelow8;

  m13 = *(uchar *) (m + 7);
  m10 &= ~lbelow5;
  lbelow4 -= lbelow5;

  m10 += lbelow4;
  lbelow5 -= lbelow6;

  m11 &= ~lbelow6;
  m11 += lbelow5;

  m11 <<= 8;
  m1 += m10;

  m1 += m11;
  m12 &= ~lbelow7;

  lbelow6 -= lbelow7;
  m13 &= ~lbelow8;

  m12 += lbelow6;
  lbelow7 -= lbelow8;

  m12 <<= 16;
  m13 += lbelow7;

  m13 <<= 24;
  m1 += m12;

  m1 += m13;
  m2 = 2279;

  lbelow9 = l - 9;
  m3 = 2343;

  lbelow10 = l - 10;
  lbelow11 = l - 11;

  lbelow9 >>= 31;
  lbelow12 = l - 12;

  lbelow10 >>= 31;
  m += lbelow9;

  m20 = *(uchar *) (m + 8);
  lbelow11 >>= 31;
  m += lbelow10;

  m21 = *(uchar *) (m + 9);
  lbelow12 >>= 31;
  m += lbelow11;

  m22 = *(uchar *) (m + 10);
  m2 <<= 51;
  m += lbelow12;

  m23 = *(uchar *) (m + 11);
  m20 &= ~lbelow9;
  lbelow8 -= lbelow9;

  m20 += lbelow8;
  lbelow9 -= lbelow10;

  m21 &= ~lbelow10;
  m21 += lbelow9;

  m21 <<= 8;
  m2 += m20;

  m2 += m21;
  m22 &= ~lbelow11;

  lbelow10 -= lbelow11;
  m23 &= ~lbelow12;

  m22 += lbelow10;
  lbelow11 -= lbelow12;

  m22 <<= 16;
  m23 += lbelow11;

  m23 <<= 24;
  m2 += m22;

  m3 <<= 51;
  lbelow13 = l - 13;

  lbelow13 >>= 31;
  lbelow14 = l - 14;

  lbelow14 >>= 31;
  m += lbelow13;
  lbelow15 = l - 15;

  m30 = *(uchar *) (m + 12);
  lbelow15 >>= 31;
  m += lbelow14;

  m31 = *(uchar *) (m + 13);
  m += lbelow15;
  m2 += m23;

  m32 = *(uchar *) (m + 14);
  m30 &= ~lbelow13;
  lbelow12 -= lbelow13;

  m30 += lbelow12;
  lbelow13 -= lbelow14;

  m3 += m30;
  m31 &= ~lbelow14;

  m31 += lbelow13;
  m32 &= ~lbelow15;

  m31 <<= 8;
  lbelow14 -= lbelow15;

  m3 += m31;
  m32 += lbelow14;
  d0 = m0;

  m32 <<= 16;
  m33 = lbelow15 + 1;
  d1 = m1;

  m33 <<= 24;
  m3 += m32;
  d2 = m2;

  m3 += m33;
  d3 = m3;

  alpha0 = *(double *) (constants + 24);

  z3 = *(double *) &d3;

  z2 = *(double *) &d2;

  z1 = *(double *) &d1;

  z0 = *(double *) &d0;

  z3 -= alpha96;

  z2 -= alpha64;

  z1 -= alpha32;

  z0 -= alpha0;

  h5 += z3;

  h3 += z2;

  h1 += z1;

  h0 += z0;

  y7 = h7 + alpha130;

  y6 = h6 + alpha130;

  y1 = h1 + alpha32;

  y0 = h0 + alpha32;

  y7 -= alpha130;

  y6 -= alpha130;

  y1 -= alpha32;

  y0 -= alpha32;

  y5 = h5 + alpha96;

  y4 = h4 + alpha96;

  x7 = h7 - y7;
  y7 *= scale;

  x6 = h6 - y6;
  y6 *= scale;

  x1 = h1 - y1;

  x0 = h0 - y0;

  y5 -= alpha96;

  y4 -= alpha96;

  x1 += y7;

  x0 += y6;

  x7 += y5;

  x6 += y4;

  y3 = h3 + alpha64;

  y2 = h2 + alpha64;

  x0 += x1;

  x6 += x7;

  y3 -= alpha64;
  r3low = r3low_stack;

  y2 -= alpha64;
  r0low = r0low_stack;

  x5 = h5 - y5;
  r3lowx0 = r3low * x0;
  r3high = r3high_stack;

  x4 = h4 - y4;
  r0lowx6 = r0low * x6;
  r0high = r0high_stack;

  x3 = h3 - y3;
  r3highx0 = r3high * x0;
  sr1low = sr1low_stack;

  x2 = h2 - y2;
  r0highx6 = r0high * x6;
  sr1high = sr1high_stack;

  x5 += y3;
  r0lowx0 = r0low * x0;
  r1low = r1low_stack;

  h6 = r3lowx0 + r0lowx6;
  sr1lowx6 = sr1low * x6;
  r1high = r1high_stack;

  x4 += y2;
  r0highx0 = r0high * x0;
  sr2low = sr2low_stack;

  h7 = r3highx0 + r0highx6;
  sr1highx6 = sr1high * x6;
  sr2high = sr2high_stack;

  x3 += y1;
  r1lowx0 = r1low * x0;
  r2low = r2low_stack;

  h0 = r0lowx0 + sr1lowx6;
  sr2lowx6 = sr2low * x6;
  r2high = r2high_stack;

  x2 += y0;
  r1highx0 = r1high * x0;
  sr3low = sr3low_stack;

  h1 = r0highx0 + sr1highx6;
  sr2highx6 = sr2high * x6;
  sr3high = sr3high_stack;

  x4 += x5;
  r2lowx0 = r2low * x0;

  h2 = r1lowx0 + sr2lowx6;
  sr3lowx6 = sr3low * x6;

  x2 += x3;
  r2highx0 = r2high * x0;

  h3 = r1highx0 + sr2highx6;
  sr3highx6 = sr3high * x6;

  r1highx4 = r1high * x4;

  h4 = r2lowx0 + sr3lowx6;
  r1lowx4 = r1low * x4;

  r0highx4 = r0high * x4;

  h5 = r2highx0 + sr3highx6;
  r0lowx4 = r0low * x4;

  h7 += r1highx4;
  sr3highx4 = sr3high * x4;

  h6 += r1lowx4;
  sr3lowx4 = sr3low * x4;

  h5 += r0highx4;
  sr2highx4 = sr2high * x4;

  h4 += r0lowx4;
  sr2lowx4 = sr2low * x4;

  h3 += sr3highx4;
  r0lowx2 = r0low * x2;

  h2 += sr3lowx4;
  r0highx2 = r0high * x2;

  h1 += sr2highx4;
  r1lowx2 = r1low * x2;

  h0 += sr2lowx4;
  r1highx2 = r1high * x2;

  h2 += r0lowx2;
  r2lowx2 = r2low * x2;

  h3 += r0highx2;
  r2highx2 = r2high * x2;

  h4 += r1lowx2;
  sr3lowx2 = sr3low * x2;

  h5 += r1highx2;
  sr3highx2 = sr3high * x2;

  h6 += r2lowx2;

  h7 += r2highx2;

  h0 += sr3lowx2;

  h1 += sr3highx2;


nomorebytes:;

  offset0 = *(double *) (constants + 104);
  y7 = h7 + alpha130;

  offset1 = *(double *) (constants + 112);
  y0 = h0 + alpha32;

  offset2 = *(double *) (constants + 120);
  y1 = h1 + alpha32;

  offset3 = *(double *) (constants + 128);
  y2 = h2 + alpha64;

  y7 -= alpha130;

  y3 = h3 + alpha64;

  y4 = h4 + alpha96;

  y5 = h5 + alpha96;

  x7 = h7 - y7;
  y7 *= scale;

  y0 -= alpha32;

  y1 -= alpha32;

  y2 -= alpha64;

  h6 += x7;

  y3 -= alpha64;

  y4 -= alpha96;

  y5 -= alpha96;

  y6 = h6 + alpha130;

  x0 = h0 - y0;

  x1 = h1 - y1;

  x2 = h2 - y2;

  y6 -= alpha130;

  x0 += y7;

  x3 = h3 - y3;

  x4 = h4 - y4;

  x5 = h5 - y5;

  x6 = h6 - y6;

  y6 *= scale;

  x2 += y0;

  x3 += y1;

  x4 += y2;

  x0 += y6;

  x5 += y3;

  x6 += y4;

  x2 += x3;

  x0 += x1;

  x4 += x5;

  x6 += y5;

  x2 += offset1;
  *(double *) &d1 = x2;

  x0 += offset0;
  *(double *) &d0 = x0;

  x4 += offset2;
  *(double *) &d2 = x4;

  x6 += offset3;
  *(double *) &d3 = x6;




  f0 = d0;

  f1 = d1;
  bits32 = -1;

  f2 = d2;
  bits32 >>= 32;

  f3 = d3;
  f = f0 >> 32;

  f0 &= bits32;
  f &= 255;

  f1 += f;
  g0 = f0 + 5;

  g = g0 >> 32;
  g0 &= bits32;

  f = f1 >> 32;
  f1 &= bits32;

  f &= 255;
  g1 = f1 + g;

  g = g1 >> 32;
  f2 += f;

  f = f2 >> 32;
  g1 &= bits32;

  f2 &= bits32;
  f &= 255;

  f3 += f;
  g2 = f2 + g;

  g = g2 >> 32;
  g2 &= bits32;

  f4 = f3 >> 32;
  f3 &= bits32;

  f4 &= 255;
  g3 = f3 + g;

  g = g3 >> 32;
  g3 &= bits32;

  g4 = f4 + g;

  g4 = g4 - 4;
  s00 = *(uchar *) (s + 0);

  f = (int64) g4 >> 63;
  s01 = *(uchar *) (s + 1);

  f0 &= f;
  g0 &= ~f;
  s02 = *(uchar *) (s + 2);

  f1 &= f;
  f0 |= g0;
  s03 = *(uchar *) (s + 3);

  g1 &= ~f;
  f2 &= f;
  s10 = *(uchar *) (s + 4);

  f3 &= f;
  g2 &= ~f;
  s11 = *(uchar *) (s + 5);

  g3 &= ~f;
  f1 |= g1;
  s12 = *(uchar *) (s + 6);

  f2 |= g2;
  f3 |= g3;
  s13 = *(uchar *) (s + 7);

  s01 <<= 8;
  f0 += s00;
  s20 = *(uchar *) (s + 8);

  s02 <<= 16;
  f0 += s01;
  s21 = *(uchar *) (s + 9);

  s03 <<= 24;
  f0 += s02;
  s22 = *(uchar *) (s + 10);

  s11 <<= 8;
  f1 += s10;
  s23 = *(uchar *) (s + 11);

  s12 <<= 16;
  f1 += s11;
  s30 = *(uchar *) (s + 12);

  s13 <<= 24;
  f1 += s12;
  s31 = *(uchar *) (s + 13);

  f0 += s03;
  f1 += s13;
  s32 = *(uchar *) (s + 14);

  s21 <<= 8;
  f2 += s20;
  s33 = *(uchar *) (s + 15);

  s22 <<= 16;
  f2 += s21;

  s23 <<= 24;
  f2 += s22;

  s31 <<= 8;
  f3 += s30;

  s32 <<= 16;
  f3 += s31;

  s33 <<= 24;
  f3 += s32;

  f2 += s23;
  f3 += s33;

  *(uchar *) (out + 0) = f0;
  f0 >>= 8;
  *(uchar *) (out + 1) = f0;
  f0 >>= 8;
  *(uchar *) (out + 2) = f0;
  f0 >>= 8;
  *(uchar *) (out + 3) = f0;
  f0 >>= 8;
  f1 += f0;

  *(uchar *) (out + 4) = f1;
  f1 >>= 8;
  *(uchar *) (out + 5) = f1;
  f1 >>= 8;
  *(uchar *) (out + 6) = f1;
  f1 >>= 8;
  *(uchar *) (out + 7) = f1;
  f1 >>= 8;
  f2 += f1;

  *(uchar *) (out + 8) = f2;
  f2 >>= 8;
  *(uchar *) (out + 9) = f2;
  f2 >>= 8;
  *(uchar *) (out + 10) = f2;
  f2 >>= 8;
  *(uchar *) (out + 11) = f2;
  f2 >>= 8;
  f3 += f2;

  *(uchar *) (out + 12) = f3;
  f3 >>= 8;
  *(uchar *) (out + 13) = f3;
  f3 >>= 8;
  *(uchar *) (out + 14) = f3;
  f3 >>= 8;
  *(uchar *) (out + 15) = f3;

  return 0;
}

int crypto_verify_16(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

int crypto_onetimeauth_poly1305_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[16];
  crypto_onetimeauth_poly1305(correct,in,inlen,k);
  return crypto_verify_16(h,correct);
}

int crypto_verify_32(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  F(16)
  F(17)
  F(18)
  F(19)
  F(20)
  F(21)
  F(22)
  F(23)
  F(24)
  F(25)
  F(26)
  F(27)
  F(28)
  F(29)
  F(30)
  F(31)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}










static const unsigned char n[16] = {0};

int crypto_box_beforenm(
  unsigned char *k,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char s[32];
  crypto_scalarmult_curve25519(s,sk,pk);
  return crypto_core_hsalsa20(k,n,s,sigma);
}

int crypto_box_afternm(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return crypto_secretbox_xsalsa20poly1305(c,m,mlen,n,k);
}

int crypto_box_open_afternm(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return crypto_secretbox_xsalsa20poly1305_open(m,c,clen,n,k);
}

int crypto_box(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_BEFORENMBYTES];
  crypto_box_beforenm(k,pk,sk);
  return crypto_box_afternm(c,m,mlen,n,k);
}

int crypto_box_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_BEFORENMBYTES];
  crypto_box_beforenm(k,pk,sk);
  return crypto_box_open_afternm(m,c,clen,n,k);
}

int crypto_box_keypair(
  unsigned char *pk,
  unsigned char *sk
)
{
  //randombytes(sk,32);
  return crypto_scalarmult_curve25519_base(pk,sk);
}


int crypto_secretbox(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  int i;
  if (mlen < 32) return -1;
  crypto_stream_xsalsa20_xor(c,m,mlen,n,k);
  crypto_onetimeauth_poly1305(c + 16,c + 32,mlen - 32,c);
  for (i = 0;i < 16;++i) c[i] = 0;
  return 0;
}

int crypto_secretbox_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  int i;
  unsigned char subkey[32];
  if (clen < 32) return -1;
  crypto_stream_xsalsa20(subkey,32,n,k);
  if (crypto_onetimeauth_poly1305_verify(c + 16,c + 32,clen - 32,subkey) != 0) return -1;
  crypto_stream_xsalsa20_xor(m,c,clen,n,k);
  for (i = 0;i < 32;++i) m[i] = 0;
  return 0;
}


// sha256
typedef unsigned int uint32;

static uint32 load_bigendian32(const unsigned char *x)
{
  return
      (uint32) (x[3]) \
  | (((uint32) (x[2])) << 8) \
  | (((uint32) (x[1])) << 16) \
  | (((uint32) (x[0])) << 24)
  ;
}

static void store_bigendian32(unsigned char *x,uint32 u)
{
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}


#undef SHR
#undef ROTR
#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef M
#undef EXPAND
#undef F
#undef G


#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define M(w0,w14,w9,w1) w0 += sigma1(w14) + w9 + sigma0(w1);

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(r0,r1,r2,r3,r4,r5,r6,r7,w,k) \
  r7 += Sigma1(r4) + Ch(r4,r5,r6) + k + w; \
  r3 += r7; \
  r7 += Sigma0(r0) + Maj(r0,r1,r2);

#define G(r0,r1,r2,r3,r4,r5,r6,r7,i) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w0 ,round32[i + 0]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w1 ,round32[i + 1]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w2 ,round32[i + 2]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w3 ,round32[i + 3]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w4 ,round32[i + 4]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w5 ,round32[i + 5]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w6 ,round32[i + 6]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w7 ,round32[i + 7]) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w8 ,round32[i + 8]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w9 ,round32[i + 9]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w10,round32[i + 10]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w11,round32[i + 11]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w12,round32[i + 12]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w13,round32[i + 13]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w14,round32[i + 14]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w15,round32[i + 15])

static const uint32 round32[64] = {
  0x428a2f98
, 0x71374491
, 0xb5c0fbcf
, 0xe9b5dba5
, 0x3956c25b
, 0x59f111f1
, 0x923f82a4
, 0xab1c5ed5
, 0xd807aa98
, 0x12835b01
, 0x243185be
, 0x550c7dc3
, 0x72be5d74
, 0x80deb1fe
, 0x9bdc06a7
, 0xc19bf174
, 0xe49b69c1
, 0xefbe4786
, 0x0fc19dc6
, 0x240ca1cc
, 0x2de92c6f
, 0x4a7484aa
, 0x5cb0a9dc
, 0x76f988da
, 0x983e5152
, 0xa831c66d
, 0xb00327c8
, 0xbf597fc7
, 0xc6e00bf3
, 0xd5a79147
, 0x06ca6351
, 0x14292967
, 0x27b70a85
, 0x2e1b2138
, 0x4d2c6dfc
, 0x53380d13
, 0x650a7354
, 0x766a0abb
, 0x81c2c92e
, 0x92722c85
, 0xa2bfe8a1
, 0xa81a664b
, 0xc24b8b70
, 0xc76c51a3
, 0xd192e819
, 0xd6990624
, 0xf40e3585
, 0x106aa070
, 0x19a4c116
, 0x1e376c08
, 0x2748774c
, 0x34b0bcb5
, 0x391c0cb3
, 0x4ed8aa4a
, 0x5b9cca4f
, 0x682e6ff3
, 0x748f82ee
, 0x78a5636f
, 0x84c87814
, 0x8cc70208
, 0x90befffa
, 0xa4506ceb
, 0xbef9a3f7
, 0xc67178f2
} ;

int crypto_hashblocks_sha256(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  uint32 state[8];
  uint32 r0;
  uint32 r1;
  uint32 r2;
  uint32 r3;
  uint32 r4;
  uint32 r5;
  uint32 r6;
  uint32 r7;

  r0 = load_bigendian32(statebytes +  0); state[0] = r0;
  r1 = load_bigendian32(statebytes +  4); state[1] = r1;
  r2 = load_bigendian32(statebytes +  8); state[2] = r2;
  r3 = load_bigendian32(statebytes + 12); state[3] = r3;
  r4 = load_bigendian32(statebytes + 16); state[4] = r4;
  r5 = load_bigendian32(statebytes + 20); state[5] = r5;
  r6 = load_bigendian32(statebytes + 24); state[6] = r6;
  r7 = load_bigendian32(statebytes + 28); state[7] = r7;

  while (inlen >= 64) {
    uint32 w0  = load_bigendian32(in +  0);
    uint32 w1  = load_bigendian32(in +  4);
    uint32 w2  = load_bigendian32(in +  8);
    uint32 w3  = load_bigendian32(in + 12);
    uint32 w4  = load_bigendian32(in + 16);
    uint32 w5  = load_bigendian32(in + 20);
    uint32 w6  = load_bigendian32(in + 24);
    uint32 w7  = load_bigendian32(in + 28);
    uint32 w8  = load_bigendian32(in + 32);
    uint32 w9  = load_bigendian32(in + 36);
    uint32 w10 = load_bigendian32(in + 40);
    uint32 w11 = load_bigendian32(in + 44);
    uint32 w12 = load_bigendian32(in + 48);
    uint32 w13 = load_bigendian32(in + 52);
    uint32 w14 = load_bigendian32(in + 56);
    uint32 w15 = load_bigendian32(in + 60);

    G(r0,r1,r2,r3,r4,r5,r6,r7,0)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,16)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,32)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,48)

    r0 += state[0];
    r1 += state[1];
    r2 += state[2];
    r3 += state[3];
    r4 += state[4];
    r5 += state[5];
    r6 += state[6];
    r7 += state[7];
  
    state[0] = r0;
    state[1] = r1;
    state[2] = r2;
    state[3] = r3;
    state[4] = r4;
    state[5] = r5;
    state[6] = r6;
    state[7] = r7;

    in += 64;
    inlen -= 64;
  }

  store_bigendian32(statebytes +  0,state[0]);
  store_bigendian32(statebytes +  4,state[1]);
  store_bigendian32(statebytes +  8,state[2]);
  store_bigendian32(statebytes + 12,state[3]);
  store_bigendian32(statebytes + 16,state[4]);
  store_bigendian32(statebytes + 20,state[5]);
  store_bigendian32(statebytes + 24,state[6]);
  store_bigendian32(statebytes + 28,state[7]);

  return 0;
}


#undef SHR
#undef ROTR
#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef M
#undef EXPAND
#undef F
#undef G

// sha512
typedef unsigned long long uint64;

static uint64 load_bigendian(const unsigned char *x)
{
  return
      (uint64) (x[7]) \
  | (((uint64) (x[6])) << 8) \
  | (((uint64) (x[5])) << 16) \
  | (((uint64) (x[4])) << 24) \
  | (((uint64) (x[3])) << 32) \
  | (((uint64) (x[2])) << 40) \
  | (((uint64) (x[1])) << 48) \
  | (((uint64) (x[0])) << 56)
  ;
}

static void store_bigendian(unsigned char *x,uint64 u)
{
  x[7] = u; u >>= 8;
  x[6] = u; u >>= 8;
  x[5] = u; u >>= 8;
  x[4] = u; u >>= 8;
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x,7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(r0,r1,r2,r3,r4,r5,r6,r7,w,k) \
  r7 += Sigma1(r4) + Ch(r4,r5,r6) + k + w; \
  r3 += r7; \
  r7 += Sigma0(r0) + Maj(r0,r1,r2);

#define G(r0,r1,r2,r3,r4,r5,r6,r7,i) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w0 ,round[i + 0]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w1 ,round[i + 1]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w2 ,round[i + 2]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w3 ,round[i + 3]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w4 ,round[i + 4]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w5 ,round[i + 5]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w6 ,round[i + 6]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w7 ,round[i + 7]) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w8 ,round[i + 8]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w9 ,round[i + 9]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w10,round[i + 10]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w11,round[i + 11]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w12,round[i + 12]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w13,round[i + 13]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w14,round[i + 14]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w15,round[i + 15])

static const uint64 round[80] = {
  0x428a2f98d728ae22ULL
, 0x7137449123ef65cdULL
, 0xb5c0fbcfec4d3b2fULL
, 0xe9b5dba58189dbbcULL
, 0x3956c25bf348b538ULL
, 0x59f111f1b605d019ULL
, 0x923f82a4af194f9bULL
, 0xab1c5ed5da6d8118ULL
, 0xd807aa98a3030242ULL
, 0x12835b0145706fbeULL
, 0x243185be4ee4b28cULL
, 0x550c7dc3d5ffb4e2ULL
, 0x72be5d74f27b896fULL
, 0x80deb1fe3b1696b1ULL
, 0x9bdc06a725c71235ULL
, 0xc19bf174cf692694ULL
, 0xe49b69c19ef14ad2ULL
, 0xefbe4786384f25e3ULL
, 0x0fc19dc68b8cd5b5ULL
, 0x240ca1cc77ac9c65ULL
, 0x2de92c6f592b0275ULL
, 0x4a7484aa6ea6e483ULL
, 0x5cb0a9dcbd41fbd4ULL
, 0x76f988da831153b5ULL
, 0x983e5152ee66dfabULL
, 0xa831c66d2db43210ULL
, 0xb00327c898fb213fULL
, 0xbf597fc7beef0ee4ULL
, 0xc6e00bf33da88fc2ULL
, 0xd5a79147930aa725ULL
, 0x06ca6351e003826fULL
, 0x142929670a0e6e70ULL
, 0x27b70a8546d22ffcULL
, 0x2e1b21385c26c926ULL
, 0x4d2c6dfc5ac42aedULL
, 0x53380d139d95b3dfULL
, 0x650a73548baf63deULL
, 0x766a0abb3c77b2a8ULL
, 0x81c2c92e47edaee6ULL
, 0x92722c851482353bULL
, 0xa2bfe8a14cf10364ULL
, 0xa81a664bbc423001ULL
, 0xc24b8b70d0f89791ULL
, 0xc76c51a30654be30ULL
, 0xd192e819d6ef5218ULL
, 0xd69906245565a910ULL
, 0xf40e35855771202aULL
, 0x106aa07032bbd1b8ULL
, 0x19a4c116b8d2d0c8ULL
, 0x1e376c085141ab53ULL
, 0x2748774cdf8eeb99ULL
, 0x34b0bcb5e19b48a8ULL
, 0x391c0cb3c5c95a63ULL
, 0x4ed8aa4ae3418acbULL
, 0x5b9cca4f7763e373ULL
, 0x682e6ff3d6b2b8a3ULL
, 0x748f82ee5defb2fcULL
, 0x78a5636f43172f60ULL
, 0x84c87814a1f0ab72ULL
, 0x8cc702081a6439ecULL
, 0x90befffa23631e28ULL
, 0xa4506cebde82bde9ULL
, 0xbef9a3f7b2c67915ULL
, 0xc67178f2e372532bULL
, 0xca273eceea26619cULL
, 0xd186b8c721c0c207ULL
, 0xeada7dd6cde0eb1eULL
, 0xf57d4f7fee6ed178ULL
, 0x06f067aa72176fbaULL
, 0x0a637dc5a2c898a6ULL
, 0x113f9804bef90daeULL
, 0x1b710b35131c471bULL
, 0x28db77f523047d84ULL
, 0x32caab7b40c72493ULL
, 0x3c9ebe0a15c9bebcULL
, 0x431d67c49c100d4cULL
, 0x4cc5d4becb3e42b6ULL
, 0x597f299cfc657e2aULL
, 0x5fcb6fab3ad6faecULL
, 0x6c44198c4a475817ULL
};

int crypto_hashblocks_sha512(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  uint64 state[8];
  uint64 r0;
  uint64 r1;
  uint64 r2;
  uint64 r3;
  uint64 r4;
  uint64 r5;
  uint64 r6;
  uint64 r7;

  r0 = load_bigendian(statebytes +  0); state[0] = r0;
  r1 = load_bigendian(statebytes +  8); state[1] = r1;
  r2 = load_bigendian(statebytes + 16); state[2] = r2;
  r3 = load_bigendian(statebytes + 24); state[3] = r3;
  r4 = load_bigendian(statebytes + 32); state[4] = r4;
  r5 = load_bigendian(statebytes + 40); state[5] = r5;
  r6 = load_bigendian(statebytes + 48); state[6] = r6;
  r7 = load_bigendian(statebytes + 56); state[7] = r7;

  while (inlen >= 128) {
    uint64 w0  = load_bigendian(in +   0);
    uint64 w1  = load_bigendian(in +   8);
    uint64 w2  = load_bigendian(in +  16);
    uint64 w3  = load_bigendian(in +  24);
    uint64 w4  = load_bigendian(in +  32);
    uint64 w5  = load_bigendian(in +  40);
    uint64 w6  = load_bigendian(in +  48);
    uint64 w7  = load_bigendian(in +  56);
    uint64 w8  = load_bigendian(in +  64);
    uint64 w9  = load_bigendian(in +  72);
    uint64 w10 = load_bigendian(in +  80);
    uint64 w11 = load_bigendian(in +  88);
    uint64 w12 = load_bigendian(in +  96);
    uint64 w13 = load_bigendian(in + 104);
    uint64 w14 = load_bigendian(in + 112);
    uint64 w15 = load_bigendian(in + 120);

    G(r0,r1,r2,r3,r4,r5,r6,r7,0)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,16)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,32)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,48)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,64)

    r0 += state[0];
    r1 += state[1];
    r2 += state[2];
    r3 += state[3];
    r4 += state[4];
    r5 += state[5];
    r6 += state[6];
    r7 += state[7];
  
    state[0] = r0;
    state[1] = r1;
    state[2] = r2;
    state[3] = r3;
    state[4] = r4;
    state[5] = r5;
    state[6] = r6;
    state[7] = r7;

    in += 128;
    inlen -= 128;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  8,state[1]);
  store_bigendian(statebytes + 16,state[2]);
  store_bigendian(statebytes + 24,state[3]);
  store_bigendian(statebytes + 32,state[4]);
  store_bigendian(statebytes + 40,state[5]);
  store_bigendian(statebytes + 48,state[6]);
  store_bigendian(statebytes + 56,state[7]);

  return 0;
}

/*
20080913
D. J. Bernstein
Public domain.
*/

static const unsigned char iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

typedef unsigned long long uint64;

int crypto_hash_sha512(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char h[64];
  unsigned char padded[256];
  int i;
  unsigned long long bytes = inlen;

  for (i = 0;i < 64;++i) h[i] = iv[i];

  crypto_hashblocks_sha512(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    crypto_hashblocks_sha512(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    crypto_hashblocks_sha512(h,padded,256);
  }

  for (i = 0;i < 64;++i) out[i] = h[i];

  return 0;
}



#define fe25519 crypto_sign_edwards25519sha512batch_fe25519
#define fe25519_unpack crypto_sign_edwards25519sha512batch_fe25519_unpack
#define fe25519_pack crypto_sign_edwards25519sha512batch_fe25519_pack
#define fe25519_cmov crypto_sign_edwards25519sha512batch_fe25519_cmov
#define fe25519_setone crypto_sign_edwards25519sha512batch_fe25519_setone
#define fe25519_setzero crypto_sign_edwards25519sha512batch_fe25519_setzero
#define fe25519_neg crypto_sign_edwards25519sha512batch_fe25519_neg
#define fe25519_getparity crypto_sign_edwards25519sha512batch_fe25519_getparity
#define fe25519_add crypto_sign_edwards25519sha512batch_fe25519_add
#define fe25519_sub crypto_sign_edwards25519sha512batch_fe25519_sub
#define fe25519_mul crypto_sign_edwards25519sha512batch_fe25519_mul
#define fe25519_square crypto_sign_edwards25519sha512batch_fe25519_square
#define fe25519_pow crypto_sign_edwards25519sha512batch_fe25519_pow
#define fe25519_sqrt_vartime crypto_sign_edwards25519sha512batch_fe25519_sqrt_vartime
#define fe25519_invert crypto_sign_edwards25519sha512batch_fe25519_invert

typedef struct {
  crypto_uint32 v[32]; 
} fe25519;

void fe25519_unpack(fe25519 *r, const unsigned char x[32]);
void fe25519_pack(unsigned char r[32], const fe25519 *x);
void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b);
void fe25519_setone(fe25519 *r);
void fe25519_setzero(fe25519 *r);
void fe25519_neg(fe25519 *r, const fe25519 *x);
unsigned char fe25519_getparity(const fe25519 *x);
void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y);
void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y);
void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y);
void fe25519_square(fe25519 *r, const fe25519 *x);
void fe25519_pow(fe25519 *r, const fe25519 *x, const unsigned char *e);
int fe25519_sqrt_vartime(fe25519 *r, const fe25519 *x, unsigned char parity);
void fe25519_invert(fe25519 *r, const fe25519 *x);



#define sc25519 crypto_sign_edwards25519sha512batch_sc25519
#define sc25519_from32bytes crypto_sign_edwards25519sha512batch_sc25519_from32bytes
#define sc25519_from64bytes crypto_sign_edwards25519sha512batch_sc25519_from64bytes
#define sc25519_to32bytes crypto_sign_edwards25519sha512batch_sc25519_to32bytes
#define sc25519_pack crypto_sign_edwards25519sha512batch_sc25519_pack
#define sc25519_getparity crypto_sign_edwards25519sha512batch_sc25519_getparity
#define sc25519_setone crypto_sign_edwards25519sha512batch_sc25519_setone
#define sc25519_setzero crypto_sign_edwards25519sha512batch_sc25519_setzero
#define sc25519_neg crypto_sign_edwards25519sha512batch_sc25519_neg
#define sc25519_add crypto_sign_edwards25519sha512batch_sc25519_add
#define sc25519_sub crypto_sign_edwards25519sha512batch_sc25519_sub
#define sc25519_mul crypto_sign_edwards25519sha512batch_sc25519_mul
#define sc25519_square crypto_sign_edwards25519sha512batch_sc25519_square
#define sc25519_invert crypto_sign_edwards25519sha512batch_sc25519_invert


#define WINDOWSIZE 4 /* Should be 1,2, or 4 */
#define WINDOWMASK ((1<<WINDOWSIZE)-1)

static void reduce_add_sub(fe25519 *r)
{
  crypto_uint32 t;
  int i,rep;

  for(rep=0;rep<4;rep++)
  {
    t = r->v[31] >> 7;
    r->v[31] &= 127;
    t *= 19;
    r->v[0] += t;
    for(i=0;i<31;i++)
    {
      t = r->v[i] >> 8;
      r->v[i+1] += t;
      r->v[i] &= 255;
    }
  }
}

static void reduce_mul(fe25519 *r)
{
  crypto_uint32 t;
  int i,rep;

  for(rep=0;rep<2;rep++)
  {
    t = r->v[31] >> 7;
    r->v[31] &= 127;
    t *= 19;
    r->v[0] += t;
    for(i=0;i<31;i++)
    {
      t = r->v[i] >> 8;
      r->v[i+1] += t;
      r->v[i] &= 255;
    }
  }
}

/* reduction modulo 2^255-19 */
static void freeze_fe(fe25519 *r) 
{
  int i;
  unsigned int m = (r->v[31] == 127);
  for(i=30;i>1;i--)
    m *= (r->v[i] == 255);
  m *= (r->v[0] >= 237);

  r->v[31] -= m*127;
  for(i=30;i>0;i--)
    r->v[i] -= m*255;
  r->v[0] -= m*237;
}

/*freeze input before calling isone*/
static int isone(const fe25519 *x)
{
  int i;
  int r = (x->v[0] == 1);
  for(i=1;i<32;i++) 
    r *= (x->v[i] == 0);
  return r;
}

/*freeze input before calling iszero*/
static int iszero(const fe25519 *x)
{
  int i;
  int r = (x->v[0] == 0);
  for(i=1;i<32;i++) 
    r *= (x->v[i] == 0);
  return r;
}


static int issquare(const fe25519 *x)
{
  unsigned char e[32] = {0xf6,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f}; /* (p-1)/2 */
  fe25519 t;

  fe25519_pow(&t,x,e);
  freeze_fe(&t);
  return isone(&t) || iszero(&t);
}

void fe25519_unpack(fe25519 *r, const unsigned char x[32])
{
  int i;
  for(i=0;i<32;i++) r->v[i] = x[i];
  r->v[31] &= 127;
}

/* Assumes input x being reduced mod 2^255 */
void fe25519_pack(unsigned char r[32], const fe25519 *x)
{
  int i;
  for(i=0;i<32;i++) 
    r[i] = x->v[i];
  
  /* freeze byte array */
  unsigned int m = (r[31] == 127); /* XXX: some compilers might use branches; fix */
  for(i=30;i>1;i--)
    m *= (r[i] == 255);
  m *= (r[0] >= 237);
  r[31] -= m*127;
  for(i=30;i>0;i--)
    r[i] -= m*255;
  r[0] -= m*237;
}

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  unsigned char nb = 1-b;
  int i;
  for(i=0;i<32;i++) r->v[i] = nb * r->v[i] + b * x->v[i];
}

unsigned char fe25519_getparity(const fe25519 *x)
{
  fe25519 t;
  int i;
  for(i=0;i<32;i++) t.v[i] = x->v[i];
  freeze_fe(&t);
  return t.v[0] & 1;
}

void fe25519_setone(fe25519 *r)
{
  int i;
  r->v[0] = 1;
  for(i=1;i<32;i++) r->v[i]=0;
}

void fe25519_setzero(fe25519 *r)
{
  int i;
  for(i=0;i<32;i++) r->v[i]=0;
}

void fe25519_neg(fe25519 *r, const fe25519 *x)
{
  fe25519 t;
  int i;
  for(i=0;i<32;i++) t.v[i]=x->v[i];
  fe25519_setzero(r);
  fe25519_sub(r, r, &t);
}

void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  int i;
  for(i=0;i<32;i++) r->v[i] = x->v[i] + y->v[i];
  reduce_add_sub(r);
}

void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  int i;
  crypto_uint32 t[32];
  t[0] = x->v[0] + 0x1da;
  t[31] = x->v[31] + 0xfe;
  for(i=1;i<31;i++) t[i] = x->v[i] + 0x1fe;
  for(i=0;i<32;i++) r->v[i] = t[i] - y->v[i];
  reduce_add_sub(r);
}

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  int i,j;
  crypto_uint32 t[63];
  for(i=0;i<63;i++)t[i] = 0;

  for(i=0;i<32;i++)
    for(j=0;j<32;j++)
      t[i+j] += x->v[i] * y->v[j];

  for(i=32;i<63;i++)
    r->v[i-32] = t[i-32] + 38*t[i]; 
  r->v[31] = t[31]; /* result now in r[0]...r[31] */

  reduce_mul(r);
}

void fe25519_square(fe25519 *r, const fe25519 *x)
{
  fe25519_mul(r, x, x);
}

/*XXX: Make constant time! */
void fe25519_pow(fe25519 *r, const fe25519 *x, const unsigned char *e)
{
  /*
  fe25519 g;
  fe25519_setone(&g);
  int i;
  unsigned char j;
  for(i=32;i>0;i--)
  {
    for(j=128;j>0;j>>=1)
    {
      fe25519_square(&g,&g);
      if(e[i-1] & j) 
        fe25519_mul(&g,&g,x);
    }
  }
  for(i=0;i<32;i++) r->v[i] = g.v[i];
  */
  fe25519 g;
  fe25519_setone(&g);
  int i,j,k;
  fe25519 pre[(1 << WINDOWSIZE)];
  fe25519 t;
  unsigned char w;

  // Precomputation
  fe25519_setone(pre);
  pre[1] = *x;
  for(i=2;i<(1<<WINDOWSIZE);i+=2)
  {
    fe25519_square(pre+i, pre+i/2);
    fe25519_mul(pre+i+1, pre+i, pre+1);
  }

  // Fixed-window scalar multiplication
  for(i=32;i>0;i--)
  {
    for(j=8-WINDOWSIZE;j>=0;j-=WINDOWSIZE)
    {
      for(k=0;k<WINDOWSIZE;k++)
        fe25519_square(&g, &g);
      // Cache-timing resistant loading of precomputed value:
      w = (e[i-1]>>j) & WINDOWMASK;
      t = pre[0];
      for(k=1;k<(1<<WINDOWSIZE);k++)
        fe25519_cmov(&t, &pre[k], k==w);
      fe25519_mul(&g, &g, &t);
    }
  }
  *r = g;
}

/* Return 0 on success, 1 otherwise */
int fe25519_sqrt_vartime(fe25519 *r, const fe25519 *x, unsigned char parity)
{
  /* See HAC, Alg. 3.37 */
  if (!issquare(x)) return -1;
  unsigned char e[32] = {0xfb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x1f}; /* (p-1)/4 */
  unsigned char e2[32] = {0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f}; /* (p+3)/8 */
  unsigned char e3[32] = {0xfd,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f}; /* (p-5)/8 */
  fe25519 p = {{0}};
  fe25519 d;
  int i;
  fe25519_pow(&d,x,e);
  freeze_fe(&d);
  if(isone(&d))
    fe25519_pow(r,x,e2);
  else
  {
    for(i=0;i<32;i++)
      d.v[i] = 4*x->v[i];
    fe25519_pow(&d,&d,e3);
    for(i=0;i<32;i++)
      r->v[i] = 2*x->v[i];
    fe25519_mul(r,r,&d);
  }
  freeze_fe(r);
  if((r->v[0] & 1) != (parity & 1))
  {
    fe25519_sub(r,&p,r);
  }
  return 0;
}

void fe25519_invert(fe25519 *r, const fe25519 *x)
{
	fe25519 z2;
	fe25519 z9;
	fe25519 z11;
	fe25519 z2_5_0;
	fe25519 z2_10_0;
	fe25519 z2_20_0;
	fe25519 z2_50_0;
	fe25519 z2_100_0;
	fe25519 t0;
	fe25519 t1;
	int i;
	
	/* 2 */ fe25519_square(&z2,x);
	/* 4 */ fe25519_square(&t1,&z2);
	/* 8 */ fe25519_square(&t0,&t1);
	/* 9 */ fe25519_mul(&z9,&t0,x);
	/* 11 */ fe25519_mul(&z11,&z9,&z2);
	/* 22 */ fe25519_square(&t0,&z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t0,&z9);

	/* 2^6 - 2^1 */ fe25519_square(&t0,&z2_5_0);
	/* 2^7 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^8 - 2^3 */ fe25519_square(&t0,&t1);
	/* 2^9 - 2^4 */ fe25519_square(&t1,&t0);
	/* 2^10 - 2^5 */ fe25519_square(&t0,&t1);
	/* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t0,&z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&t0,&z2_10_0);
	/* 2^12 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t1,&z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&t0,&z2_20_0);
	/* 2^22 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^40 - 2^0 */ fe25519_mul(&t0,&t1,&z2_20_0);

	/* 2^41 - 2^1 */ fe25519_square(&t1,&t0);
	/* 2^42 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
	/* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t0,&z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&t0,&z2_50_0);
	/* 2^52 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t1,&z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&t1,&z2_100_0);
	/* 2^102 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
	/* 2^200 - 2^0 */ fe25519_mul(&t1,&t0,&z2_100_0);

	/* 2^201 - 2^1 */ fe25519_square(&t0,&t1);
	/* 2^202 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^250 - 2^0 */ fe25519_mul(&t0,&t1,&z2_50_0);

	/* 2^251 - 2^1 */ fe25519_square(&t1,&t0);
	/* 2^252 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^253 - 2^3 */ fe25519_square(&t1,&t0);
	/* 2^254 - 2^4 */ fe25519_square(&t0,&t1);
	/* 2^255 - 2^5 */ fe25519_square(&t1,&t0);
	/* 2^255 - 21 */ fe25519_mul(r,&t1,&z11);
}



typedef struct {
  crypto_uint32 v[32]; 
} sc25519;

void sc25519_from32bytes(sc25519 *r, const unsigned char x[32]);
void sc25519_from64bytes(sc25519 *r, const unsigned char x[64]);
void sc25519_to32bytes(unsigned char r[32], const sc25519 *x);
void sc25519_pack(unsigned char r[32], const sc25519 *x);
unsigned char sc25519_getparity(const sc25519 *x);
void sc25519_setone(sc25519 *r);
void sc25519_setzero(sc25519 *r);
void sc25519_add(sc25519 *r, const sc25519 *x, const sc25519 *y);
void sc25519_sub(sc25519 *r, const sc25519 *x, const sc25519 *y);
void sc25519_mul(sc25519 *r, const sc25519 *x, const sc25519 *y);
void sc25519_square(sc25519 *r, const sc25519 *x);
void sc25519_invert(sc25519 *r, const sc25519 *x);

/*Arithmetic modulo the group order n = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 */

static const crypto_uint32 m[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

static const crypto_uint32 mu[33] = {0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21, 
                                     0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F};

/* Reduce coefficients of r before calling sc25519_reduce_add_sub */
static void sc25519_reduce_add_sub(sc25519 *r)
{
  int i, b, pb=0, nb;
  unsigned char t[32];

  for(i=0;i<32;i++) 
  {
    b = (r->v[i]<pb+m[i]);
    t[i] = r->v[i]-pb-m[i]+b*256;
    pb = b;
  }
  nb = 1-b;
  for(i=0;i<32;i++) 
    r->v[i] = r->v[i]*b + t[i]*nb;
}

/* Reduce coefficients of x before calling sc25519_barrett_reduce */
static void sc25519_barrett_reduce(sc25519 *r, const crypto_uint32 x[64])
{
  /* See HAC, Alg. 14.42 */
  int i,j;
  crypto_uint32 q2[66] = {0};
  crypto_uint32 *q3 = q2 + 33;
  crypto_uint32 r1[33];
  crypto_uint32 r2[33] = {0};
  crypto_uint32 carry;
  int b, pb=0;

  for(i=0;i<33;i++)
    for(j=0;j<33;j++)
      if(i+j >= 31) q2[i+j] += mu[i]*x[j+31];
  carry = q2[31] >> 8;
  q2[32] += carry;
  carry = q2[32] >> 8;
  q2[33] += carry;

  for(i=0;i<33;i++)r1[i] = x[i];
  for(i=0;i<32;i++)
    for(j=0;j<33;j++)
      if(i+j < 33) r2[i+j] += m[i]*q3[j];

  for(i=0;i<32;i++)
  {
    carry = r2[i] >> 8;
    r2[i+1] += carry;
    r2[i] &= 0xff;
  }

  for(i=0;i<32;i++) 
  {
    b = (r1[i]<pb+r2[i]);
    r->v[i] = r1[i]-pb-r2[i]+b*256;
    pb = b;
  }

  /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
   * If so: Handle  it here!
   */

  sc25519_reduce_add_sub(r);
  sc25519_reduce_add_sub(r);
}

/*
static int iszero(const sc25519 *x)
{
  // Implement
  return 0;
}
*/

void sc25519_from32bytes(sc25519 *r, const unsigned char x[32])
{
  int i;
  crypto_uint32 t[64] = {0};
  for(i=0;i<32;i++) t[i] = x[i];
  sc25519_barrett_reduce(r, t);
}

void sc25519_from64bytes(sc25519 *r, const unsigned char x[64])
{
  int i;
  crypto_uint32 t[64] = {0};
  for(i=0;i<64;i++) t[i] = x[i];
  sc25519_barrett_reduce(r, t);
}

/* XXX: What we actually want for crypto_group is probably just something like
 * void sc25519_frombytes(sc25519 *r, const unsigned char *x, size_t xlen)
 */

void sc25519_to32bytes(unsigned char r[32], const sc25519 *x)
{
  int i;
  for(i=0;i<32;i++) r[i] = x->v[i];
}

void sc25519_add(sc25519 *r, const sc25519 *x, const sc25519 *y)
{
  int i, carry;
  for(i=0;i<32;i++) r->v[i] = x->v[i] + y->v[i];
  for(i=0;i<31;i++)
  {
    carry = r->v[i] >> 8;
    r->v[i+1] += carry;
    r->v[i] &= 0xff;
  }
  sc25519_reduce_add_sub(r);
}

void sc25519_mul(sc25519 *r, const sc25519 *x, const sc25519 *y)
{
  int i,j,carry;
  crypto_uint32 t[64];
  for(i=0;i<64;i++)t[i] = 0;

  for(i=0;i<32;i++)
    for(j=0;j<32;j++)
      t[i+j] += x->v[i] * y->v[j];

  /* Reduce coefficients */
  for(i=0;i<63;i++)
  {
    carry = t[i] >> 8;
    t[i+1] += carry;
    t[i] &= 0xff;
  }

  sc25519_barrett_reduce(r, t);
}

void sc25519_square(sc25519 *r, const sc25519 *x)
{
  sc25519_mul(r, x, x);
}


#define ge25519 crypto_sign_edwards25519sha512batch_ge25519
#define ge25519_unpack_vartime crypto_sign_edwards25519sha512batch_ge25519_unpack_vartime
#define ge25519_pack crypto_sign_edwards25519sha512batch_ge25519_pack
#define ge25519_add crypto_sign_edwards25519sha512batch_ge25519_add
#define ge25519_double crypto_sign_edwards25519sha512batch_ge25519_double
#define ge25519_scalarmult crypto_sign_edwards25519sha512batch_ge25519_scalarmult
#define ge25519_scalarmult_base crypto_sign_edwards25519sha512batch_ge25519_scalarmult_base

typedef struct {
  fe25519 x;
  fe25519 y;
  fe25519 z;
  fe25519 t;
} ge25519;

int ge25519_unpack_vartime(ge25519 *r, const unsigned char p[32]);
void ge25519_pack(unsigned char r[32], const ge25519 *p);
void ge25519_add(ge25519 *r, const ge25519 *p, const ge25519 *q);
void ge25519_double(ge25519 *r, const ge25519 *p);
void ge25519_scalarmult(ge25519 *r, const ge25519 *p, const sc25519 *s);
void ge25519_scalarmult_base(ge25519 *r, const sc25519 *s);

/* 
 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 
 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
 */

typedef struct
{
  fe25519 x;
  fe25519 z;
  fe25519 y;
  fe25519 t;
} ge25519_p1p1;

typedef struct
{
  fe25519 x;
  fe25519 y;
  fe25519 z;
} ge25519_p2;

#define ge25519_p3 ge25519

#undef WINDOWSIZE
/* Windowsize for fixed-window scalar multiplication */
#define WINDOWSIZE 2                      /* Should be 1,2, or 4 */
#define WINDOWMASK ((1<<WINDOWSIZE)-1)

/* packed parameter d in the Edwards curve equation */
static const unsigned char ecd[32] = {0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00, 
                                      0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52};

/* Packed coordinates of the base point */
static const unsigned char ge25519_base_x[32] = {0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69, 
                                                 0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21};
static const unsigned char ge25519_base_y[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 
                                                 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
static const unsigned char ge25519_base_z[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const unsigned char ge25519_base_t[32] = {0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20, 
                                                 0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67};

/* Packed coordinates of the neutral element */
static const unsigned char ge25519_neutral_x[32] = {0};
static const unsigned char ge25519_neutral_y[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const unsigned char ge25519_neutral_z[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const unsigned char ge25519_neutral_t[32] = {0};

static void p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p)
{
  fe25519_mul(&r->x, &p->x, &p->t);
  fe25519_mul(&r->y, &p->y, &p->z);
  fe25519_mul(&r->z, &p->z, &p->t);
}

static void p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p)
{
  p1p1_to_p2((ge25519_p2 *)r, p);
  fe25519_mul(&r->t, &p->x, &p->y);
}

/* Constant-time version of: if(b) r = p */
static void cmov_p3(ge25519_p3 *r, const ge25519_p3 *p, unsigned char b)
{
  fe25519_cmov(&r->x, &p->x, b);
  fe25519_cmov(&r->y, &p->y, b);
  fe25519_cmov(&r->z, &p->z, b);
  fe25519_cmov(&r->t, &p->t, b);
}

/* See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd */
static void dbl_p1p1(ge25519_p1p1 *r, const ge25519_p2 *p)
{
  fe25519 a,b,c,d;
  fe25519_square(&a, &p->x);
  fe25519_square(&b, &p->y);
  fe25519_square(&c, &p->z);
  fe25519_add(&c, &c, &c);
  fe25519_neg(&d, &a);

  fe25519_add(&r->x, &p->x, &p->y);
  fe25519_square(&r->x, &r->x);
  fe25519_sub(&r->x, &r->x, &a);
  fe25519_sub(&r->x, &r->x, &b);
  fe25519_add(&r->z, &d, &b);
  fe25519_sub(&r->t, &r->z, &c);
  fe25519_sub(&r->y, &d, &b);
}

static void add_p1p1(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q)
{
  fe25519 a, b, c, d, t, fd;
  fe25519_unpack(&fd, ecd);
  
  fe25519_sub(&a, &p->y, &p->x); // A = (Y1-X1)*(Y2-X2)
  fe25519_sub(&t, &q->y, &q->x);
  fe25519_mul(&a, &a, &t);
  fe25519_add(&b, &p->x, &p->y); // B = (Y1+X1)*(Y2+X2)
  fe25519_add(&t, &q->x, &q->y);
  fe25519_mul(&b, &b, &t);
  fe25519_mul(&c, &p->t, &q->t); //C = T1*k*T2
  fe25519_mul(&c, &c, &fd);
  fe25519_add(&c, &c, &c);       //XXX: Can save this addition by precomputing 2*ecd
  fe25519_mul(&d, &p->z, &q->z); //D = Z1*2*Z2
  fe25519_add(&d, &d, &d);
  fe25519_sub(&r->x, &b, &a); // E = B-A
  fe25519_sub(&r->t, &d, &c); // F = D-C
  fe25519_add(&r->z, &d, &c); // G = D+C
  fe25519_add(&r->y, &b, &a); // H = B+A
}

/* ********************************************************************
 *                    EXPORTED FUNCTIONS
 ******************************************************************** */

/* return 0 on success, -1 otherwise */
int ge25519_unpack_vartime(ge25519_p3 *r, const unsigned char p[32])
{
  int ret;
  fe25519 t, fd;
  fe25519_setone(&r->z);
  fe25519_unpack(&fd, ecd);
  unsigned char par = p[31] >> 7;
  fe25519_unpack(&r->y, p);
  fe25519_square(&r->x, &r->y);
  fe25519_mul(&t, &r->x, &fd);
  fe25519_sub(&r->x, &r->x, &r->z);
  fe25519_add(&t, &r->z, &t);
  fe25519_invert(&t, &t);
  fe25519_mul(&r->x, &r->x, &t);
  ret = fe25519_sqrt_vartime(&r->x, &r->x, par);
  fe25519_mul(&r->t, &r->x, &r->y);
  return ret;
}

void ge25519_pack(unsigned char r[32], const ge25519_p3 *p)
{
  fe25519 tx, ty, zi;
  fe25519_invert(&zi, &p->z); 
  fe25519_mul(&tx, &p->x, &zi);
  fe25519_mul(&ty, &p->y, &zi);
  fe25519_pack(r, &ty);
  r[31] ^= fe25519_getparity(&tx) << 7;
}

void ge25519_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q)
{
  ge25519_p1p1 grp1p1;
  add_p1p1(&grp1p1, p, q);
  p1p1_to_p3(r, &grp1p1);
}

void ge25519_double(ge25519_p3 *r, const ge25519_p3 *p)
{
  ge25519_p1p1 grp1p1;
  dbl_p1p1(&grp1p1, (ge25519_p2 *)p);
  p1p1_to_p3(r, &grp1p1);
}

void ge25519_scalarmult(ge25519_p3 *r, const ge25519_p3 *p, const sc25519 *s)
{
  int i,j,k;
  ge25519_p3 g;  
  fe25519_unpack(&g.x, ge25519_neutral_x);
  fe25519_unpack(&g.y, ge25519_neutral_y);
  fe25519_unpack(&g.z, ge25519_neutral_z);
  fe25519_unpack(&g.t, ge25519_neutral_t);

  ge25519_p3 pre[(1 << WINDOWSIZE)];
  ge25519_p3 t;
  ge25519_p1p1 tp1p1;
  unsigned char w;
  unsigned char sb[32];
  sc25519_to32bytes(sb, s);

  // Precomputation
  pre[0] = g;
  pre[1] = *p;
  for(i=2;i<(1<<WINDOWSIZE);i+=2)
  {
    dbl_p1p1(&tp1p1, (ge25519_p2 *)(pre+i/2));
    p1p1_to_p3(pre+i, &tp1p1);
    add_p1p1(&tp1p1, pre+i, pre+1);
    p1p1_to_p3(pre+i+1, &tp1p1);
  }

  // Fixed-window scalar multiplication
  for(i=32;i>0;i--)
  {
    for(j=8-WINDOWSIZE;j>=0;j-=WINDOWSIZE)
    {
      for(k=0;k<WINDOWSIZE-1;k++)
      {
        dbl_p1p1(&tp1p1, (ge25519_p2 *)&g);
        p1p1_to_p2((ge25519_p2 *)&g, &tp1p1);
      }
      dbl_p1p1(&tp1p1, (ge25519_p2 *)&g);
      p1p1_to_p3(&g, &tp1p1);
      // Cache-timing resistant loading of precomputed value:
      w = (sb[i-1]>>j) & WINDOWMASK;
      t = pre[0];
      for(k=1;k<(1<<WINDOWSIZE);k++)
        cmov_p3(&t, &pre[k], k==w);

      add_p1p1(&tp1p1, &g, &t);
      if(j != 0) p1p1_to_p2((ge25519_p2 *)&g, &tp1p1);
      else p1p1_to_p3(&g, &tp1p1); /* convert to p3 representation at the end */
    }
  }
  r->x = g.x;
  r->y = g.y;
  r->z = g.z;
  r->t = g.t;
}

void ge25519_scalarmult_base(ge25519_p3 *r, const sc25519 *s)
{
  /* XXX: Better algorithm for known-base-point scalar multiplication */
  ge25519_p3 t;
  fe25519_unpack(&t.x, ge25519_base_x);
  fe25519_unpack(&t.y, ge25519_base_y);
  fe25519_unpack(&t.z, ge25519_base_z);
  fe25519_unpack(&t.t, ge25519_base_t);
  ge25519_scalarmult(r, &t, s);          
}

int crypto_sign_keypair(
    unsigned char *pk,
    unsigned char *sk
    )
{
  sc25519 scsk;
  ge25519 gepk;

  //randombytes(sk, 32);
  crypto_hash_sha512(sk, sk, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;

  sc25519_from32bytes(&scsk,sk);
  
  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);
  return 0;
}

int crypto_sign(
    unsigned char *sm,unsigned long long *smlen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *sk
    )
{
  sc25519 sck, scs, scsk;
  ge25519 ger;
  unsigned char r[32];
  unsigned char s[32];
  unsigned long long i;
  unsigned char hmg[crypto_hash_sha512_BYTES];
  unsigned char hmr[crypto_hash_sha512_BYTES];

  *smlen = mlen+64;
  for(i=0;i<mlen;i++)
    sm[32 + i] = m[i];
  for(i=0;i<32;i++)
    sm[i] = sk[32+i];
  crypto_hash_sha512(hmg, sm, mlen+32); /* Generate k as h(m,sk[32],...,sk[63]) */

  sc25519_from64bytes(&sck, hmg);
  ge25519_scalarmult_base(&ger, &sck);
  ge25519_pack(r, &ger);
  
  for(i=0;i<32;i++)
    sm[i] = r[i];

  crypto_hash_sha512(hmr, sm, mlen+32); /* Compute h(m,r) */
  sc25519_from64bytes(&scs, hmr);
  sc25519_mul(&scs, &scs, &sck);
  
  sc25519_from32bytes(&scsk, sk);
  sc25519_add(&scs, &scs, &scsk);

  sc25519_to32bytes(s,&scs); /* cat s */
  for(i=0;i<32;i++)
    sm[mlen+32+i] = s[i]; 

  return 0;
}

int crypto_sign_open(
    unsigned char *m,unsigned long long *mlen,
    const unsigned char *sm,unsigned long long smlen,
    const unsigned char *pk
    )
{
  int i;
  unsigned char t1[32], t2[32];
  ge25519 get1, get2, gepk;
  sc25519 schmr, scs;
  unsigned char hmr[crypto_hash_sha512_BYTES];

  if (ge25519_unpack_vartime(&get1, sm)) return -1;
  if (ge25519_unpack_vartime(&gepk, pk)) return -1;

  crypto_hash_sha512(hmr,sm,smlen-32);

  sc25519_from64bytes(&schmr, hmr);
  ge25519_scalarmult(&get1, &get1, &schmr);
  ge25519_add(&get1, &get1, &gepk);
  ge25519_pack(t1, &get1);

  sc25519_from32bytes(&scs, &sm[smlen-32]);
  ge25519_scalarmult_base(&get2, &scs);
  ge25519_pack(t2, &get2);

  for(i=0;i<smlen-64;i++)
    m[i] = sm[i + 32];
  *mlen = smlen-64;

  return crypto_verify_32(t1, t2);
}
