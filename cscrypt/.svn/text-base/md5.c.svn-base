/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest. This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * ----------------------------------------------------------------------------
 * The md5_crypt() function was taken from freeBSD's libcrypt and contains 
 * this license: 
 *    "THE BEER-WARE LICENSE" (Revision 42):
 *     <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 *     can do whatever you want with this stuff. If we meet some day, and you think
 *     this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 *
 * $FreeBSD: src/lib/libcrypt/crypt.c,v 1.7.2.1 1999/08/29 14:56:33 peter Exp $
 *
 * ----------------------------------------------------------------------------
 * On April 19th, 2001 md5_crypt() was modified to make it reentrant 
 * by Erik Andersen <andersen@uclibc.org>
 */

#include "../globals.h"

#include "md5.h"

#if !defined(WITH_SSL) && !defined(WITH_LIBCRYPTO)

typedef struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
} MD5_CTX;

#ifdef __i386__
#define byteReverse(a, b)
#else
/*
 * Note: This code is harmless on little-endian machines.
 *       The ifdefs are just a small optimization
 */
static void byteReverse(unsigned char *buf, unsigned int longs)
{
	uint32_t t;
	do {
		t = (uint32_t)((unsigned int)buf[3] << 8 | buf[2]) << 16 |
					  ((unsigned int)buf[1] << 8 | buf[0]);
		*(uint32_t *) buf = t;
		buf += 4;
	} while (--longs);
}
#endif

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5_Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5_Transform(uint32_t buf[4],  uint32_t in[16])
{
	uint32_t a = buf[0];
	uint32_t b = buf[1];
	uint32_t c = buf[2];
	uint32_t d = buf[3];

	MD5STEP(F1, a, b, c, d, in[ 0] + 0xd76aa478,  7);
	MD5STEP(F1, d, a, b, c, in[ 1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[ 2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[ 3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[ 4] + 0xf57c0faf,  7);
	MD5STEP(F1, d, a, b, c, in[ 5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[ 6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[ 7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[ 8] + 0x698098d8,  7);
	MD5STEP(F1, d, a, b, c, in[ 9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122,  7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[ 1] + 0xf61e2562,  5);
	MD5STEP(F2, d, a, b, c, in[ 6] + 0xc040b340,  9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[ 0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[ 5] + 0xd62f105d,  5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453,  9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[ 4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[ 9] + 0x21e1cde6,  5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6,  9);
	MD5STEP(F2, c, d, a, b, in[ 3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[ 8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905,  5);
	MD5STEP(F2, d, a, b, c, in[ 2] + 0xfcefa3f8,  9);
	MD5STEP(F2, c, d, a, b, in[ 7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[ 5] + 0xfffa3942,  4);
	MD5STEP(F3, d, a, b, c, in[ 8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[ 1] + 0xa4beea44,  4);
	MD5STEP(F3, d, a, b, c, in[ 4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[ 7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6,  4);
	MD5STEP(F3, d, a, b, c, in[ 0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[ 3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[ 6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[ 9] + 0xd9d4d039,  4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[ 2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[ 0] + 0xf4292244,  6);
	MD5STEP(F4, d, a, b, c, in[ 7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[ 5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3,  6);
	MD5STEP(F4, d, a, b, c, in[ 3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[ 1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[ 8] + 0x6fa87e4f,  6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[ 6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[ 4] + 0xf7537e82,  6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[ 2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[ 9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void MD5_Init(MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void MD5_Update(MD5_CTX *ctx, const unsigned char *buf, unsigned int len)
{
	uint32_t t;

	/* Update bitcount */

	t = ctx->bits[0];
	if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
	ctx->bits[1]++; 	/* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

	/* Handle any leading odd-sized chunks */

	if (t) {
		unsigned char *p = (unsigned char *)ctx->in + t;
		t = 64 - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		byteReverse(ctx->in, 16);
		MD5_Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += t;
		len -= t;
	}

	/* Process data in 64-byte chunks */
	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		byteReverse(ctx->in, 16);
		MD5_Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void MD5_Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx)
{
	unsigned count;
	unsigned char *p;

	/* Compute number of bytes mod 64 */
	count = (ctx->bits[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		byteReverse(ctx->in, 16);
		MD5_Transform(ctx->buf, (uint32_t *) ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}
	byteReverse(ctx->in, 14);

	/* Append length in bits and transform */
	uint32_t *c = (uint32_t *)ctx->in;
	c[14] = ctx->bits[0];
	c[15] = ctx->bits[1];

	MD5_Transform(ctx->buf, (uint32_t *) ctx->in);
	byteReverse((unsigned char *) ctx->buf, 4);

	memcpy(digest, ctx->buf, 16);
	memset(ctx, 0, sizeof(struct MD5Context)); /* In case it's sensitive */
}

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output)
{
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, len);
	MD5_Final(output, &ctx);
	memset(&ctx, 0, sizeof(ctx)); /* security consideration */
	return output;
}
#endif

/* This string is magic for this algorithm.  Having
   it this way, we can get better later on */
static const char __md5__magic[] = "$1$";

/* 0 ... 63 => ascii - 64 */
static const unsigned char __md5_itoa64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void __md5_to64( char *s, unsigned long v, int n)
{
	while (--n >= 0) {
		*s++ = __md5_itoa64[v&0x3f];
		v >>= 6;
	}
}

/*
 * UNIX password
 *
 * Use MD5 for what it is best at...
 */

char * __md5_crypt( const char *pw, const char *salt, char *passwd )
{
	const char *sp, *ep;
	char *p;

	unsigned char	final[17];	/* final[16] exists only to aid in looping */
	int sl,pl,i,__md5__magic_len,pw_len;
	MD5_CTX ctx,ctx1;
	unsigned long l;

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	__md5__magic_len = strlen(__md5__magic);
	if(!strncmp(sp,__md5__magic,__md5__magic_len))
		sp += __md5__magic_len;

	/* It stops at the first '$', max 8 chars */
	for(ep=sp;*ep && *ep != '$' && ep < (sp+8);ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;

	MD5_Init(&ctx);

	/* The password first, since that is what is most unknown */
	pw_len = strlen(pw);
	MD5_Update(&ctx,(const unsigned char *)pw,pw_len);

	/* Then our magic string */
	MD5_Update(&ctx,(const unsigned char *)__md5__magic,__md5__magic_len);

	/* Then the raw salt */
	MD5_Update(&ctx,(const unsigned char *)sp,sl);

	/* Then just as many characters of the MD5(pw,salt,pw) */
	MD5_Init(&ctx1);
	MD5_Update(&ctx1,(const unsigned char *)pw,pw_len);
	MD5_Update(&ctx1,(const unsigned char *)sp,sl);
	MD5_Update(&ctx1,(const unsigned char *)pw,pw_len);
	MD5_Final(final,&ctx1);
	for(pl = pw_len; pl > 0; pl -= 16)
		MD5_Update(&ctx,(const unsigned char *)final,pl>16 ? 16 : pl);

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);

	/* Then something really weird... */
	for (i = pw_len; i ; i >>= 1) {
		MD5_Update(&ctx, ((i&1) ? final : (const unsigned char *) pw), 1);
	}

	/* Now make the output string */
	strncpy(passwd,__md5__magic,4); // This should be safe
	strncat(passwd,sp,sl);
	strcat(passwd,"$");

	MD5_Final(final,&ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		MD5_Init(&ctx1);
		if(i & 1)
			MD5_Update(&ctx1,(const unsigned char *)pw,pw_len);
		else
			MD5_Update(&ctx1,(const unsigned char *)final,16);

		if(i % 3)
			MD5_Update(&ctx1,(const unsigned char *)sp,sl);

		if(i % 7)
			MD5_Update(&ctx1,(const unsigned char *)pw,pw_len);

		if(i & 1)
			MD5_Update(&ctx1,(const unsigned char *)final,16);
		else
			MD5_Update(&ctx1,(const unsigned char *)pw,pw_len);
		MD5_Final(final,&ctx1);
	}

	p = passwd + strlen(passwd);

	final[16] = final[5];
	for ( i=0 ; i < 5 ; i++ ) {
		l = (final[i]<<16) | (final[i+6]<<8) | final[i+12];
		__md5_to64(p,l,4); p += 4;
	}
	l = final[11];
	__md5_to64(p,l,2); p += 2;
	*p = '\0';

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);

	return passwd;
}
