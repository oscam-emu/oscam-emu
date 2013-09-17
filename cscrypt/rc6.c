/* rc6 (TM)
 * Unoptimized sample implementation of Ron Rivest's submission to the
 * AES bakeoff.
 *
 * Salvo Salasio, 19 June 1998
 *
 * Intellectual property notes:  The name of the algorithm (RC6) is
 * trademarked; any property rights to the algorithm or the trademark
 * should be discussed with discussed with the authors of the defining
 * paper "The RC6(TM) Block Cipher": Ronald L. Rivest (MIT),
 * M.J.B. Robshaw (RSA Labs), R. Sidney (RSA Labs), and Y.L. Yin (RSA Labs),
 * distributed 18 June 1998 and available from the lead author's web site.
 *
 * This sample implementation is placed in the public domain by the author,
 * Salvo Salasio.  The ROTL and ROTR definitions were cribbed from RSA Labs'
 * RC5 reference implementation.
 */

#include <stdio.h>
#include "rc6.h"

#define w 32    /* word size in bits */
#define r 20    /* based on security estimates */

#define P32 0xB7E15163  /* Magic constants for key setup */
#define Q32 0x9E3779B9

/* derived constants */
#define bytes   (w / 8)                         /* bytes per word */
#define c       ((b + bytes - 1) / bytes)       /* key in words, rounded up */
#define R24     (2 * r + 4)
#define lgw     5                               /* log2(w) -- wussed out */

/* Rotations */
#define ROTL(x,y) (((x)<<((y)&(w-1))) | ((x)>>(w-((y)&(w-1)))))
#define ROTR(x,y) (((x)>>((y)&(w-1))) | ((x)<<(w-((y)&(w-1)))))

void rc6_key_setup(unsigned char *K, int b, RC6KEY S)
{
	int i, j, s, v;
	unsigned int L[(32 + bytes - 1) / bytes]; /* Big enough for max b */
	unsigned int A, B;

	L[c - 1] = 0;
	for (i = b - 1; i >= 0; i--)
		L[i / bytes] = (L[i / bytes] << 8) + K[i];

	S[0] = P32;
	for (i = 1; i <= 2 * r + 3; i++)
		S[i] = S[i - 1] + Q32;

	A = B = i = j = 0;
	v = R24;
	if (c > v) v = c;
	v *= 3;

	for (s = 1; s <= v; s++)
	{
		A = S[i] = ROTL(S[i] + A + B, 3);
		B = L[j] = ROTL(L[j] + A + B, A + B);
		i = (i + 1) % R24;
		j = (j + 1) % c;
	}
}

void rc6_block_encrypt(unsigned int *pt, unsigned int *ct, int block_count, RC6KEY S)
{
	unsigned int A, B, C, D, t, u, x;
	int i;

	while (block_count>0) {
		A = pt[0];
		B = pt[1];
		C = pt[2];
		D = pt[3];
		B += S[0];
		D += S[1];
		for (i = 2; i <= 2 * r; i += 2)
		{
			t = ROTL(B * (2 * B + 1), lgw);
			u = ROTL(D * (2 * D + 1), lgw);
			A = ROTL(A ^ t, u) + S[i];
			C = ROTL(C ^ u, t) + S[i + 1];
			x = A;
			A = B;
			B = C;
			C = D;
			D = x;
		}
		A += S[2 * r + 2];
		C += S[2 * r + 3];
		ct[0] = A;
		ct[1] = B;
		ct[2] = C;
		ct[3] = D;
		
		block_count--;
		pt++;
		ct++;
	}
}

void rc6_block_decrypt(unsigned int *ct, unsigned int *pt, int block_count, RC6KEY S)
{
	unsigned int A, B, C, D, t, u, x;
	int i;

	while (block_count>0) {
		A = ct[0];
		B = ct[1];
		C = ct[2];
		D = ct[3];
		C -= S[2 * r + 3];
		A -= S[2 * r + 2];
		for (i = 2 * r; i >= 2; i -= 2)
		{
			x = D;
			D = C;
			C = B;
			B = A;
			A = x;
			u = ROTL(D * (2 * D + 1), lgw);
			t = ROTL(B * (2 * B + 1), lgw);
			C = ROTR(C - S[i + 1], t) ^ u;
			A = ROTR(A - S[i], u) ^ t;
		}
		D -= S[1];
		B -= S[0];
		pt[0] = A;
		pt[1] = B;
		pt[2] = C;
		pt[3] = D;
		
		block_count--;
		ct++;
		pt++;
	}
}

/*
struct test_struct
{
	int keylen;
	unsigned char key[32];
	unsigned int pt[4];
	unsigned int ct[4];
} tests[] =
{
	{ 16,   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x36a5c38f, 0x78f7b156, 0x4edf29c1, 0x1ea44898},
	},

	{ 16,   {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78},
		{0x35241302, 0x79685746, 0xbdac9b8a, 0xf1e0dfce},
		{0x2f194e52, 0x23c61547, 0x36f6511f, 0x183fa47e},
	},

	{ 24,   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0xcb1bd66c, 0x38300b19, 0x163f8a4e, 0x82ae9086},
	},

	{ 24,   {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
		 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0},
		{0x35241302, 0x79685746, 0xbdac9b8a, 0xf1e0dfce},
		{0xd0298368, 0x0405e519, 0x2ae9521e, 0xd49152f9},
	},

	{ 32,   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x05bd5f8f, 0xa85fd110, 0xda3ffa93, 0xc27e856e},
	},

	{ 32,   {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
		 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
		 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe},
		{0x35241302, 0x79685746, 0xbdac9b8a, 0xf1e0dfce},
		{0x161824c8, 0x89e4d7f0, 0xa116ad20, 0x485d4e67},
	},

	{       0,
	}
};

int
main()
{
	unsigned int ct[4], pt[4];
	int i;
	struct test_struct *p;
	RC6KEY S;

	for (p = tests, i = 1; p->keylen; p++, i++)
	{

		rc6_key_setup(p->key, p->keylen, &S);
		rc6_block_encrypt(p->pt, ct, &S);
		printf("Test   %d:  %08x %08x %08x %08x\n",
			i, ct[0], ct[1], ct[2], ct[3]);
		printf("Should be: %08x %08x %08x %08x\n",
			p->ct[0], p->ct[1], p->ct[2], p->ct[3]);
		rc6_block_decrypt(ct, pt, &S);
		printf("Plain:     %08x %08x %08x %08x\n",
			pt[0], pt[1], pt[2], pt[3]);
		printf("Should be: %08x %08x %08x %08x\n\n",
			p->pt[0], p->pt[1], p->pt[2], p->pt[3]);
	}

	return 0;
}
*/

