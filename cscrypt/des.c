#include "../globals.h"
#include "../oscam-string.h"
#include "des.h"

#define CRYPT           0
#define HASH            1

#define F_EURO_S2       0
#define F_TRIPLE_DES    1

#define TestBit(addr, bit) ((addr) & (1 << bit))

static unsigned char PC2[8][6] =
{
	{ 14, 17, 11, 24,  1,  5 },
	{  3, 28, 15,  6, 21, 10 },
	{ 23, 19, 12,  4, 26,  8 },
	{ 16,  7, 27, 20, 13,  2 },
	{ 41, 52, 31, 37, 47, 55 },
	{ 30, 40, 51, 45, 33, 48 },
	{ 44, 49, 39, 56, 34, 53 },
	{ 46, 42, 50, 36, 29, 32 }
};


static unsigned char E[8][6] =
{
	{ 32,  1,  2,  3,  4,  5 },
	{  4,  5,  6,  7,  8,  9 },
	{  8,  9, 10, 11, 12, 13 },
	{ 12, 13, 14, 15, 16, 17 },
	{ 16, 17, 18, 19, 20, 21 },
	{ 20, 21, 22, 23, 24, 25 },
	{ 24, 25, 26, 27, 28, 29 },
	{ 28, 29, 30, 31, 32,  1 }
};



static unsigned char P[32] =
{
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};


static unsigned char SBOXES[4][64] =
{
	{
		0x2e, 0xe0, 0xc4, 0xbf, 0x4d, 0x27, 0x11, 0xc4,
		0x72, 0x4e, 0xaf, 0x72, 0xbb, 0xdd, 0x68, 0x11,
		0x83, 0x5a, 0x5a, 0x06, 0x36, 0xfc, 0xfc, 0xab,
		0xd5, 0x39, 0x09, 0x95, 0xe0, 0x83, 0x97, 0x68,
		0x44, 0xbf, 0x21, 0x8c, 0x1e, 0xc8, 0xb8, 0x72,
		0xad, 0x14, 0xd6, 0xe9, 0x72, 0x21, 0x8b, 0xd7,
		0xff, 0x65, 0x9c, 0xfb, 0xc9, 0x03, 0x57, 0x9e,
		0x63, 0xaa, 0x3a, 0x40, 0x05, 0x56, 0xe0, 0x3d
	},
	{
		0xcf, 0xa3, 0x11, 0xfd, 0xa8, 0x44, 0xfe, 0x27,
		0x96, 0x7f, 0x2b, 0xc2, 0x63, 0x98, 0x84, 0x5e,
		0x09, 0x6c, 0xd7, 0x10, 0x32, 0xd1, 0x4d, 0xea,
		0xec, 0x06, 0x70, 0xb9, 0x55, 0x3b, 0xba, 0x85,
		0x90, 0x4d, 0xee, 0x38, 0xf7, 0x2a, 0x5b, 0xc1,
		0x2a, 0x93, 0x84, 0x5f, 0xcd, 0xf4, 0x31, 0xa2,
		0x75, 0xbb, 0x08, 0xe6, 0x4c, 0x17, 0xa6, 0x7c,
		0x19, 0x60, 0xd3, 0x05, 0xb2, 0x8e, 0x6f, 0xd9
	},
	{
		0x4a, 0xdd, 0xb0, 0x07, 0x29, 0xb0, 0xee, 0x79,
		0xf6, 0x43, 0x03, 0x94, 0x8f, 0x16, 0xd5, 0xaa,
		0x31, 0xe2, 0xcd, 0x38, 0x9c, 0x55, 0x77, 0xce,
		0x5b, 0x2c, 0xa4, 0xfb, 0x62, 0x8f, 0x18, 0x61,
		0x1d, 0x61, 0x46, 0xba, 0xb4, 0xdd, 0xd9, 0x80,
		0xc8, 0x16, 0x3f, 0x49, 0x73, 0xa8, 0xe0, 0x77,
		0xab, 0x94, 0xf1, 0x5f, 0x62, 0x0e, 0x8c, 0xf3,
		0x05, 0xeb, 0x5a, 0x25, 0x9e, 0x32, 0x27, 0xcc
	},
	{
		0xd7, 0x1d, 0x2d, 0xf8, 0x8e, 0xdb, 0x43, 0x85,
		0x60, 0xa6, 0xf6, 0x3f, 0xb9, 0x70, 0x1a, 0x43,
		0xa1, 0xc4, 0x92, 0x57, 0x38, 0x62, 0xe5, 0xbc,
		0x5b, 0x01, 0x0c, 0xea, 0xc4, 0x9e, 0x7f, 0x29,
		0x7a, 0x23, 0xb6, 0x1f, 0x49, 0xe0, 0x10, 0x76,
		0x9c, 0x4a, 0xcb, 0xa1, 0xe7, 0x8d, 0x2d, 0xd8,
		0x0f, 0xf9, 0x61, 0xc4, 0xa3, 0x95, 0xde, 0x0b,
		0xf5, 0x3c, 0x32, 0x57, 0x58, 0x62, 0x84, 0xbe
	}
};



static unsigned char PC1[][8] =
{
	{57, 49, 41, 33, 25, 17,  9, 1},
	{58, 50, 42, 34, 26, 18, 10, 2},
	{59, 51, 43, 35, 27, 19, 11, 3},
	{60, 52, 44, 36, 63, 55, 47, 39},
	{31, 23, 15,  7, 62, 54, 46, 38},
	{30, 22, 14,  6, 61, 53, 45, 37},
	{29, 21, 13,  5, 28, 20, 12, 4}
};


void doPC1(unsigned char data[])
{
	unsigned char buf[8];
	unsigned char i, j;

	memset(buf, 0, 8);

	for(j = 0; j < 7; j++)
	{
		for(i = 0; i < 8; i++)
		{
			unsigned char lookup = PC1[j][i];
			buf[j] |= ((data[(lookup >> 3)] >> (8 - (lookup & 7))) & 1) << (7 - i);
		}
	}

	memcpy(data, buf, 8);
}

static void doIp(unsigned char data[])
{
	unsigned char j, k;
	unsigned char val;
	unsigned char buf[8];
	unsigned char *p;
	unsigned char i = 8;
	get_random_bytes(buf, sizeof(buf));

	for(i = 0; i < 8; i++)
	{
		val = data[i];
		p = &buf[3];
		j = 4;

		do
		{
			for(k = 0; k <= 4; k += 4)
			{
				p[k] >>= 1;
				if(val & 1) { p[k] |= 0x80; }
				val >>= 1;
			}
			p--;
		}
		while(--j);
	}

	memcpy(data, buf, 8);
}

static void doIp_1(unsigned char data[])
{
	unsigned char j, k;
	unsigned char r = 0;
	unsigned char buf[8];
	unsigned char *p;
	unsigned char i = 8;

	for(i = 0; i < 8; i++)
	{
		p = &data[3];
		j = 4;

		do
		{
			for(k = 0; k <= 4; k += 4)
			{
				r >>= 1;
				if(p[k] & 1) { r |= 0x80; }
				p[k] >>= 1;
			}
			p--;
		}
		while(--j);
		buf[i] = r;
	}

	memcpy(data, buf, 8);
}



static void makeK(unsigned char *left, unsigned char *right, unsigned char *K)
{
	unsigned char i, j;
	unsigned char bit, val;
	unsigned char *p;

	for(i = 0; i < 8; i++)
	{
		val = 0;
		for(j = 0; j < 6; j++)
		{
			bit = PC2[i][j];
			if(bit < 29)
			{
				bit = 28 - bit;
				p   = left;
			}
			else
			{
				bit = 56 - bit;
				p   = right;
			}
			val <<= 1;
			if(p[bit >> 3] & (1 << (bit & 7))) { val |= 1; }
		}
		*K = val;
		K++;
	}
}

static void rightRot(unsigned char key[])
{
	unsigned char *p     = key;
	unsigned char  i     = 3;
	unsigned char  carry = 0;

	carry = 0;

	if(*p & 1) { carry = 0x08; }

	do
	{
		*p = (*p >> 1) | ((p[1] & 1) ? 0x80 : 0);
		p++;
	}
	while(--i);

	*p = (*p >> 1) | carry;
}

static void rightRotKeys(unsigned char left[], unsigned char right[])
{
	rightRot(left);
	rightRot(right);
}

static void leftRot(unsigned char key[])
{
	unsigned char i = 27;

	do
	{
		rightRot(key);
	}
	while(--i);
}

static void leftRotKeys(unsigned char left[], unsigned char right[])
{
	leftRot(left);
	leftRot(right);
}

static void desCore(unsigned char data[], unsigned char K[], unsigned char result[])
{
	unsigned char i, j;
	unsigned char bit, val;

	memset(result, 0, 4);

	for(i = 0; i < 8; i++)
	{
		val = 0;
		for(j = 0; j < 6; j++)
		{
			bit = 32 - E[i][j];
			val <<= 1;
			if(data[3 - (bit >> 3)] & (1 << (bit & 7))) { val |= 1; }
		}
		val ^= K[i];
		val  = SBOXES[i & 3][val];
		if(i > 3)
		{
			val >>= 4;
		}
		val &= 0x0f;
		result[i >> 1] |= (i & 1) ? val : (val << 4);
	}
}

static void permut32(unsigned char data[])
{
	unsigned char i, j;
	unsigned char bit;
	unsigned char r[4] = {0}; // init to keep Valgrind happy
	unsigned char *p;

	for(i = 0; i < 32; i++)
	{
		bit = 32 - P[i];
		p = r;
		for(j = 0; j < 3; j++)
		{
			*p = (*p << 1) | ((p[1] & 0x80) ? 1 : 0);
			p++;
		}
		*p <<= 1;
		if(data[3 - (bit >> 3)] & (1 << (bit & 7))) { *p |= 1; }
	}

	memcpy(data, r, 4);
}

static void swap(unsigned char left[], unsigned char right[])
{
	unsigned char x[4];

	memcpy(x, right, 4);
	memcpy(right, left, 4);
	memcpy(left, x, 4);
}

static void desRound(unsigned char left[], unsigned char right[], unsigned char data[], unsigned char mode, unsigned char k8)
{
	unsigned char i;
	unsigned char K[8];
	unsigned char r[4];
	unsigned char tempr[4];
	unsigned short temp;

	memcpy(tempr, data + 4, 4);

	/* Viaccess */
	temp = (short)k8 * (short)tempr[0] + (short)k8 + (short)tempr[0];
	tempr[0] = (temp & 0xff) - ((temp >> 8) & 0xff);
	if((temp & 0xff) - (temp >> 8) < 0)
		{ tempr[0]++; }

	makeK(left, right, K);
	desCore(tempr, K, r);
	permut32(r);

	if(mode & DES_HASH)
	{
		i    = r[0];
		r[0] = r[1];
		r[1] = i;
	}

	for(i = 0; i < 4; i++)
	{
		*data ^= r[i];
		data++;
	}

	swap(data - 4, data);
}

void des(unsigned char key[], unsigned char mode, unsigned char data[])
{
	unsigned char i;
	unsigned char left[8];
	unsigned char right[8];
	unsigned char *p = left;

	short DESShift = (mode & DES_RIGHT) ? 0x8103 : 0xc081;

	for(i = 3; i > 0; i--)
	{
		*p = (key[i - 1] << 4) | (key[i] >> 4);
		p++;
	}
	left[3] =  key[0] >> 4;
	right[0] = key[6];
	right[1] = key[5];
	right[2] = key[4];
	right[3] = key[3] & 0x0f;

	if(mode & DES_IP) { doIp(data); }

	do
	{
		if(!(mode & DES_RIGHT))
		{
			leftRotKeys(left, right);
			if(!(DESShift & 0x8000)) { leftRotKeys(left, right); }
		}
		desRound(left, right, data, mode, key[7]);

		if(mode & DES_RIGHT)
		{
			rightRotKeys(left, right);
			if(!(DESShift & 0x8000)) { rightRotKeys(left, right); }
		}
		DESShift <<= 1;
	}
	while(DESShift);

	swap(data, data + 4);
	if(mode & DES_IP_1) { doIp_1(data); }

}

static unsigned char getmask(unsigned char *OutData, unsigned char *Mask, unsigned char I, unsigned char J)
{
	unsigned char K, B, M, M1 , D, DI, MI;

	K = I ^ J;
	DI = 7;
	if((K & 4) == 4)
	{
		K ^= 7;
		DI ^= 7;
	}
	MI = 3;
	MI &= J;
	K ^= MI;
	K += MI;
	if((K & 4) == 4)
	{
		return 0;
	}
	DI ^= J;
	D = OutData[DI];
	MI = 0;
	MI += J;
	M1 = Mask[MI];
	MI ^= 4;
	M = Mask[MI];
	B = 0;
	for(K = 0; K <= 7; K++)
	{
		if((D & 1) == 1) { B += M; }
		D = (D >> 1) + ((B & 1) << 7);
		B = B >> 1;
	}
	return D ^ M1;
}

static void v2mask(unsigned char *cw, unsigned char *mask)
{
	int i, j;

	for(i = 7; i >= 0; i--)
		for(j = 7; j >= 4; j--)
			{ cw[i] ^= getmask(cw, mask, i, j); }
	for(i = 0; i <= 7; i++)
		for(j = 0; j <= 3; j++)
			{ cw[i] ^= getmask(cw, mask, i, j); }
}


static void EuroDes(unsigned char key1[], unsigned char key2[], unsigned char desMode, unsigned char operatingMode, unsigned char data[])
{
	unsigned char mode;

	if(key1[7])   /* Viaccess */
	{
		mode = (operatingMode == HASH) ? DES_ECM_HASH : DES_ECM_CRYPT;

		if(key2 != NULL)
			{ v2mask(data, key2); }
		des(key1, mode, data);
		if(key2 != NULL)
			{ v2mask(data, key2); }
	}
	else if(TestBit(desMode, F_TRIPLE_DES))
	{
		/* Eurocrypt 3-DES */
		mode = (operatingMode == HASH) ?  0 : DES_RIGHT;
		des(key1, (unsigned char)(DES_IP | mode), data);

		mode ^= DES_RIGHT;
		des(key2, mode, data);

		mode ^= DES_RIGHT;
		des(key1, (unsigned char)(mode | DES_IP_1), data);
	}
	else
	{
		if(TestBit(desMode, F_EURO_S2))
		{
			/* Eurocrypt S2 */
			mode = (operatingMode == HASH) ? DES_ECS2_CRYPT : DES_ECS2_DECRYPT;
		}
		else
		{
			/* Eurocrypt M */
			mode = (operatingMode == HASH) ? DES_ECM_HASH : DES_ECM_CRYPT;
		}
		des(key1, mode, data);
	}
}

/*------------------------------------------------------------------------*/
static void des_key_parity_adjust(unsigned char *key, unsigned char len)
{
	unsigned char i, j, parity;

	for(i = 0; i < len; i++)
	{
		parity = 1;
		for(j = 1; j < 8; j++) if((key[i] >> j) & 0x1) { parity = ~parity & 0x01; }
		key[i] |= parity;
	}
}

static unsigned char *des_key_spread(unsigned char *normal, unsigned char *spread)
{
	spread[ 0] = normal[ 0] & 0xfe;
	spread[ 1] = ((normal[ 0] << 7) | (normal[ 1] >> 1)) & 0xfe;
	spread[ 2] = ((normal[ 1] << 6) | (normal[ 2] >> 2)) & 0xfe;
	spread[ 3] = ((normal[ 2] << 5) | (normal[ 3] >> 3)) & 0xfe;
	spread[ 4] = ((normal[ 3] << 4) | (normal[ 4] >> 4)) & 0xfe;
	spread[ 5] = ((normal[ 4] << 3) | (normal[ 5] >> 5)) & 0xfe;
	spread[ 6] = ((normal[ 5] << 2) | (normal[ 6] >> 6)) & 0xfe;
	spread[ 7] = normal[ 6] << 1;
	spread[ 8] = normal[ 7] & 0xfe;
	spread[ 9] = ((normal[ 7] << 7) | (normal[ 8] >> 1)) & 0xfe;
	spread[10] = ((normal[ 8] << 6) | (normal[ 9] >> 2)) & 0xfe;
	spread[11] = ((normal[ 9] << 5) | (normal[10] >> 3)) & 0xfe;
	spread[12] = ((normal[10] << 4) | (normal[11] >> 4)) & 0xfe;
	spread[13] = ((normal[11] << 3) | (normal[12] >> 5)) & 0xfe;
	spread[14] = ((normal[12] << 2) | (normal[13] >> 6)) & 0xfe;
	spread[15] = normal[13] << 1;

	des_key_parity_adjust(spread, 16);
	return spread;
}

static void des_random_get(unsigned char *buffer, unsigned char len)
{
	unsigned char idx = 0;
	int randomNo = 0;

	for(idx = 0; idx < len; idx++)
	{
		if(!(idx % 3)) { randomNo = rand(); }
		buffer[idx] = (randomNo >> ((idx % 3) << 3)) & 0xff;
	}
}

#define MSGSIZE 400 //csp 0.8.9 (default: 400). This is CWS_NETMSGSIZE. The old default was 240

int des_encrypt(unsigned char *buffer, int len, unsigned char *deskey)
{
	unsigned char checksum = 0;
	unsigned char noPadBytes;
	unsigned char padBytes[7];
	char ivec[8];
	short i;

	if(!deskey) { return len; }
	noPadBytes = (8 - ((len - 1) % 8)) % 8;
	if(len + noPadBytes + 1 >= MSGSIZE - 8) { return -1; }
	des_random_get(padBytes, noPadBytes);
	for(i = 0; i < noPadBytes; i++) { buffer[len++] = padBytes[i]; }
	for(i = 2; i < len; i++) { checksum ^= buffer[i]; }
	buffer[len++] = checksum;
	des_random_get((unsigned char *)ivec, 8);
	memcpy(buffer + len, ivec, 8);
	for(i = 2; i < len; i += 8)
	{
		unsigned char j;
		const unsigned char flags = (1 << F_EURO_S2) | (1 << F_TRIPLE_DES);
		for(j = 0; j < 8; j++) { buffer[i + j] ^= ivec[j]; }
		EuroDes(deskey, deskey + 8, flags, HASH, buffer + i);
		memcpy(ivec, buffer + i, 8);
	}
	len += 8;
	return len;
}

int des_decrypt(unsigned char *buffer, int len, unsigned char *deskey)
{
	char ivec[8];
	char nextIvec[8];
	int i;
	unsigned char checksum = 0;

	if(!deskey) { return len; }
	if((len - 2) % 8 || (len - 2) < 16) { return -1; }
	len -= 8;
	memcpy(nextIvec, buffer + len, 8);
	for(i = 2; i < len; i += 8)
	{
		unsigned char j;
		const unsigned char flags = (1 << F_EURO_S2) | (1 << F_TRIPLE_DES);

		memcpy(ivec, nextIvec, 8);
		memcpy(nextIvec, buffer + i, 8);
		EuroDes(deskey, deskey + 8, flags, CRYPT, buffer + i);
		for(j = 0; j < 8; j++)
			{ buffer[i + j] ^= ivec[j]; }
	}
	for(i = 2; i < len; i++) { checksum ^= buffer[i]; }
	if(checksum) { return -1; }
	return len;
}

unsigned char *des_login_key_get(unsigned char *key1, unsigned char *key2, int len, unsigned char *des16)
{
	unsigned char des14[14];
	int i;

	memcpy(des14, key1, sizeof(des14));
	for(i = 0; i < len; i++) { des14[i % 14] ^= key2[i]; }
	des16 = des_key_spread(des14, des16);
	doPC1(des16);
	doPC1(des16 + 8);
	return des16;
}
