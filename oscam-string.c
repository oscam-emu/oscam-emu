#include "globals.h"
#include "oscam-string.h"

/* This function encapsulates malloc. It automatically adds an error message
   to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
   result will be automatically filled with the new memory position or NULL
   on failure. */
bool cs_malloc(void *result, size_t size)
{
	void **tmp = result;
	*tmp = malloc(size);
	if(*tmp == NULL)
	{
		fprintf(stderr, "%s: ERROR: Can't allocate %zu bytes!", __func__, size);
	}
	else
	{
		memset(*tmp, 0, size);
	}
	return !!*tmp;
}

/* This function encapsulates realloc. It automatically adds an error message
   to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
   result will be automatically filled with the new memory position or NULL
   on failure. If a failure occured, the existing memory in result will
   be freed. */
bool cs_realloc(void *result, size_t size)
{
	void **tmp = result, **tmp2 = result;
	*tmp = realloc(*tmp, size);
	if(*tmp == NULL)
	{
		fprintf(stderr, "%s: ERROR: Can't allocate %zu bytes!", __func__, size);
		free(*tmp2);
	}
	return !!*tmp;
}

/* Allocates a new empty string and copies str into it. You need to free() the result. */
char *cs_strdup(const char *str)
{
	char *newstr;
	if(!str)
		{ return NULL; }
	if(cs_malloc(&newstr, strlen(str) + 1))
	{
		strncpy(newstr, str, strlen(str));
		return newstr;
	}
	return NULL;
}

/* Ordinary strncpy does not terminate the string if the source is exactly
   as long or longer as the specified size. This can raise security issues.
   This function is a replacement which makes sure that a \0 is always added.
   num should be the real size of char array (do not subtract -1). */
void cs_strncpy(char *destination, const char *source, size_t num)
{
	if(!source)
	{
		destination[0] = '\0';
		return;
	}
	uint32_t l, size = strlen(source);
	if(size > num - 1)
		{ l = num - 1; }
	else
		{ l = size; }
	memcpy(destination, source, l);
	destination[l] = '\0';
}

/* Converts the string txt to it's lower case representation. */
char *strtolower(char *txt)
{
	char *p;
	for(p = txt; *p; p++)
	{
		if(isupper((uchar)*p))
			{ *p = tolower((uchar) * p); }
	}
	return txt;
}

/* Converts the string txt to it's upper case representation. */
char *strtoupper(char *txt)
{
	char *p;
	for(p = txt; *p; p++)
	{
		if(islower((uchar)*p))
			{ *p = toupper((uchar) * p); }
	}
	return txt;
}

char *trim(char *txt)
{
	int32_t l;
	char *p1, *p2;
	if(*txt == ' ')
	{
		for(p1 = p2 = txt; (*p1 == ' ') || (*p1 == '\t') || (*p1 == '\n') || (*p1 == '\r'); p1++)
			{ ; }
		while(*p1)
			{ *p2++ = *p1++; }
		*p2 = '\0';
	}
	l = strlen(txt);
	if(l > 0)
	{
		for(p1 = txt + l - 1; l > 0 && ((*p1 == ' ') || (*p1 == '\t') || (*p1 == '\n') || (*p1 == '\r')); *p1-- = '\0', l--)
			{ ; }
	}
	return txt;
}

char *remove_white_chars(char *txt)
{

	char *p1 = txt, *p2 = txt;

	if(NULL != p1)
	{
		while('\0' != *p1)
		{
			if((' '  != *p1) && ('\t' != *p1) &&
					('\n' != *p1) && ('\r' != *p1))
			{
				*p2++ = *p1;
			}
			p1++;
		}
		*p2 = '\0';
	}
	return txt;
}

bool streq(const char *s1, const char *s2)
{
	if(!s1 && s2) { return 0; }
	if(s1 && !s2) { return 0; }
	if(!s1 && !s2) { return 1; }
	return strcmp(s1, s2) == 0;
}

char *cs_hexdump(int32_t m, const uchar *buf, int32_t n, char *target, int32_t len)
{
	int32_t i = 0;
	target[0] = '\0';
	m = m ? 3 : 2;
	if(m * n >= len)
		{ n = (len / m) - 1; }
	while(i < n)
	{
		snprintf(target + (m * i), len - (m * i), "%02X%s", *buf++, m > 2 ? " " : "");
		i++;
	}
	return target;
}

int32_t gethexval(char c)
{
	if(c >= '0' && c <= '9') { return c - '0'; }
	if(c >= 'A' && c <= 'F') { return c - 'A' + 10; }
	if(c >= 'a' && c <= 'f') { return c - 'a' + 10; }
	return -1;
}

int32_t cs_atob(uchar *buf, char *asc, int32_t n)
{
	int32_t i, rc;
	for(i = 0; i < n; i++)
	{
		rc = (gethexval(asc[i << 1]) << 4) | gethexval(asc[(i << 1) + 1]);
		if(rc & 0x100)
			{ return -1; }
		buf[i] = rc;
	}
	return n;
}

uint32_t cs_atoi(char *asc, int32_t l, int32_t val_on_err)
{
	int32_t i, n = 0;
	uint32_t rc = 0;
	for(i = ((l - 1) << 1), errno = 0; i >= 0 && n < 4; i -= 2)
	{
		int32_t b = (gethexval(asc[i]) << 4) | gethexval(asc[i + 1]);
		if(b < 0)
		{
			errno = EINVAL;
			rc = val_on_err ? 0xFFFFFFFF : 0;
			break;
		}
		rc |= b << (n << 3);
		n++;
	}
	return rc;
}

int32_t byte_atob(char *asc)
{
	int32_t rc;
	if(strlen(trim(asc)) != 2)
	{
		rc = -1;
	}
	else
	{
		rc = (gethexval(asc[0]) << 4) | gethexval(asc[1]);
		if(rc & 0x100)
			{ rc = -1; }
	}
	return rc;
}

int32_t word_atob(char *asc)
{
	int32_t rc;
	if(strlen(trim(asc)) != 4)
	{
		rc = -1;
	}
	else
	{
		rc = gethexval(asc[0]) << 12 | gethexval(asc[1]) << 8 |
			 gethexval(asc[2]) << 4  | gethexval(asc[3]);
		if(rc & 0x10000)
			{ rc = -1; }
	}
	return rc;
}

/*
 * dynamic word_atob
 * converts an 1-4 digit asc hexstring
 */
int32_t dyn_word_atob(char *asc)
{
	int32_t rc = (-1);
	int32_t i, len = strlen(trim(asc));
	if(len <= 4 && len > 0)
	{
		for(i = 0, rc = 0; i < len; i++)
		{
			rc = rc << 4 | gethexval(asc[i]);
		}
		if(rc & 0x10000)
			{ rc = -1; }
	}
	return rc;
}

int32_t key_atob_l(char *asc, uchar *bin, int32_t l)
{
	int32_t i, n1, n2, rc;
	for(i = rc = 0; i < l; i += 2)
	{
		if((n1 = gethexval(asc[i  ])) < 0) { rc = -1; }
		if((n2 = gethexval(asc[i + 1])) < 0) { rc = -1; }
		bin[i >> 1] = (n1 << 4) + (n2 & 0xff);
	}
	return rc;
}

uint32_t b2i(int32_t n, const uchar *b)
{
	switch(n)
	{
	case 2:
		return (b[0] <<  8) |  b[1];
	case 3:
		return (b[0] << 16) | (b[1] <<  8) |  b[2];
	case 4:
		return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) & 0xffffffffL;
	default:
		cs_log("Error in b2i, n=%i", n);
	}
	return 0;
}

uint64_t b2ll(int32_t n, uchar *b)
{
	int32_t i;
	uint64_t k = 0;
	for(i = 0; i < n; k += b[i++])
		{ k <<= 8; }
	return k;
}

uchar *i2b_buf(int32_t n, uint32_t i, uchar *b)
{
	switch(n)
	{
	case 2:
		b[0] = (i >> 8) & 0xff;
		b[1] = (i) & 0xff;
		break;
	case 3:
		b[0] = (i >> 16) & 0xff;
		b[1] = (i >> 8) & 0xff;
		b[2] = (i) & 0xff;
	case 4:
		b[0] = (i >> 24) & 0xff;
		b[1] = (i >> 16) & 0xff;
		b[2] = (i >> 8) & 0xff;
		b[3] = (i) & 0xff;
		break;
	}
	return b;
}

uint32_t a2i(char *asc, int32_t bytes)
{
	int32_t i, n;
	uint32_t rc;
	for(rc = i = 0, n = strlen(trim(asc)) - 1; i < abs(bytes) << 1; n--, i++)
	{
		if(n >= 0)
		{
			int32_t rcl;
			if((rcl = gethexval(asc[n])) < 0)
			{
				errno = EINVAL;
				return 0x1f1f1f;
			}
			rc |= rcl << (i << 2);
		}
		else
		{
			if(bytes < 0)
				{ rc |= 0xf << (i << 2); }
		}
	}
	errno = 0;
	return rc;
}

int32_t boundary(int32_t exp, int32_t n)
{
	return (((n - 1) >> exp) + 1) << exp;
}

/* Checks an array if it is filled (a value > 0) and number of filled bytes.
   length specifies the maximum length to check for. */
int32_t check_filled(uchar *value, int32_t length)
{
	if(!value)
		{ return 0; }
	int32_t i, j = 0;
	for(i = 0; i < length; ++i)
	{
		if(value[i] > 0)
			{ j++; }
	}
	return j;
}

#define RAND_POOL_SIZE 64

// The last bytes are used to init random seed
static uint8_t rand_pool[RAND_POOL_SIZE + sizeof(uint32_t)];

void get_random_bytes_init(void)
{
	srand(time(NULL));
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
	{
		fd = open("/dev/random", O_RDONLY);
		if(fd < 0)
			{ return; }
	}
	if(read(fd, rand_pool, RAND_POOL_SIZE + sizeof(uint32_t)) > -1)
	{
		uint32_t *pool_seed = (uint32_t *)rand_pool + RAND_POOL_SIZE;
		srand(*pool_seed);
	}
	close(fd);
}

void get_random_bytes(uint8_t *dst, uint32_t dst_len)
{
	static uint32_t rand_pool_pos; // *MUST* be static
	uint32_t i;
	for(i = 0; i < dst_len; i++)
	{
		rand_pool_pos++; // Races are welcome...
		dst[i] = rand() ^ rand_pool[rand_pool_pos % RAND_POOL_SIZE];
	}
}

static unsigned long crc_table[256] =
{
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
	0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
	0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
	0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
	0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
	0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
	0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
	0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
	0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
	0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
	0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
	0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
	0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
	0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
	0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
	0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
	0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
	0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
	0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
	0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
	0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
	0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
	0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
	0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
	0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
	0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
	0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
	0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
	0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
	0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
	0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
	0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
	0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
	0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
	0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
	0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
	0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
	0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
	0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
	0x2d02ef8dL
};

/*
 * crc32 -- compute the CRC-32 of a data stream
 * Copyright (C) 1995-1996 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */
#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf) DO1(buf); DO1(buf);
#define DO4(buf) DO2(buf); DO2(buf);
#define DO8(buf) DO4(buf); DO4(buf);

unsigned long crc32(unsigned long crc, const unsigned char *buf, unsigned int len)
{
	if(!buf)
		{ return 0L; }
	crc = crc ^ 0xffffffffL;
	while(len >= 8)
	{
		DO8(buf);
		len -= 8;
	}
	if(len)
	{
		do
		{
			DO1(buf);
		}
		while(--len);
	}
	return crc ^ 0xffffffffL;
}

// https://en.wikipedia.org/wiki/Jenkins_hash_function
uint32_t jhash(const char *key, size_t len)
{
	uint32_t hash, i;
	for(hash = i = 0; i < len; i++)
	{
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

/* Converts a char to it's hex representation. See char_to_hex on how to use it. */
char to_hex(char code)
{
	static const char hex[] = "0123456789abcdef";
	return hex[(int)code & 15];
}

/* Converts a char array to a char array with hex values (needed for example for md5).
   Note that result needs to be at least (p_array_len * 2) + 1 large. */
void char_to_hex(const unsigned char *p_array, uint32_t p_array_len, unsigned char *result)
{
	result[p_array_len * 2] = '\0';
	const unsigned char *p_end = p_array + p_array_len;
	uint32_t pos = 0;
	const unsigned char *p;
	for(p = p_array; p != p_end; p++, pos += 2)
	{
		result[pos    ] = to_hex(*p >> 4);
		result[pos + 1] = to_hex(*p & 15);
	}
}

static inline unsigned char to_uchar(char ch)
{
	return ch;
}

void base64_encode(const char *in, size_t inlen, char *out, size_t outlen)
{
	static const char b64str[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	while(inlen && outlen)
	{
		*out++ = b64str[(to_uchar(in[0]) >> 2) & 0x3f];
		if(!--outlen) { break; }
		*out++ = b64str[((to_uchar(in[0]) << 4) + (--inlen ? to_uchar(in[1]) >> 4 : 0)) & 0x3f];
		if(!--outlen) { break; }
*out++ = (inlen ? b64str[((to_uchar(in[1]) << 2) + (--inlen ? to_uchar(in[2]) >> 6 : 0)) & 0x3f] : '=');
		if(!--outlen) { break; }
		*out++ = inlen ? b64str[to_uchar(in[2]) & 0x3f] : '=';
		if(!--outlen) { break; }
		if(inlen) { inlen--; }
		if(inlen) { in += 3; }
		if(outlen) { *out = '\0'; }
	}
}

size_t b64encode(const char *in, size_t inlen, char **out)
{
	size_t outlen = 1 + BASE64_LENGTH(inlen);
	if(inlen > outlen)
	{
		*out = NULL;
		return 0;
	}
	if(!cs_malloc(out, outlen))
		{ return -1; }
	base64_encode(in, inlen, *out, outlen);
	return outlen - 1;
}

static int8_t b64decoder[256];

/* Prepares the base64 decoding array */
void b64prepare(void)
{
	const unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int32_t i;
	for(i = sizeof(b64decoder) - 1; i >= 0; --i)
	{
		b64decoder[i] = -1;
	}

	for(i = sizeof(alphabet) - 1; i >= 0; --i)
	{
		b64decoder[alphabet[i]] = i;
	}
}

/* Decodes a base64-encoded string. The given array will be used directly for output and is thus modified! */
int32_t b64decode(unsigned char *result)
{
	int32_t i, len = strlen((char *)result), j = 0, bits = 0, char_count = 0;

	if(!b64decoder[0]) { b64prepare(); }

	for(i = 0; i < len; ++i)
	{
		if(result[i] == '=') { break; }
		int8_t tmp = b64decoder[result[i]];
		if(tmp == -1) { continue; }
		bits += tmp;
		++char_count;
		if(char_count == 4)
		{
			result[j++] = bits >> 16;
			result[j++] = (bits >> 8) & 0xff;
			result[j++] = bits & 0xff;
			bits = 0;
			char_count = 0;
		}
		else
		{
			bits <<= 6;
		}
	}
	if(i == len)
	{
		if(char_count)
		{
			result[j] = '\0';
			return 0;
		}
	}
	else
	{
		switch(char_count)
		{
		case 1:
			result[j] = '\0';
			return 0;
		case 2:
			result[j++] = bits >> 10;
			result[j] = '\0';
			break;
		case 3:
			result[j++] = bits >> 16;
			result[j++] = (bits >> 8) & 0xff;
			result[j] = '\0';
			break;
		}
	}
	return j;
}
