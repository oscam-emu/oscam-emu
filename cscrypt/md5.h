#ifndef _CSCRYPT_MD5_H
#define _CSCRYPT_MD5_H

#if defined(WITH_SSL) || defined(WITH_LIBCRYPTO)
#  include <openssl/md5.h>
#else
#define MD5_DIGEST_LENGTH 16

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output_hash);
#endif

typedef struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
} MD5_CTX;

char * __md5_crypt(const char *text_pass, const char *salt, char *crypted_passwd);
void MD5_Init(MD5_CTX *ctx);
void MD5_Update(MD5_CTX *ctx, const unsigned char *buf, unsigned int len);
void MD5_Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx);

#endif
