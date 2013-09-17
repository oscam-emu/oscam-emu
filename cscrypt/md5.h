#ifndef _CSCRYPT_MD5_H
#define _CSCRYPT_MD5_H

#if defined(WITH_SSL) || defined(WITH_LIBCRYPTO)
#  include <openssl/md5.h>
#else
#define MD5_DIGEST_LENGTH 16

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output_hash);
#endif

char * __md5_crypt(const char *text_pass, const char *salt, char *crypted_passwd);

#endif
