/* openssl_mods.h */
#ifndef _OPENSSL_MODSH
#define _OPENSSL_MODSH

#define OPENSSL_malloc(num)    CRYPTO_malloc((int)num,__FILE__,__LINE__)
#define OPENSSL_free(addr)     CRYPTO_free(addr)

void *CRYPTO_malloc(int num, const char *file, int line);
void CRYPTO_free(void *);

#endif
