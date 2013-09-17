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
                
/* RC6 is parameterized for w-bit words, b bytes of key, and
 * r rounds.  The AES version of RC6 specifies b=16, 24, or 32;
 * w=32; and r=20.
 */

#define rc6keylen 44

typedef unsigned int RC6KEY[rc6keylen];

/*
 * K=plain key
 * b=plain key len
 * S=prepared key by setup
 * pt=uncrypted data
 * ct=crypted data
 * block size is always 16bytes
 */
void rc6_key_setup(unsigned char *K, int b, RC6KEY S);
void rc6_block_encrypt(unsigned int *pt, unsigned int *ct, int block_count, RC6KEY S);
void rc6_block_decrypt(unsigned int *ct, unsigned int *pt, int block_count, RC6KEY S);
