/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "../headers/tomcrypt_private.h"

/**
  @file der_decode_bit_string.c
  ASN.1 DER, encode a BIT STRING, Tom St Denis
*/


#ifdef LTC_DER

#define SETBIT(v, n)    (v=((unsigned char)(v) | (1U << (unsigned char)(n))))
#define CLRBIT(v, n)    (v=((unsigned char)(v) & ~(1U << (unsigned char)(n))))

/**
  Store a BIT STRING
  @param in      The DER encoded BIT STRING
  @param inlen   The size of the DER BIT STRING
  @param out     [out] The array of bits stored (8 per char)
  @param outlen  [in/out] The number of bits stored
  @return CRYPT_OK if successful
*/
int der_decode_raw_bit_string(const unsigned char *in,  unsigned long inlen,
                                unsigned char *out, unsigned long *outlen)
{
   unsigned long dlen, blen, x, y;
   int err;



   /* packet must be at least 4 bytes */
   if (inlen < 4) {
       return CRYPT_INVALID_ARG;
   }

   /* check for 0x03 */
   if ((in[0]&0x1F) != 0x03) {
      return CRYPT_INVALID_PACKET;
   }

   /* offset in the data */
   x = 1;

   /* get the length of the data */
   y = inlen - 1;
   if ((err = der_decode_asn1_length(in + x, &y, &dlen)) != CRYPT_OK) {
      return err;
   }
   x += y;
   /* is the data len too long or too short? */
   if ((dlen == 0) || (dlen > (inlen - x))) {
       return CRYPT_INVALID_PACKET;
   }

   /* get padding count */
   blen = ((dlen - 1) << 3) - (in[x++] & 7);

   /* too many bits? */
   if (blen > *outlen) {
      *outlen = blen;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* decode/store the bits */
   for (y = 0; y < blen; y++) {
      if (in[x] & (1 << (7 - (y & 7)))) {
         SETBIT(out[y/8], 7-(y%8));
      } else {
         CLRBIT(out[y/8], 7-(y%8));
      }
      if ((y & 7) == 7) {
         ++x;
      }
   }

   /* we done */
   *outlen = blen;
   return CRYPT_OK;
}

#endif
