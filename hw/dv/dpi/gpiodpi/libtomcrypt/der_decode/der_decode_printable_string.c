/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "../headers/tomcrypt_private.h"

/**
  @file der_decode_printable_string.c
  ASN.1 DER, encode a printable STRING, Tom St Denis
*/


#ifdef LTC_DER

/**
  Store a printable STRING
  @param in      The DER encoded printable STRING
  @param inlen   The size of the DER printable STRING
  @param out     [out] The array of octets stored (one per char)
  @param outlen  [in/out] The number of octets stored
  @return CRYPT_OK if successful
*/
int der_decode_printable_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;
   int           t, err;



   /* must have header at least */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check for 0x13 */
   if ((in[0] & 0x1F) != 0x13) {
      return CRYPT_INVALID_PACKET;
   }
   x = 1;

   /* get the length of the data */
   y = inlen - x;
   if ((err = der_decode_asn1_length(in + x, &y, &len)) != CRYPT_OK) {
      return err;
   }
   x += y;

   /* is it too long? */
   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (len > (inlen - x)) {
      return CRYPT_INVALID_PACKET;
   }

   /* read the data */
   for (y = 0; y < len; y++) {
       t = der_printable_value_decode(in[x++]);
       if (t == -1) {
           return CRYPT_INVALID_ARG;
       }
       out[y] = t;
   }

   *outlen = y;

   return CRYPT_OK;
}

#endif
