/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "../headers/tomcrypt_private.h"

/**
  @file rsa_import.c
  Import a PKCS RSA key, Tom St Denis
*/

#ifdef LTC_MRSA

/**
  Import an RSAPublicKey or RSAPrivateKey [two-prime only, only support >= 1024-bit keys, defined in PKCS #1 v2.1]
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;
   void         *zero;
   unsigned char *tmpbuf=NULL;
   unsigned long tmpbuf_len, len;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if ((err = rsa_init(key)) != CRYPT_OK) {
      return err;
   }

   /* see if the OpenSSL DER format RSA public key will work */
   tmpbuf_len = inlen;
   tmpbuf = (unsigned char*)XCALLOC(1, tmpbuf_len);
   if (tmpbuf == NULL) {
       err = CRYPT_MEM;
       goto LBL_ERR;
   }

   len = 0;
   err = x509_decode_subject_public_key_info(in, inlen,
        PKA_RSA, tmpbuf, &tmpbuf_len,
        LTC_ASN1_NULL, NULL, &len);

   if (err == CRYPT_OK) { /* SubjectPublicKeyInfo format */

      /* now it should be SEQUENCE { INTEGER, INTEGER } */
      if ((err = der_decode_sequence_multi(tmpbuf, tmpbuf_len,
                                           LTC_ASN1_INTEGER, 1UL, key->N,
                                           LTC_ASN1_INTEGER, 1UL, key->e,
                                           LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      key->type = PK_PUBLIC;
      err = CRYPT_OK;
      goto LBL_FREE;
   }

   /* not SSL public key, try to match against PKCS #1 standards */
   err = der_decode_sequence_multi(in, inlen, LTC_ASN1_INTEGER, 1UL, key->N,
                                              LTC_ASN1_EOL,     0UL, NULL);

   if (err != CRYPT_OK && err != CRYPT_INPUT_TOO_LONG) {
      goto LBL_ERR;
   }

   if (mp_cmp_d(key->N, 0) == LTC_MP_EQ) {
      if ((err = mp_init(&zero)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      /* it's a private key */
      if ((err = der_decode_sequence_multi(in, inlen,
                          LTC_ASN1_INTEGER, 1UL, zero,
                          LTC_ASN1_INTEGER, 1UL, key->N,
                          LTC_ASN1_INTEGER, 1UL, key->e,
                          LTC_ASN1_INTEGER, 1UL, key->d,
                          LTC_ASN1_INTEGER, 1UL, key->p,
                          LTC_ASN1_INTEGER, 1UL, key->q,
                          LTC_ASN1_INTEGER, 1UL, key->dP,
                          LTC_ASN1_INTEGER, 1UL, key->dQ,
                          LTC_ASN1_INTEGER, 1UL, key->qP,
                          LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         mp_clear(zero);
         goto LBL_ERR;
      }
      mp_clear(zero);
      key->type = PK_PRIVATE;
   } else if (mp_cmp_d(key->N, 1) == LTC_MP_EQ) {
      /* we don't support multi-prime RSA */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   } else {
      /* it's a public key and we lack e */
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_INTEGER, 1UL, key->N,
                                     LTC_ASN1_INTEGER, 1UL, key->e,
                                     LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      key->type = PK_PUBLIC;
   }
   err = CRYPT_OK;
   goto LBL_FREE;

LBL_ERR:
   rsa_free(key);

LBL_FREE:
   if (tmpbuf != NULL) {
      XFREE(tmpbuf);
   }
   return err;
}

#endif /* LTC_MRSA */

