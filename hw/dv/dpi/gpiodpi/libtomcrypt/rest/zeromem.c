/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "../headers/tomcrypt_private.h"

/**
   @file zeromem.c
   Zero a block of memory, Tom St Denis
*/

/**
   Zero a block of memory
   @param out    The destination of the area to zero
   @param outlen The length of the area to zero (octets)
*/
void zeromem(volatile void *out, size_t outlen)
{
   volatile char *mem = (volatile char*)out;

   while (outlen-- > 0) {
      *mem++ = '\0';
   }
}
