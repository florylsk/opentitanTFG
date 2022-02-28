/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#define DESC_DEF_ONLY
#include "tomcrypt_private.h"

#ifdef LTM_DESC

#include <tommath.h>
#if !defined(PRIVATE_MP_WARRAY) && !defined(BN_MP_PRIME_IS_PRIME_C)
#include <stdbool.h>
#endif

static const struct {
    mp_err mpi_code;
    int ltc_code;
} mpi_to_ltc_codes[] = {
   { MP_OKAY ,  CRYPT_OK},
   { MP_MEM  ,  CRYPT_MEM},
   { MP_VAL  ,  CRYPT_INVALID_ARG},
#if defined(MP_BUF) || defined(MP_USE_ENUMS)
   { MP_ITER ,  CRYPT_INVALID_PACKET},
   { MP_BUF  ,  CRYPT_BUFFER_OVERFLOW},
#endif
};

/**
   Convert a MPI error to a LTC error (Possibly the most powerful function ever!  Oh wait... no)
   @param err    The error to convert
   @return The equivalent LTC error code or CRYPT_ERROR if none found
*/
static int mpi_to_ltc_error(mp_err err)
{
   size_t x;

   for (x = 0; x < sizeof(mpi_to_ltc_codes)/sizeof(mpi_to_ltc_codes[0]); x++) {
       if (err == mpi_to_ltc_codes[x].mpi_code) {
          return mpi_to_ltc_codes[x].ltc_code;
       }
   }
   return CRYPT_ERROR;
}

static int init_mpi(void **a)
{
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(mp_int));
   if (*a == NULL) {
      return CRYPT_MEM;
   } else {
      return CRYPT_OK;
   }
}

static int init(void **a)
{
   int err;

   LTC_ARGCHK(a != NULL);

   if ((err = init_mpi(a)) != CRYPT_OK) {
      return err;
   }
   if ((err = mpi_to_ltc_error(mp_init((mp_int*)*a))) != CRYPT_OK) {
      XFREE(*a);
   }
   return err;
}

static void deinit(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   mp_clear((mp_int*)a);
   XFREE(a);
}

static int neg(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_neg((const mp_int*)a, (mp_int*)b));
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_copy((const mp_int*)a, (mp_int*)b));
}

static int init_copy(void **a, void *b)
{
   int err;
   LTC_ARGCHK(a  != NULL);
   LTC_ARGCHK(b  != NULL);
   if ((err = init_mpi(a)) != CRYPT_OK) return err;
   return mpi_to_ltc_error(mp_init_copy((mp_int*)*a, (const mp_int*)b));
}

/* ---- trivial ---- */
static int set_int(void *a, ltc_mp_digit b)
{
   LTC_ARGCHK(a != NULL);
#ifdef BN_MP_SET_INT_C
   return mpi_to_ltc_error(mp_set_int(a, b));
#else
   mp_set_u32((mp_int*)a, b);
   return CRYPT_OK;
#endif
}

static unsigned long get_int(void *a)
{
   LTC_ARGCHK(a != NULL);
#ifdef BN_MP_GET_INT_C
   return mp_get_int(a);
#else
   return mp_get_ul((const mp_int*)a);
#endif
}

static ltc_mp_digit get_digit(void *a, int n)
{
   mp_int *A;
   LTC_ARGCHK(a != NULL);
   A = (mp_int*)a;
   return (n >= A->used || n < 0) ? 0 : A->dp[n];
}

static int get_digit_count(void *a)
{
   mp_int *A;
   LTC_ARGCHK(a != NULL);
   A =(mp_int*) a;
   return A->used;
}

static int compare(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   switch (mp_cmp((const mp_int*)a, (const mp_int*)b)) {
      case MP_LT: return LTC_MP_LT;
      case MP_EQ: return LTC_MP_EQ;
      case MP_GT: return LTC_MP_GT;
      default:    return 0;
   }
}

static int compare_d(void *a, ltc_mp_digit b)
{
   LTC_ARGCHK(a != NULL);
   switch (mp_cmp_d((const mp_int*)a, b)) {
      case MP_LT: return LTC_MP_LT;
      case MP_EQ: return LTC_MP_EQ;
      case MP_GT: return LTC_MP_GT;
      default:    return 0;
   }
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mp_count_bits((const mp_int*)a);
}

static int count_lsb_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mp_cnt_lsb((const mp_int*)a);
}


static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   return mpi_to_ltc_error(mp_2expt((mp_int*)a, n));
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_read_radix((mp_int*)a, b, radix));
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
#ifdef BN_MP_TORADIX_C
   return mpi_to_ltc_error(mp_toradix(a, b, radix));
#else
   return mpi_to_ltc_error(mp_to_radix((const mp_int*)a, b, SIZE_MAX, NULL, radix));
#endif
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   LTC_ARGCHK(a != NULL);
#ifdef BN_MP_UNSIGNED_BIN_SIZE_C
   return mp_unsigned_bin_size(a);
#else
   return (unsigned long)mp_ubin_size((const mp_int*)a);
#endif
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
#ifdef BN_MP_TO_UNSIGNED_BIN_C
   return mpi_to_ltc_error(mp_to_unsigned_bin(a, b));
#else
   return mpi_to_ltc_error(mp_to_ubin((const mp_int*)a, b, SIZE_MAX, NULL));
#endif
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
#ifdef BN_MP_READ_UNSIGNED_BIN_C
   return mpi_to_ltc_error(mp_read_unsigned_bin(a, b, len));
#else
   return mpi_to_ltc_error(mp_from_ubin((mp_int*)a, b, (size_t)len));
#endif
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_add((const mp_int*)a,(const mp_int*) b, (mp_int*)c));
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_add_d((const mp_int*)a, b, (mp_int*)c));
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sub((const mp_int*)a,(const mp_int*) b,(mp_int*) c));
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sub_d((const mp_int*)a, b, (mp_int*)c));
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_mul((const mp_int*)a,(const mp_int*) b,(mp_int*) c));
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_mul_d((const mp_int*)a, b,(mp_int*) c));
}

/* sqr */
static int sqr(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_sqr((const mp_int*)a, (mp_int*)b));
}

/* sqrtmod_prime */
static int sqrtmod_prime(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sqrtmod_prime((const mp_int*)a,(const mp_int*) b, (mp_int*)c));
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_div((const mp_int*)a, (const mp_int*)b,(mp_int*) c,(mp_int*) d));
}

static int div_2(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_div_2((const mp_int*)a, (mp_int*)b));
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
   mp_digit tmp;
   int      err;

   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);

   if ((err = mpi_to_ltc_error(mp_mod_d((const mp_int*)a, b, &tmp))) != CRYPT_OK) {
      return err;
   }
   *c = tmp;
   return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_gcd((const mp_int*)a, (const mp_int*)b,(mp_int*) c));
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_lcm((const mp_int*)a,(const mp_int*) b,(mp_int*) c));
}

static int addmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_addmod((const mp_int*)a,(const mp_int*)b,(const mp_int*)c,(mp_int*)d));
}

static int submod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_submod((const mp_int*)a,(const mp_int*)b,(const mp_int*)c,(mp_int*)d));
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_mulmod((const mp_int*)a,(const mp_int*)b,(const mp_int*)c,(mp_int*)d));
}

static int sqrmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sqrmod((const mp_int*)a,(const mp_int*)b,(mp_int*)c));
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_invmod((const mp_int*)a, (const mp_int*)b, (mp_int*)c));
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
   int err;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = XCALLOC(1, sizeof(mp_digit));
   if (*b == NULL) {
      return CRYPT_MEM;
   }
   if ((err = mpi_to_ltc_error(mp_montgomery_setup((const mp_int*)a, (mp_digit *)*b))) != CRYPT_OK) {
      XFREE(*b);
   }
   return err;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_montgomery_calc_normalization((mp_int*)a, (const mp_int*)b));
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_montgomery_reduce((mp_int*)a, (const mp_int*)b, *((mp_digit *)c)));
}

/* clean up */
static void montgomery_deinit(void *a)
{
   XFREE(a);
}

static int exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_exptmod((const mp_int*)a,(const mp_int*)b,(const mp_int*)c,(mp_int*)d));
}

static int isprime(void *a, int b, int *c)
{
   int err;
#if defined(PRIVATE_MP_WARRAY) || defined(BN_MP_PRIME_IS_PRIME_C)
   int res;
#else
   bool res;
#endif
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   b = mp_prime_rabin_miller_trials(mp_count_bits((const mp_int*)a));
   err = mpi_to_ltc_error(mp_prime_is_prime((const mp_int*)a, b, &res));
   *c = res ? LTC_MP_YES : LTC_MP_NO;
   return err;
}

static int set_rand(void *a, int size)
{
   LTC_ARGCHK(a != NULL);
   return mpi_to_ltc_error(mp_rand((mp_int*)a, size));
}

#ifndef MP_DIGIT_BIT
#define MP_DIGIT_BIT DIGIT_BIT
#endif

const ltc_math_descriptor ltm_desc = {

   "LibTomMath",
   (int)MP_DIGIT_BIT,

   &init,
   &init_copy,
   &deinit,

   &neg,
   &copy,

   &set_int,
   &get_int,
   &get_digit,
   &get_digit_count,
   &compare,
   &compare_d,
   &count_bits,
   &count_lsb_bits,
   &twoexpt,

   &read_radix,
   &write_radix,
   &unsigned_size,
   &unsigned_write,
   &unsigned_read,

   &add,
   &addi,
   &sub,
   &subi,
   &mul,
   &muli,
   &sqr,
   &sqrtmod_prime,
   &divide,
   &div_2,
   &modi,
   &gcd,
   &lcm,

   &mulmod,
   &sqrmod,
   &invmod,

   &montgomery_setup,
   &montgomery_normalization,
   &montgomery_reduce,
   &montgomery_deinit,

   &exptmod,
   &isprime,

#ifdef LTC_MECC
#ifdef LTC_MECC_FP
   &ltc_ecc_fp_mulmod,
#else
   &ltc_ecc_mulmod,
#endif
   &ltc_ecc_projective_add_point,
   &ltc_ecc_projective_dbl_point,
   &ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
   &ltc_ecc_fp_mul2add,
#else
   &ltc_ecc_mul2add,
#endif /* LTC_MECC_FP */
#else
   NULL,
#endif /* LTC_ECC_SHAMIR */
#else
   NULL, NULL, NULL, NULL, NULL,
#endif /* LTC_MECC */

#ifdef LTC_MRSA
   &rsa_make_key,
   &rsa_exptmod,
#else
   NULL, NULL,
#endif
   &addmod,
   &submod,

   &set_rand,

};


#endif
