/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#define DESC_DEF_ONLY
#include "tomcrypt_private.h"

#ifdef TFM_DESC

#include <tfm.h>

static const struct {
    int tfm_code, ltc_code;
} tfm_to_ltc_codes[] = {
   { FP_OKAY ,  CRYPT_OK},
   { FP_MEM  ,  CRYPT_MEM},
   { FP_VAL  ,  CRYPT_INVALID_ARG},
};

/**
   Convert a tfm error to a LTC error (Possibly the most powerful function ever!  Oh wait... no)
   @param err    The error to convert
   @return The equivalent LTC error code or CRYPT_ERROR if none found
*/
static int tfm_to_ltc_error(int err)
{
   int x;

   for (x = 0; x < (int)(sizeof(tfm_to_ltc_codes)/sizeof(tfm_to_ltc_codes[0])); x++) {
       if (err == tfm_to_ltc_codes[x].tfm_code) {
          return tfm_to_ltc_codes[x].ltc_code;
       }
   }
   return CRYPT_ERROR;
}

static int init(void **a)
{
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(fp_int));
   if (*a == NULL) {
      return CRYPT_MEM;
   }
   fp_init(*a);
   return CRYPT_OK;
}

static void deinit(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   XFREE(a);
}

static int neg(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_neg(((fp_int*)a), ((fp_int*)b));
   return CRYPT_OK;
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_copy(a, b);
   return CRYPT_OK;
}

static int init_copy(void **a, void *b)
{
   if (init(a) != CRYPT_OK) {
      return CRYPT_MEM;
   }
   return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, ltc_mp_digit b)
{
   LTC_ARGCHK(a != NULL);
   fp_set((fp_int*)a, b);
   return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A =(fp_int*) a;
   return A->used > 0 ? A->dp[0] : 0;
}

static ltc_mp_digit get_digit(void *a, int n)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A = (fp_int*)a;
   return (n >= A->used || n < 0) ? 0 : A->dp[n];
}

static int get_digit_count(void *a)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A =(fp_int*) a;
   return A->used;
}

static int compare(void *a, void *b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   ret = fp_cmp((fp_int*)a, (fp_int*)b);
   switch (ret) {
      case FP_LT: return LTC_MP_LT;
      case FP_EQ: return LTC_MP_EQ;
      case FP_GT: return LTC_MP_GT;
   }
   return 0;
}

static int compare_d(void *a, ltc_mp_digit b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   ret = fp_cmp_d((fp_int*)a, b);
   switch (ret) {
      case FP_LT: return LTC_MP_LT;
      case FP_EQ: return LTC_MP_EQ;
      case FP_GT: return LTC_MP_GT;
   }
   return 0;
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return fp_count_bits((fp_int*)a);
}

static int count_lsb_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return fp_cnt_lsb((fp_int*)a);
}

static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   fp_2expt((fp_int*)a, n);
   return CRYPT_OK;
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_read_radix((fp_int*)a, (char *)b, radix));
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_toradix((fp_int*)a, b, radix));
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   LTC_ARGCHK(a != NULL);
   return fp_unsigned_bin_size((fp_int*)a);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_to_unsigned_bin((fp_int*)a, b);
   return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_read_unsigned_bin((fp_int*)a, b, len);
   return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_add((fp_int*)a,(fp_int*) b, (fp_int*)c);
   return CRYPT_OK;
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_add_d((fp_int*)a, b, (fp_int*)c);
   return CRYPT_OK;
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_sub((fp_int*)a,(fp_int*) b,(fp_int*) c);
   return CRYPT_OK;
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_sub_d((fp_int*)a, b,(fp_int*) c);
   return CRYPT_OK;
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_mul((fp_int*)a,(fp_int*) b,(fp_int*) c);
   return CRYPT_OK;
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_mul_d((fp_int*)a, b,(fp_int*) c);
   return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_sqr((fp_int*)a,(fp_int*) b);
   return CRYPT_OK;
}

/* sqrtmod_prime - NOT SUPPORTED */

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_div((fp_int*)a,(fp_int*) b,(fp_int*) c,(fp_int*) d));
}

static int div_2(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_div_2((fp_int*)a,(fp_int*) b);
   return CRYPT_OK;
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
   fp_digit tmp;
   int      err;

   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);

   if ((err = tfm_to_ltc_error(fp_mod_d((fp_int*)a, b, &tmp))) != CRYPT_OK) {
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
   fp_gcd((fp_int*)a, (fp_int*)b, (fp_int*)c);
   return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_lcm((fp_int*)a,(fp_int*) b, (fp_int*)c);
   return CRYPT_OK;
}

static int addmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return tfm_to_ltc_error(fp_addmod((fp_int*)a,(fp_int*)b,(fp_int*)c,(fp_int*)d));
}

static int submod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return tfm_to_ltc_error(fp_submod((fp_int*)a,(fp_int*)b,(fp_int*)c,(fp_int*)d));
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return tfm_to_ltc_error(fp_mulmod((fp_int*)a,(fp_int*)b,(fp_int*)c,(fp_int*)d));
}

static int sqrmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return tfm_to_ltc_error(fp_sqrmod((fp_int*)a,(fp_int*)b,(fp_int*)c));
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return tfm_to_ltc_error(fp_invmod((fp_int*)a, (fp_int*)b, (fp_int*)c));
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
   int err;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = XCALLOC(1, sizeof(fp_digit));
   if (*b == NULL) {
      return CRYPT_MEM;
   }
   if ((err = tfm_to_ltc_error(fp_montgomery_setup((fp_int*)a, (fp_digit *)*b))) != CRYPT_OK) {
      XFREE(*b);
   }
   return err;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_montgomery_calc_normalization((fp_int*)a, (fp_int*)b);
   return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_montgomery_reduce((fp_int*)a, (fp_int*)b, *((fp_digit *)c));
   return CRYPT_OK;
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
   return tfm_to_ltc_error(fp_exptmod((fp_int*)a,(fp_int*)b,(fp_int*)c,(fp_int*)d));
}

static int isprime(void *a, int b, int *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   if (b == 0) {
       b = LTC_MILLER_RABIN_REPS;
   } /* if */
   *c = (fp_isprime_ex((fp_int*)a, b) == FP_YES) ? LTC_MP_YES : LTC_MP_NO;
   return CRYPT_OK;
}

#if defined(LTC_MECC) && defined(LTC_MECC_ACCEL)

static int tfm_ecc_projective_dbl_point(const ecc_point *P, ecc_point *R, void *ma, void *modulus, void *Mp)
{
   fp_int t1, t2;
   fp_digit mp;
   int err, inf;

   LTC_ARGCHK(P       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(Mp      != NULL);

   mp = *((fp_digit*)Mp);

   fp_init(&t1);
   fp_init(&t2);

   if (P != R) {
      fp_copy(P->x, R->x);
      fp_copy(P->y, R->y);
      fp_copy(P->z, R->z);
   }

   if ((err = ltc_ecc_is_point_at_infinity(P, modulus, &inf)) != CRYPT_OK) return err;
   if (inf) {
      /* if P is point at infinity >> Result = point at infinity */
      ltc_mp.set_int(R->x, 1);
      ltc_mp.set_int(R->y, 1);
      ltc_mp.set_int(R->z, 0);
      return CRYPT_OK;
   }

   /* t1 = Z * Z */
   fp_sqr((fp_int*)R->z, &t1);
   fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);
   /* Z = Y * Z */
   fp_mul((fp_int*)R->z,(fp_int*) R->y,(fp_int*) R->z);
   fp_montgomery_reduce((fp_int*)R->z,(fp_int*) modulus, mp);
   /* Z = 2Z */
   fp_add((fp_int*)R->z,(fp_int*) R->z,(fp_int*) R->z);
   if (fp_cmp((fp_int*)R->z, (fp_int*)modulus) != FP_LT) {
      fp_sub((fp_int*)R->z,(fp_int*) modulus,(fp_int*) R->z);
   }

   if (ma == NULL) { /* special case for curves with a == -3 (10% faster than general case) */
      /* T2 = X - T1 */
      fp_sub((fp_int*)R->x, &t1, &t2);
      if (fp_cmp_d(&t2, 0) == LTC_MP_LT) {
         fp_add(&t2, (fp_int*)modulus, &t2);
      }
      /* T1 = X + T1 */
      fp_add(&t1,(fp_int*) R->x, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
      /* T2 = T1 * T2 */
      fp_mul(&t1, &t2, &t2);
      fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
      /* T1 = 2T2 */
      fp_add(&t2, &t2, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
      /* T1 = T1 + T2 */
      fp_add(&t1, &t2, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
   }
   else {
      /* T2 = T1 * T1 */
      fp_sqr(&t1, &t2);
      fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
      /* T1 = T2 * a */
      fp_mul(&t2, (fp_int*)ma, &t1);
      fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);
      /* T2 = X * X */
      fp_sqr((fp_int*)R->x, &t2);
      fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
      /* T1 = T1 + T2 */
      fp_add(&t1, &t2, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
      /* T1 = T1 + T2 */
      fp_add(&t1, &t2, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
      /* T1 = T1 + T2 */
      fp_add(&t1, &t2, &t1);
      if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
         fp_sub(&t1, (fp_int*)modulus, &t1);
      }
   }

   /* Y = 2Y */
   fp_add((fp_int*)R->y,(fp_int*) R->y,(fp_int*) R->y);
   if (fp_cmp((fp_int*)R->y, (fp_int*)modulus) != FP_LT) {
      fp_sub((fp_int*)R->y, (fp_int*)modulus,(fp_int*) R->y);
   }
   /* Y = Y * Y */
   fp_sqr((fp_int*)R->y, (fp_int*)R->y);
   fp_montgomery_reduce((fp_int*)R->y, (fp_int*)modulus, mp);
   /* T2 = Y * Y */
   fp_sqr((fp_int*)R->y, &t2);
   fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
   /* T2 = T2/2 */
   if (fp_isodd(&t2)) {
      fp_add(&t2, (fp_int*)modulus, &t2);
   }
   fp_div_2(&t2, &t2);
   /* Y = Y * X */
   fp_mul((fp_int*)R->y, (fp_int*)R->x, (fp_int*)R->y);
   fp_montgomery_reduce((fp_int*)R->y, (fp_int*)modulus, mp);

   /* X  = T1 * T1 */
   fp_sqr(&t1, (fp_int*)R->x);
   fp_montgomery_reduce((fp_int*)R->x, (fp_int*)modulus, mp);
   /* X = X - Y */
   fp_sub((fp_int*)R->x,(fp_int*) R->y,(fp_int*) R->x);
   if (fp_cmp_d((fp_int*)R->x, 0) == FP_LT) {
      fp_add((fp_int*)R->x, (fp_int*)modulus, (fp_int*)R->x);
   }
   /* X = X - Y */
   fp_sub((fp_int*)R->x, (fp_int*)R->y, (fp_int*)R->x);
   if (fp_cmp_d((fp_int*)R->x, 0) == FP_LT) {
      fp_add((fp_int*)R->x, (fp_int*)modulus,(fp_int*) R->x);
   }

   /* Y = Y - X */
   fp_sub((fp_int*)R->y, (fp_int*)R->x, (fp_int*)R->y);
   if (fp_cmp_d((fp_int*)R->y, 0) == FP_LT) {
      fp_add((fp_int*)R->y, (fp_int*)modulus, (fp_int*)R->y);
   }
   /* Y = Y * T1 */
   fp_mul((fp_int*)R->y, &t1, (fp_int*)R->y);
   fp_montgomery_reduce((fp_int*)R->y, (fp_int*)modulus, mp);
   /* Y = Y - T2 */
   fp_sub((fp_int*)R->y, &t2, (fp_int*)R->y);
   if (fp_cmp_d((fp_int*)R->y, 0) == FP_LT) {
      fp_add((fp_int*)R->y, (fp_int*)modulus, (fp_int*)R->y);
   }

   return CRYPT_OK;
}

/**
   Add two ECC points
   @param P        The point to add
   @param Q        The point to add
   @param R        [out] The destination of the double
   @param modulus  The modulus of the field the ECC curve is in
   @param Mp       The "b" value from montgomery_setup()
   @return CRYPT_OK on success
*/
static int tfm_ecc_projective_add_point(const ecc_point *P, const ecc_point *Q, ecc_point *R, void *ma, void *modulus, void *Mp)
{
   fp_int  t1, t2, x, y, z;
   fp_digit mp;
   int err, inf;

   LTC_ARGCHK(P       != NULL);
   LTC_ARGCHK(Q       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(Mp      != NULL);

   mp = *((fp_digit*)Mp);

   fp_init(&t1);
   fp_init(&t2);
   fp_init(&x);
   fp_init(&y);
   fp_init(&z);

   if ((err = ltc_ecc_is_point_at_infinity(P, modulus, &inf)) != CRYPT_OK) return err;
   if (inf) {
      /* P is point at infinity >> Result = Q */
      ltc_mp.copy(Q->x, R->x);
      ltc_mp.copy(Q->y, R->y);
      ltc_mp.copy(Q->z, R->z);
      return CRYPT_OK;
   }

   if ((err = ltc_ecc_is_point_at_infinity(Q, modulus, &inf)) != CRYPT_OK) return err;
   if (inf) {
      /* Q is point at infinity >> Result = P */
      ltc_mp.copy(P->x, R->x);
      ltc_mp.copy(P->y, R->y);
      ltc_mp.copy(P->z, R->z);
      return CRYPT_OK;
   }

   /* should we dbl instead? */
   fp_sub((fp_int*)modulus,(fp_int*) Q->y, &t1);
   if ( (fp_cmp((fp_int*)P->x,(fp_int*) Q->x) == FP_EQ) &&
        (Q->z != NULL && fp_cmp((fp_int*)P->z, (fp_int*)Q->z) == FP_EQ) &&
        (fp_cmp((fp_int*)P->y, (fp_int*)Q->y) == FP_EQ || fp_cmp((fp_int*)P->y, &t1) == FP_EQ)) {
        return tfm_ecc_projective_dbl_point(P, R, ma, modulus, Mp);
   }

   fp_copy(P->x, &x);
   fp_copy(P->y, &y);
   fp_copy(P->z, &z);

   /* if Z is one then these are no-operations */
   if (Q->z != NULL) {
      /* T1 = Z' * Z' */
      fp_sqr((fp_int*)Q->z, &t1);
      fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);
      /* X = X * T1 */
      fp_mul(&t1, &x, &x);
      fp_montgomery_reduce(&x,(fp_int*) modulus, mp);
      /* T1 = Z' * T1 */
      fp_mul((fp_int*)Q->z, &t1, &t1);
      fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);
      /* Y = Y * T1 */
      fp_mul(&t1, &y, &y);
      fp_montgomery_reduce(&y, (fp_int*)modulus, mp);
   }

   /* T1 = Z*Z */
   fp_sqr(&z, &t1);
   fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);
   /* T2 = X' * T1 */
   fp_mul((fp_int*)Q->x, &t1, &t2);
   fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
   /* T1 = Z * T1 */
   fp_mul(&z, &t1, &t1);
   fp_montgomery_reduce(&t1,(fp_int*) modulus, mp);
   /* T1 = Y' * T1 */
   fp_mul((fp_int*)Q->y, &t1, &t1);
   fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);

   /* Y = Y - T1 */
   fp_sub(&y, &t1, &y);
   if (fp_cmp_d(&y, 0) == FP_LT) {
      fp_add(&y, (fp_int*)modulus, &y);
   }
   /* T1 = 2T1 */
   fp_add(&t1, &t1, &t1);
   if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
      fp_sub(&t1, (fp_int*)modulus, &t1);
   }
   /* T1 = Y + T1 */
   fp_add(&t1, &y, &t1);
   if (fp_cmp(&t1, (fp_int*)modulus) != FP_LT) {
      fp_sub(&t1, (fp_int*)modulus, &t1);
   }
   /* X = X - T2 */
   fp_sub(&x, &t2, &x);
   if (fp_cmp_d(&x, 0) == FP_LT) {
      fp_add(&x,(fp_int*) modulus, &x);
   }
   /* T2 = 2T2 */
   fp_add(&t2, &t2, &t2);
   if (fp_cmp(&t2,(fp_int*) modulus) != FP_LT) {
      fp_sub(&t2, (fp_int*)modulus, &t2);
   }
   /* T2 = X + T2 */
   fp_add(&t2, &x, &t2);
   if (fp_cmp(&t2, (fp_int*)modulus) != FP_LT) {
      fp_sub(&t2, (fp_int*)modulus, &t2);
   }

   /* if Z' != 1 */
   if (Q->z != NULL) {
      /* Z = Z * Z' */
      fp_mul(&z, (fp_int*)Q->z, &z);
      fp_montgomery_reduce(&z, (fp_int*)modulus, mp);
   }

   /* Z = Z * X */
   fp_mul(&z, &x, &z);
   fp_montgomery_reduce(&z,(fp_int*) modulus, mp);

   /* T1 = T1 * X  */
   fp_mul(&t1, &x, &t1);
   fp_montgomery_reduce(&t1,(fp_int*) modulus, mp);
   /* X = X * X */
   fp_sqr(&x, &x);
   fp_montgomery_reduce(&x, (fp_int*)modulus, mp);
   /* T2 = T2 * x */
   fp_mul(&t2, &x, &t2);
   fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
   /* T1 = T1 * X  */
   fp_mul(&t1, &x, &t1);
   fp_montgomery_reduce(&t1, (fp_int*)modulus, mp);

   /* X = Y*Y */
   fp_sqr(&y, &x);
   fp_montgomery_reduce(&x, (fp_int*)modulus, mp);
   /* X = X - T2 */
   fp_sub(&x, &t2, &x);
   if (fp_cmp_d(&x, 0) == FP_LT) {
      fp_add(&x, (fp_int*)modulus, &x);
   }

   /* T2 = T2 - X */
   fp_sub(&t2, &x, &t2);
   if (fp_cmp_d(&t2, 0) == FP_LT) {
      fp_add(&t2, (fp_int*)modulus, &t2);
   }
   /* T2 = T2 - X */
   fp_sub(&t2, &x, &t2);
   if (fp_cmp_d(&t2, 0) == FP_LT) {
      fp_add(&t2, (fp_int*)modulus, &t2);
   }
   /* T2 = T2 * Y */
   fp_mul(&t2, &y, &t2);
   fp_montgomery_reduce(&t2, (fp_int*)modulus, mp);
   /* Y = T2 - T1 */
   fp_sub(&t2, &t1, &y);
   if (fp_cmp_d(&y, 0) == FP_LT) {
      fp_add(&y,(fp_int*) modulus, &y);
   }
   /* Y = Y/2 */
   if (fp_isodd(&y)) {
      fp_add(&y, (fp_int*)modulus, &y);
   }
   fp_div_2(&y, &y);

   fp_copy(&x, R->x);
   fp_copy(&y, R->y);
   fp_copy(&z, R->z);

   return CRYPT_OK;
}


#endif

static int set_rand(void *a, int size)
{
   LTC_ARGCHK(a != NULL);
   fp_rand((fp_int*)a, size);
   return CRYPT_OK;
}

const ltc_math_descriptor tfm_desc = {

   "TomsFastMath",
   (int)DIGIT_BIT,

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
   NULL, /* TODO: &sqrtmod_prime */
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
#endif /* LTC_MECC_FP */
#ifdef LTC_MECC_ACCEL
   &tfm_ecc_projective_add_point,
   &tfm_ecc_projective_dbl_point,
#else
   &ltc_ecc_projective_add_point,
   &ltc_ecc_projective_dbl_point,
#endif /* LTC_MECC_ACCEL */
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

   set_rand,

};


#endif
