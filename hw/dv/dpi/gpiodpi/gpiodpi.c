// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "gpiodpi.h"
#include "tomcrypt_private.h"
#ifdef __linux__
#include <pty.h>
#elif __APPLE__
#include <util.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void hash_to_string(char string[65], const uint8_t hash[32]);
// This file does a lot of bit setting and getting; these macros are intended to
// make that a little more readable.
#define GET_BIT(word, bit_idx) (((word) >> (bit_idx)) & 1)
#define SET_BIT(word, bit_idx) ((word) |= (1 << (bit_idx)))
#define CLR_BIT(word, bit_idx) ((word) &= ~(1 << (bit_idx)))

struct gpiodpi_ctx {
  // The number of pins we're driving.
  int n_bits;

  // The last known value of the pins, in little-endian order.
  uint32_t driven_pin_values;

  // File descriptors and paths for the device-to-host and host-to-device
  // FIFOs.
  int dev_to_host_fifo;
  char dev_to_host_path[PATH_MAX];
  int host_to_dev_fifo;
  char host_to_dev_path[PATH_MAX];
};


//sha256
static void hash_to_string(char string[65], const uint8_t hash[32])
{
  size_t i;
  for (i = 0; i < 32; i++) {
    string += sprintf(string, "%02x", hash[i]);
  }
}

#ifdef LTC_SMALL_CODE
/* the K array */
static const ulong32 K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
#endif

/* Various logical functions */
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

/* compress 512-bits */
#ifdef LTC_CLEAN_STACK
static int ss_sha256_compress(hash_state * md, const unsigned char *buf)
#else
static int s_sha256_compress(hash_state * md, const unsigned char *buf)
#endif
{
  ulong32 S[8], W[64], t0, t1;
#ifdef LTC_SMALL_CODE
  ulong32 t;
#endif
  int i;

  /* copy state into S */
  for (i = 0; i < 8; i++) {
    S[i] = md->sha256.state[i];
  }

  /* copy the state into 512-bits into W[0..15] */
  for (i = 0; i < 16; i++) {
    LOAD32H(W[i], buf + (4*i));
  }

  /* fill W[16..63] */
  for (i = 16; i < 64; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
  }

  /* Compress */
#ifdef LTC_SMALL_CODE
#define RND(a,b,c,d,e,f,g,h,i)                         \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h  = t0 + t1;

  for (i = 0; i < 64; ++i) {
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
    t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
    S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
  }
#else
#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
     t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                  \
     d += t0;                                        \
     h  = t0 + t1;

  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);
#endif
#undef RND

  /* feedback */
  for (i = 0; i < 8; i++) {
    md->sha256.state[i] = md->sha256.state[i] + S[i];
  }
  return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
static int s_sha256_compress(hash_state * md, const unsigned char *buf)
{
  int err;
  err = ss_sha256_compress(md, buf);
  burn_stack(sizeof(ulong32) * 74);
  return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha256_init(hash_state * md)
{

  md->sha256.curlen = 0;
  md->sha256.length = 0;
  md->sha256.state[0] = 0x6A09E667UL;
  md->sha256.state[1] = 0xBB67AE85UL;
  md->sha256.state[2] = 0x3C6EF372UL;
  md->sha256.state[3] = 0xA54FF53AUL;
  md->sha256.state[4] = 0x510E527FUL;
  md->sha256.state[5] = 0x9B05688CUL;
  md->sha256.state[6] = 0x1F83D9ABUL;
  md->sha256.state[7] = 0x5BE0CD19UL;
  return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha256_process,s_sha256_compress, sha256, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int sha256_done(hash_state * md, unsigned char *out)
{
  int i;


  if (md->sha256.curlen >= sizeof(md->sha256.buf)) {
    return CRYPT_INVALID_ARG;
  }


  /* increase the length of the message */
  md->sha256.length += md->sha256.curlen * 8;

  /* append the '1' bit */
  md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

  /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
   */
  if (md->sha256.curlen > 56) {
    while (md->sha256.curlen < 64) {
      md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
    }
    s_sha256_compress(md, md->sha256.buf);
    md->sha256.curlen = 0;
  }

  /* pad upto 56 bytes of zeroes */
  while (md->sha256.curlen < 56) {
    md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
  }

  /* store length */
  STORE64H(md->sha256.length, md->sha256.buf+56);
  s_sha256_compress(md, md->sha256.buf);

  /* copy output */
  for (i = 0; i < 8; i++) {
    STORE32H(md->sha256.state[i], out+(4*i));
  }

  return CRYPT_OK;
}














/**
 * Creates a new UNIX FIFO file at |path_buf|, and opens it with |flags|.
 *
 * @return a file descriptor for the FIFO, or -1 if any syscall failed.
 */
static int open_fifo(char *path_buf, int flags) {
  int fifo_status = mkfifo(path_buf, 0644);
  if (fifo_status != 0) {
    if (errno == EEXIST) {
      fprintf(stderr, "GPIO: Reusing existing FIFO at %s\n", path_buf);
    } else {
      fprintf(stderr, "GPIO: Unable to create FIFO at %s: %s\n", path_buf,
              strerror(errno));
      return -1;
    }
  }

  int fd = open(path_buf, flags);
  if (fd < 0) {
    // Delete the fifo we created; ignore errors.
    unlink(path_buf);
    fprintf(stderr, "GPIO: Unable to open FIFO at %s: %s\n", path_buf,
            strerror(errno));
    return -1;
  }

  return fd;
}

/**
 * Print out a usage message for the GPIO interface.
 *
 * @arg rfifo the path to the "read" side (w.r.t the host).
 * @arg wfifo the path to the "write" side (w.r.t the host).
 * @arg n_bits the number of pins supported.
 */
static void print_usage(char *rfifo, char *wfifo, int n_bits) {
  printf("\n");
  printf(
      "GPIO: FIFO pipes created at %s (read) and %s (write) for %d-bit wide "
      "GPIO.\n",
      rfifo, wfifo, n_bits);
  printf(
      "GPIO: To measure the values of the pins as driven by the device, run\n");
  printf("$ cat %s  # '0' low, '1' high, 'X' floating\n", rfifo);
  printf("GPIO: To drive the pins, run a command like\n");
  printf("$ echo 'h09 l31' > %s  # Pull the pin 9 high, and pin 31 low.\n",
         wfifo);
}

void *gpiodpi_create(const char *name, int n_bits) {
  struct gpiodpi_ctx *ctx =
      (struct gpiodpi_ctx *)malloc(sizeof(struct gpiodpi_ctx));
  assert(ctx);

  // n_bits > 32 requires more sophisticated handling of svBitVecVal which we
  // currently don't do.
  assert(n_bits <= 32 && "n_bits must be <= 32");
  ctx->n_bits = n_bits;

  ctx->driven_pin_values = 0;

  char cwd_buf[PATH_MAX];
  char *cwd = getcwd(cwd_buf, sizeof(cwd_buf));
  assert(cwd != NULL);

  int path_len;
  path_len = snprintf(ctx->dev_to_host_path, PATH_MAX, "%s/%s-read", cwd, name);
  assert(path_len > 0 && path_len <= PATH_MAX);
  path_len =
      snprintf(ctx->host_to_dev_path, PATH_MAX, "%s/%s-write", cwd, name);
  assert(path_len > 0 && path_len <= PATH_MAX);

  ctx->dev_to_host_fifo = open_fifo(ctx->dev_to_host_path, O_RDWR);
  if (ctx->dev_to_host_fifo < 0) {
    return NULL;
  }

  ctx->host_to_dev_fifo = open_fifo(ctx->host_to_dev_path, O_RDWR);
  if (ctx->host_to_dev_fifo < 0) {
    return NULL;
  }

  int flags = fcntl(ctx->host_to_dev_fifo, F_GETFL, 0);
  fcntl(ctx->host_to_dev_fifo, F_SETFL, flags | O_NONBLOCK);

  print_usage(ctx->dev_to_host_path, ctx->host_to_dev_path, ctx->n_bits);

  return (void *)ctx;
}

void gpiodpi_device_to_host(void *ctx_void, svBitVecVal *gpio_data,
                            svBitVecVal *gpio_oe) {
  struct gpiodpi_ctx *ctx = (struct gpiodpi_ctx *)ctx_void;
  assert(ctx);

  // Write 0, 1, or X (when oe is not set) for each GPIO pin, in big endian
  // order (i.e., pin 0 is the last character written). Finish it with a
  // newline.
  char gpio_str[32 + 1];
  char *pin_char = gpio_str;
  for (int i = ctx->n_bits - 1; i >= 0; --i, ++pin_char) {
    if (!GET_BIT(gpio_oe[0], i)) {
      *pin_char = 'X';
    } else if (GET_BIT(gpio_data[0], i)) {
      *pin_char = '1';
    } else {
      *pin_char = '0';
    }
  }
  *pin_char = '\n';

  ssize_t written = write(ctx->dev_to_host_fifo, gpio_str, ctx->n_bits + 1);
  assert(written == ctx->n_bits + 1);
}

/**
 * Parses an unsigned decimal number from |text|, advancing it forward as
 * necessary.
 *
 * Returns upon encountering any non-decimal digit.
 */
static uint32_t parse_dec(char **text) {
  if (text == NULL || *text == NULL) {
    return 0;
  }

  uint32_t value = 0;
  for (; **text != '\0'; ++*text) {
    char c = **text;
    uint32_t digit;
    if (c >= '0' && c <= '9') {
      digit = (c - '0');
    } else {
      break;
    }

    value *= 10;
    value += digit;
  }

  return value;
}

uint32_t gpiodpi_host_to_device_tick(void *ctx_void, svBitVecVal *gpio_oe) {
  struct gpiodpi_ctx *ctx = (struct gpiodpi_ctx *)ctx_void;
  assert(ctx);

  char gpio_str[32 + 2];
  ssize_t read_len = read(ctx->host_to_dev_fifo, gpio_str, 32 + 1);
  if (read_len < 0) {
    return ctx->driven_pin_values;
  }
  //TEST SHA 256
  int i;
  unsigned char tmp[32];
  hash_state md;
  const char* message=(const char*)gpio_str;
  sha256_init(&md);
  sha256_process(&md, (unsigned char*)message, (unsigned long)XSTRLEN(message));
  sha256_done(&md, tmp);
  printf("\nTEST HASH 256:");
  for(int i=0;i<32;++i){
    printf("%02x",tmp[i]);
  }
  printf("\n");






  gpio_str[read_len] = '\0';

  char *gpio_text = gpio_str;
  for (; *gpio_text != '\0'; ++gpio_text) {
    switch (*gpio_text) {
      case '\n':
      case '\r':
      case '\0':
        goto parse_loop_end;
      case 'l':
      case 'L': {
        ++gpio_text;
        int idx = parse_dec(&gpio_text);
        if (!GET_BIT(gpio_oe[0], idx)) {
          fprintf(stderr,
                  "GPIO: Host tried to pull disabled pin low: pin %2d\n", idx);
        }
        CLR_BIT(ctx->driven_pin_values, idx);
        break;
      }
      case 'h':
      case 'H': {
        ++gpio_text;
        int idx = parse_dec(&gpio_text);
        if (!GET_BIT(gpio_oe[0], idx)) {
          fprintf(stderr,
                  "GPIO: Host tried to pull disabled pin high: pin %2d\n", idx);
        }
        SET_BIT(ctx->driven_pin_values, idx);
        break;
      }
      default:
        break;
    }
  }

parse_loop_end:
  return ctx->driven_pin_values;
}

void gpiodpi_close(void *ctx_void) {
  struct gpiodpi_ctx *ctx = (struct gpiodpi_ctx *)ctx_void;
  if (ctx == NULL) {
    return;
  }

  if (close(ctx->dev_to_host_fifo) != 0) {
    printf("GPIO: Failed to close FIFO file at %s: %s\n", ctx->dev_to_host_path,
           strerror(errno));
  }
  if (close(ctx->host_to_dev_fifo) != 0) {
    printf("GPIO: Failed to close FIFO file at %s: %s\n", ctx->host_to_dev_path,
           strerror(errno));
  }

  if (unlink(ctx->dev_to_host_path) != 0) {
    printf("GPIO: Failed to unlink FIFO file at %s: %s\n",
           ctx->dev_to_host_path, strerror(errno));
  }
  if (unlink(ctx->host_to_dev_path) != 0) {
    printf("GPIO: Failed to unlink FIFO file at %s: %s\n",
           ctx->host_to_dev_path, strerror(errno));
  }

  free(ctx);
}
