// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "gpiodpi.h"
#include "headers/tomcrypt_private.h"
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

const char keyPub[]="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQAB";
/*** test key */
static const unsigned char openssl_public_rsa[] = {
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xcf, 0x9a, 0xde,
    0x64, 0x8a, 0xda, 0xc8, 0x33, 0x20, 0xa9, 0xd7, 0x83, 0x31, 0x19, 0x54, 0xb2, 0x9a, 0x85, 0xa7,
    0xa1, 0xb7, 0x75, 0x33, 0xb6, 0xa9, 0xac, 0x84, 0x24, 0xb3, 0xde, 0xdb, 0x7d, 0x85, 0x2d, 0x96,
    0x65, 0xe5, 0x3f, 0x72, 0x95, 0x24, 0x9f, 0x28, 0x68, 0xca, 0x4f, 0xdb, 0x44, 0x1c, 0x3e, 0x60,
    0x12, 0x8a, 0xdd, 0x26, 0xa5, 0xeb, 0xff, 0x0b, 0x5e, 0xd4, 0x88, 0x38, 0x49, 0x2a, 0x6e, 0x5b,
    0xbf, 0x12, 0x37, 0x47, 0xbd, 0x05, 0x6b, 0xbc, 0xdb, 0xf3, 0xee, 0xe4, 0x11, 0x8e, 0x41, 0x68,
    0x7c, 0x61, 0x13, 0xd7, 0x42, 0xc8, 0x80, 0xbe, 0x36, 0x8f, 0xdc, 0x08, 0x8b, 0x4f, 0xac, 0xa4,
    0xe2, 0x76, 0x0c, 0xc9, 0x63, 0x6c, 0x49, 0x58, 0x93, 0xed, 0xcc, 0xaa, 0xdc, 0x25, 0x3b, 0x0a,
    0x60, 0x3f, 0x8b, 0x54, 0x3a, 0xc3, 0x4d, 0x31, 0xe7, 0x94, 0xa4, 0x44, 0xfd, 0x02, 0x03, 0x01,
    0x00, 0x01,  };







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
  printf("\nHASH 256:");
  for(int i=0;i<32;++i){
    printf("%02x",tmp[i]);
  }
  printf("\n");


  //TEST RSA VERIFY
  ltc_mp = tfm_desc; //init tfm

  printf("\nBeginning test\n");
  printf("CRYPT_PK_INVALID_PADDING: %d\n",CRYPT_PK_INVALID_PADDING);
  printf("CRYPT_INVALID_PACKET: %d\n",CRYPT_INVALID_PACKET);
  printf("CRYPT_MEM: %d\n",CRYPT_MEM);
  printf("CRYPT_INVALID_ARG: %d\n",CRYPT_INVALID_ARG);
  unsigned char in[1024];
  rsa_key       pubKey;
  int           hash_idx,stat,err;
  unsigned long len,len2;
  //the signature
  //const unsigned char tmpOut[]="]x\\xf2\\xca\\x12Uc\\xd1\\x08enr\\x98g$\\xc2\\xa0\\xc2\\x11\\xae3k\\x19\\x87Y\\x88\\xfeb\\x94\\x9c\\x8c\\xfe\\xc2\\x8b]\\xef\\xffSE\\xd1!iT\\x89K\\xd0Jh)x\\x90OO\\x93\\x12\\x12\\xa2GME\\xb7\\xde\\xf5m\\x1e\\x8eo\\x82\\xde<\\x18\\\\\\x18b\\xcfW\\xcd\\xec\\xc3\\x98\\x1f@E\\x03\\x84^\\xcf\\x00\\xc5\\xe4z\\xb3\\x7f\\x89\\x1b\\xdf\\x1e}\\xfb\\x7f\\xb0}\\xeck\\xcce\\xa1\\x0b\\xafj6.J!m,pl5\\xd5{\\x90\\xa4N\\xaa\\x01Y-";
  strcpy((char*)in,(char*)tmp);
  //strcpy((char*)out,(char*)tmpOut);
  unsigned char out[]={0X2D, 0X59, 0X01, 0XAA, 0X4E, 0XA4, 0X90, 0X7B, 0XD5, 0X35, 0X6C, 0X70, 0X2C, 0X6D, 0X21, 0X4A, 0X2E, 0X36, 0X6A, 0XAF, 0X0B, 0XA1, 0X65, 0XCC, 0X6B, 0XEC, 0X7D, 0XB0, 0X7F, 0XFB, 0X7D, 0X1E, 0XDF, 0X1B, 0X89, 0X7F, 0XB3, 0X7A, 0XE4, 0XC5, 0X00, 0XCF, 0X5E, 0X84, 0X03, 0X45, 0X40, 0X1F, 0X98, 0XC3, 0XEC, 0XCD, 0X57, 0XCF, 0X62, 0X18, 0X5C, 0X18, 0X3C, 0XDE, 0X82, 0X6F, 0X8E, 0X1E, 0X6D, 0XF5, 0XDE, 0XB7, 0X45, 0X4D, 0X47, 0XA2, 0X12, 0X12, 0X93, 0X4F, 0X4F, 0X90, 0X78, 0X29, 0X68, 0X4A, 0XD0, 0X4B, 0X89, 0X54, 0X69, 0X21, 0XD1, 0X45, 0X53, 0XFF, 0XEF, 0X5D, 0X8B, 0XC2, 0XFE, 0X8C, 0X9C, 0X94, 0X62, 0XFE, 0X88, 0X59, 0X87, 0X19, 0X6B, 0X33, 0XAE, 0X11, 0XC2, 0XA0, 0XC2, 0X24, 0X67, 0X98, 0X72, 0X6E, 0X65, 0X08, 0XD1, 0X63, 0X55, 0X12, 0XCA, 0XF2, 0X78, 0X5D};

  len=sizeof(out);
  //len2=sizeof(tmp);
  if((hash_idx= register_hash(&sha256_desc)) != CRYPT_OK){
    printf("hash idx error: %d",hash_idx);
  }
  unsigned char keyPubDER[300];
  unsigned long keypubDERSize=sizeof(keyPubDER);
  //pubkey pem to der sequence
  printf("Proceeding base64 decode pem pubkey\n");
  if ((err = base64_decode(keyPub,sizeof(keyPub),keyPubDER,&keypubDERSize)) != CRYPT_OK) {
    printf("base64 decode failed: %d\n", err);
  }
  printf("Proceeding to import public key\n");
  if ((err = rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa),
                        &pubKey)) != CRYPT_OK) {
    printf("PUBLIC import failed: %d\n", err);
  }
  printf("Proceeding to verify test hash\n");
  if ((err= rsa_verify_hash(out, len, in, 32, hash_idx, 0, &stat, &pubKey)) != CRYPT_OK){
    printf("Verify Hash error: %d\n", err);
  }
  printf("\nrsa_verify_hash_ex stat result= %d\n",stat);



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
