// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "gpiodpi.h"
#include "headers/tomcrypt.h"
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

  //char gpio_str[32 + 2];
  char gpio_str[600+2];
  //ssize_t read_len = read(ctx->host_to_dev_fifo, gpio_str, 32 + 1);
  ssize_t read_len = read(ctx->host_to_dev_fifo, gpio_str, 600+1);
  if (read_len < 0) {
    return ctx->driven_pin_values;
  }
  //TEST SHA 256
  int i;
  unsigned char tmp[32];
  hash_state md;
  char* message=(char*)gpio_str;
  //split message into tokens
  char* token=strtok(message,"\t");
  char *inPubPem;
  char *inSigHex;
  char *inMessage;
  int tokenCounter=0;
  while( token != NULL ) {
    if (tokenCounter==0){
      inPubPem=token;
    }
    else if (tokenCounter==1){
      inSigHex=token;
    }
    else{
      inMessage=token;
    }
    token = strtok(NULL, "\t");
    tokenCounter++;
  }
  printf("\nPubpem:%s:END\n",inPubPem);
  printf("sigHex:%s:END\n",inSigHex);
  printf("Message:%s:END\n",inMessage);

//  sha256_init(&md);
//  sha256_process(&md, (unsigned char*)message, (unsigned long)XSTRLEN(message));
//  sha256_done(&md, tmp);
//  printf("\nHASH 256:");
//  for(int i=0;i<32;++i){
//    printf("%02x",tmp[i]);
//  }
//  printf("\n");


  //TEST RSA VERIFY
  ltc_mp = tfm_desc; //init tfm

  printf("\nBeginning test\n");
  unsigned char in[1024],out[1024];
  rsa_key       pubKey,privKey,pubTest,privTest;
  int           hash_idx,stat,err;
  unsigned long len,len2;
  if((hash_idx= register_hash(&sha256_desc)) != CRYPT_OK){
    printf("hash idx error: %d",hash_idx);
  }
  //this is the one
  const char hexE[]="10001";
  const char hexN[]="d1e89e2bf8aa4486101dddbc16488d683c7af162f4ab648ec2560de0fdb519b4bf05cf43069a977c7d6cdeb3e6a4801b2f52cb938e4e137b73d5fdbe6a95e20ba5e3e3298090540d1c8172adf2bea65bb00cc7ca6043cf0e2221be777be6ec8c819057537e040f7578d82afbef04ea8951e8482407a357d6a4526d726f9f558f";
  const char hexD[]="bd68fb3950544c2af0e6124c838b0a5691a49aa6a182fae53b052dd6e4f882eeaf244de6fc5188fa63af56b1dd20791c8eb256529aa9673911c87a0455e753a56d088595d4bd8a02f08cddf0d55bcc42c27f2719b7db511d6147e72b832e78c734efa7acf0277a37cc40831a0c73a9ae29a04069b18a2f390c58a38134a64939";
  //const char hexSignature[]="41b2c1c386f4fdb70a76e066c728c71d161b4d0b48b8529d79bebcdb22445d480443561633c7b75c7b6990194f325e22bbffd871d64dfe82bc5dcdc6798f7e6527663b436a35b90d6f49d639f34e56127dcb5f2e78a526493bbafd43201a59308879bd70584317275c45162eaaabffed9ff415db3a20319b024c7d15813610e1";
  const char hexHash[]="47f53245cd05a2b3e811ad6515000b44604b947a57d441b02125b04f4a16bb74";


  unsigned char binE[128];
  unsigned char binN[257];
  unsigned char binD[257];
  unsigned char binSignature[1024];
  unsigned char binHash[1024];

  unsigned long lenSignature;
  unsigned long lenbinE;
  unsigned long lenbinN;
  unsigned long lenbinD;
  unsigned long lenHash;

  lenbinE=sizeof(binE);
  lenbinN=sizeof(binN);
  lenbinD=sizeof(binD);
  lenSignature=sizeof(binSignature);
  lenHash=sizeof(binHash);

  //hexadecimal to binary
  int radix_to_bin_e=radix_to_bin(hexE,16,binE,&lenbinE);
  printf("\nRadix to bin operation on E: %d\n",radix_to_bin_e);
  int radix_to_bin_N=radix_to_bin(hexN,16,binN,&lenbinN);
  printf("Radix to bin operation on N: %d\n",radix_to_bin_N);
  int radix_to_bin_D=radix_to_bin(hexD,16,binD,&lenbinD);
  printf("Radix to bin operation on D: %d\n",radix_to_bin_D);
  int radix_to_bin_Signature=radix_to_bin(inSigHex,16,binSignature,&lenSignature);
  printf("Radix to bin operation on signature: %d\n",radix_to_bin_Signature);
  int radix_to_bin_Hash=radix_to_bin(hexHash,16,binHash,&lenHash);
  printf("Radix to bin operation on hash: %d\n",radix_to_bin_Hash);

  //pubkey
  int rsa_set_pubkey_ret=rsa_set_key(binN,lenbinN,binE,lenbinE,NULL,NULL,&pubTest);
  printf("RSA Set pub Key ret: %d\n",rsa_set_pubkey_ret);
  //privkey
  int rsa_set_privkey_ret=rsa_set_key(binN,lenbinN,binE,lenbinE,binD,lenbinD,&privTest);
  printf("RSA Set priv Key ret: %d\n",rsa_set_privkey_ret);

  //verify hash real
  printf("proceeding with real signature\n");
  int verify_hash_real= rsa_verify_hash_ex(binSignature,lenSignature,binHash,lenHash,LTC_PKCS_1_PSS,hash_idx,0,&stat,&pubTest);
  printf("Verify hash real return: %d\n",verify_hash_real);
  printf("stat real value: %d\n",stat);
  rsa_free(&pubTest);
  rsa_free(&privTest);

  //test with PEM now
  //const char pubKeyPEM[]="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQAB";
  printf("proceeding with PEM certificate now\n");
  unsigned long lenX509;
  unsigned char keyPubDER[1024];
  lenX509=sizeof(keyPubDER);

  printf("Decoding pem base64 to der\n");
  if ((err= base64_decode(inPubPem,strlen(inPubPem),keyPubDER,&lenX509)) != CRYPT_OK){
    printf("\nError decoding PEM: %d\n",err);
  }
  //debug
  printf("lenx509: %d\n",lenX509);
  printf("Proceeding to import public key\n");
  if ((err = rsa_import(keyPubDER,lenX509,&pubKey)) != CRYPT_OK) {
    printf("PUBLIC KEY import failed: %d\n", err);
  }
  printf("proceeding with real signature\n");
  verify_hash_real= rsa_verify_hash_ex(binSignature,lenSignature,binHash,32,LTC_PKCS_1_PSS,hash_idx,0,&stat,&pubKey);
  printf("Verify hash real return: %d\n",verify_hash_real);
  printf("stat real value: %d\n",stat);
  rsa_free(&pubKey);



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
