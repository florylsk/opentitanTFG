// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/examples/demos.h"

#include <stdbool.h>

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/dif/dif_gpio.h"
#include "sw/device/lib/dif/dif_spi_device.h"
#include "sw/device/lib/dif/dif_uart.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/check.h"
#include "sw/device/lib/dif/dif_hmac.h"
#include "sw/device/lib/testing/test_framework/ottf.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#define MAX_FIFO_FILL 10

static void run_test(const dif_hmac_t *hmac, const char *data, size_t len,
                     const uint8_t *key);
static void check_digest(const dif_hmac_t *hmac);
    const test_config_t kTestConfig;

// This test needs to understand the byte order of the data in the string and
// the digest values below, as they are laid out for the current processor.
// RISC-V is little-endian, so the first of these `kHmacTransactionConfig`
// values is the one we expect to be used, but we include the other for
// completeness.
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "This test assumes the target platform is little endian.");

static const dif_hmac_transaction_t kHmacTransactionConfig = {
    .digest_endianness = kDifHmacEndiannessLittle,
    .message_endianness = kDifHmacEndiannessLittle,
};



static uint32_t kHmacKey[8] = {0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
                               0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89};


char* itoa(int i, char b[]){
  char const digit[] = "0123456789";
  char* p = b;
  if(i<0){
    *p++ = '-';
    i *= -1;
  }
  int shifter = i;
  do{
    ++p;
    shifter = shifter/10;
  }while(shifter);
  *p = '\0';
  do{
    *--p = digit[i%10];
    i = i/10;
  }while(i);
  return b;
}

//--------------------------------------------
//HMAC ENGINE
//--------------------------------------------

static void test_setup(mmio_region_t base_addr, dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_init(base_addr, hmac));
}

static void test_start(const dif_hmac_t *hmac, const uint8_t *key) {
  // Let a null key indicate we are operating in SHA256-only mode.
  if (key == NULL) {
    CHECK_DIF_OK(dif_hmac_mode_sha256_start(hmac, kHmacTransactionConfig));
  } else {
    CHECK_DIF_OK(dif_hmac_mode_hmac_start(hmac, key, kHmacTransactionConfig));
  }
}
static void push_message(const dif_hmac_t *hmac, const char *data, size_t len) {
  int fifo_fill_count = 0;
  const char *dp = data;
  size_t sent_bytes;

  while (dp - data < len) {
    dif_result_t res =
        dif_hmac_fifo_push(hmac, dp, len - (dp - data), &sent_bytes);

    CHECK(res != kDifBadArg,
          "Invalid arguments encountered while pushing to FIFO.");

    if (res == kDifIpFifoFull) {
      ++fifo_fill_count;
    } else {
      CHECK(res != kDifBadArg,
            "Invalid arguments encountered while pushing to FIFO.");
      CHECK(res == kDifOk, "Unknown error encountered while pushing to FIFO.");
    }

    CHECK(fifo_fill_count <= MAX_FIFO_FILL,
          "FIFO filled up too may times, giving up.");

    dp += sent_bytes;
  }
}
static void wait_for_fifo_empty(const dif_hmac_t *hmac) {
  uint32_t fifo_depth;
  do {
    CHECK_DIF_OK(dif_hmac_fifo_count_entries(hmac, &fifo_depth));
  } while (fifo_depth > 0);
}
static void check_message_length(const dif_hmac_t *hmac,
                                 uint64_t expected_sent_bits) {
  uint64_t sent_bits;
  CHECK_DIF_OK(dif_hmac_get_message_length(hmac, &sent_bits));

  // TODO: Support 64-bit integers in logging.
  CHECK(expected_sent_bits == sent_bits,
        "Message length mismatch. Expected %u bits but got %u bits.",
        (uint32_t)expected_sent_bits, (uint32_t)sent_bits);
}
static void run_hmac(const dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_process(hmac));
}
static void check_digest(const dif_hmac_t *hmac) {
  dif_hmac_digest_t digest_result;
  bool hmac_done = false;
  do {
    dif_result_t res = dif_hmac_finish(hmac, &digest_result);

    CHECK(res != kDifBadArg,
          "Invalid arguments encountered reading HMAC digest.");

    hmac_done = (res != kDifUnavailable);

    if (hmac_done) {
      CHECK(res == kDifOk, "Unknown error encountered reading HMAC digest.");
    }
  } while (!hmac_done);

  for (int i=0;i<8;++i){
    LOG_INFO("HEX %d: %x",i,digest_result.digest[i]);
  }
}

static void run_test(const dif_hmac_t *hmac, const char *data, size_t len,
                     const uint8_t *key) {
  test_start(hmac, key);
  push_message(hmac, data, len);
  wait_for_fifo_empty(hmac);
  check_message_length(hmac, len * 8);
  run_hmac(hmac);
  check_digest(hmac);
}



















//--------------------------------------------
//GPIO FUNCTIONS
//--------------------------------------------


void demo_gpio_startup(dif_gpio_t *gpio) {
  LOG_INFO("Watch the LEDs!");

  // Give a LED pattern as startup indicator for 5 seconds.
  CHECK_DIF_OK(dif_gpio_write_all(gpio, 0xff00));
  for (int i = 0; i < 32; ++i) {
    usleep(5 * 1000);  // 5 ms
    CHECK_DIF_OK(dif_gpio_write(gpio, 8 + (i % 8), (i / 8) % 2));
  }
  CHECK_DIF_OK(dif_gpio_write_all(gpio, 0x0000));  // All LEDs off.
}

/**
 * Mask for "valid" GPIO bits. The first byte represents switch inputs,
 * while byte 16 represents the FTDI bit.
 */
static const uint32_t kGpioMask = 0x100ff;

/**
 * Mask for the FTDI bit among the GPIO bits.
 */
static const uint32_t kFtdiMask = 0x10000;

uint32_t demo_gpio_to_log_echo(dif_gpio_t *gpio, uint32_t prev_gpio_state) {
  uint32_t gpio_state;
  CHECK_DIF_OK(dif_gpio_read_all(gpio, &gpio_state));
  gpio_state &= kGpioMask;

  uint32_t state_delta = prev_gpio_state ^ gpio_state;
  for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
    bool changed = ((state_delta >> bit_idx) & 0x1) != 0;
    bool is_currently_set = ((gpio_state >> bit_idx) & 0x1) != 0;
    if (changed) {
      LOG_INFO("GPIO switch #%d changed to %d", bit_idx, is_currently_set);
    }
  }

  if ((state_delta & kFtdiMask) != 0) {
    if ((gpio_state & kFtdiMask) != 0) {
      LOG_INFO("FTDI control changed. Enable JTAG.");
    } else {
      LOG_INFO("FTDI control changed. Enable JTAG.");
    }
  }
  return gpio_state;
}

void demo_spi_to_log_echo(const dif_spi_device_t *spi,
                          const dif_spi_device_config_t *spi_config) {
  uint32_t spi_buf[8];
  size_t spi_len;
  CHECK_DIF_OK(
      dif_spi_device_recv(spi, spi_config, spi_buf, sizeof(spi_buf), &spi_len));
  if (spi_len > 0) {
    uint32_t echo_word = spi_buf[0] ^ 0x01010101;
    CHECK_DIF_OK(dif_spi_device_send(spi, spi_config, &echo_word,
                                     sizeof(uint32_t),
                                     /*bytes_sent=*/NULL));
    LOG_INFO("SPI: %z", spi_len, spi_buf);
  }
}

void demo_uart_to_uart_and_gpio_echo(dif_uart_t *uart, dif_gpio_t *gpio) {
  while (true) {
    size_t chars_available;
    if (dif_uart_rx_bytes_available(uart, &chars_available) != kDifOk ||
        chars_available == 0) {
      break;
    }

    uint8_t rcv_char;
    CHECK_DIF_OK(dif_uart_bytes_receive(uart, 1, &rcv_char, NULL));
    CHECK_DIF_OK(dif_uart_byte_send_polled(uart, rcv_char));

    //encrypt data
    dif_hmac_t hmac;
    LOG_INFO("GPIO data to write: %d",rcv_char);
    test_setup(mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR), &hmac);
    LOG_INFO("Running HMAC...");
    char kData[10];
    itoa(rcv_char,kData);
    run_test(&hmac, kData, sizeof(kData), (uint8_t *)(&kHmacKey[0]));
    //write data on gpio
    CHECK_DIF_OK(dif_gpio_write_all(gpio, rcv_char << 8));
  }
}
