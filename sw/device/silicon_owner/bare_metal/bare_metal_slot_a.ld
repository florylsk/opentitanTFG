/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Linker script for an OpenTitan first Silicon Owner stage.
 *
 * Portions of this file are Ibex-specific.
 *
 * The first Silicon Owner stage kept in flash, and can be loaded into either
 * Slot A (lower half o the flash), or Slot B (upper half of flash), this
 * linker script only targets Slot A.
 */

INCLUDE hw/top_earlgrey/sw/autogen/top_earlgrey_memory.ld

/* Reserving space at the top of the RAM for the stack. */
_stack_size = 0x2000;
_stack_end = ORIGIN(ram_main) + LENGTH(ram_main);
_stack_start = _stack_end - _stack_size;

/* Slot A starts at the start of the eFlash plus the fixed size of the first
 * Silicon Owner stage */
 /* TODO(#9045): Move ROM_EXT size to a common location. */
_slot_start_address = ORIGIN(eflash) + 0x10000;

INCLUDE sw/device/silicon_owner/bare_metal/bare_metal_common.ld
