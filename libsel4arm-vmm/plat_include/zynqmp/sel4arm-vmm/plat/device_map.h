/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#pragma once

/***** Physical Map ****/
#define RAM_BASE  0x800000000
#define RAM_END   0x810000000
#define RAM_SIZE (RAM_END - RAM_BASE)

/* UART */
#define UART0_PADDR           0xFF000000
#define UART1_PADDR           0xFF010000

/* Misc Devices */
#define GEM3_PADDR            0xFF0E0000
