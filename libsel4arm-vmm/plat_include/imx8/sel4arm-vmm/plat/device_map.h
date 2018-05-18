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
#define RAM_BASE 0x90000000
#define RAM_SIZE 0x10000000

/* UART */
#define UART0_PADDR     0x5A060000
#define UART0_DMA_PADDR 0x5A460000

/* Ethernet */
#define ENET1_PADDR      0x5B040000
#define LPCG_ENET1_PADDR 0x5B230000

/* Other Devices */
#define MU_PADDR0       0x5D1B0000
#define MU_PADDR1       0x5D1C0000
#define MU_PADDR2       0x5D1D0000
#define MU_PADDR3       0x5D1E0000