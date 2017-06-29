/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */
#ifndef SEL4ARM_VMM_TK1_MAP_H
#define SEL4ARM_VMM_TK1_MAP_H

/***** Physical Map ****/
#define RAM_BASE  0x80000000
#define RAM_END   0x90000000
#define RAM_SIZE (RAM_END - RAM_BASE)

#define USB1_PADDR              0x7d000000
#define USB3_PADDR              0x7d008000
#define SDMMC_PADDR             0x700b0000
#define RTC_PADDR               0x7000e000
#define DATA_MEMORY_PADDR       0x40000000
#define EXCEPTION_VECTORS_PADDR 0x6000f000
#define SYSTEM_REGISTERS_PADDR  0x6000c000
#define ICTLR_PADDR             0x60004000
#define APB_MISC_PADDR          0x70000000
#define FUSE_PADDR              0x7000f000
#define GPIOS_PADDR             0x6000d000

#endif /* SEL4ARM_VMM_TK1_MAP_H */
