/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#include <sel4arm-vmm/plat/devices.h>

const struct device dev_uart0 = {
    .devid = DEV_UART0,
    .attr = DEV_ATTR_NONE,
    .name = "uart0",
    .pstart = UART0_PADDR,
    .size = 0x1000,
    .handle_page_fault = NULL,
    .priv = NULL
};

const struct device dev_uart1 = {
    .devid = DEV_UART1,
    .attr = DEV_ATTR_NONE,
    .name = "uart1",
    .pstart = UART1_PADDR,
    .size = 0x1000,
    .handle_page_fault = NULL,
    .priv = NULL
};
