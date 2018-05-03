/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#include <sel4arm-vmm/plat/device_map.h>
#include <sel4arm-vmm/devices.h>

const struct device dev_gem3 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "gem3",
    .pstart = GEM3_PADDR,
    .size = 0x1000,
    .sid = 0x877,
    .handle_page_fault = NULL,
    .priv = NULL
};
