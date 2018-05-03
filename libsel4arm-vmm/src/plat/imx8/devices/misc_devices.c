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

const struct device dev_mu = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_MULTI_MAP,
    .name = "mu",
    .pstart = MU_PADDR,
    .size = 0x1000,
    .handle_page_fault = NULL,
    .priv = NULL
};
