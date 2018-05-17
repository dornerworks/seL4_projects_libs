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

const struct device dev_enet1 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "gem3",
    .pstart = ENET1_PADDR,
    .size = 0x10000,
    .sid = 0x12,
    .handle_page_fault = NULL,
    .priv = NULL
};

const struct device dev_lpcg_enet1 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "lpcg_gem3",
    .pstart = LPCG_ENET1_PADDR,
    .size = 0x10000,
    .handle_page_fault = NULL,
    .priv = NULL
};

const struct device dev_mu0 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "mu0",
    .pstart = MU_PADDR0,
    .size = 0x10000,
    .handle_page_fault = NULL,
    .priv = NULL
};

/* If you are using the default i.MX8 configuration, then it is likely that the SCU
 * has not provided MU1 as a resource to the hardware partition in which this code is running.
 * Do not pass-through this device unless the SCU configuration has been modified.
 *
 * If you are having issues with passing-through any device, then check the SCU partitioning
 * configuration to make sure that device is assigned to the current hardware partition.
 */
const struct device dev_mu1 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "mu1",
    .pstart = MU_PADDR1,
    .size = 0x10000,
    .handle_page_fault = NULL,
    .priv = NULL
};

const struct device dev_mu2 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "mu2",
    .pstart = MU_PADDR2,
    .size = 0x10000,
    .handle_page_fault = NULL,
    .priv = NULL
};

const struct device dev_mu3 = {
    .devid = DEV_CUSTOM,
    .attr = DEV_ATTR_NONE,
    .name = "mu3",
    .pstart = MU_PADDR3,
    .size = 0x10000,
    .handle_page_fault = NULL,
    .priv = NULL
};
