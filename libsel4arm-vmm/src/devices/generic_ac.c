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
#include <stdlib.h>
#include <string.h>

#include "../vm.h"
#include "../devices.h"

//#define AC_DEBUG

#ifdef AC_DEBUG
#define DAC(...) printf(__VA_ARGS__)
#else
#define DAC(...) do{}while(0)
#endif


struct gac_device_priv {
    void* regs;
    void* mask;
    size_t mask_size;
    enum vacdev_action action;
};


static int
handle_gac_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    struct gac_device_priv* gac_device_priv = (struct gac_device_priv*)d->priv;
    volatile uint32_t *reg;
    int offset;

    /* Gather fault information */
    offset = fault_get_address(fault) - d->pstart;
    reg = (volatile uint32_t*)(gac_device_priv->regs + offset);

    if (fault_is_read(fault)) {
        fault_set_data(fault, *reg);
    } else if (offset < gac_device_priv->mask_size) {
        uint32_t mask, result;
        assert((offset & MASK(2)) == 0);
        mask = *(uint32_t*)(gac_device_priv->mask + offset);

        result = fault_emulate(fault, *reg);
        /* Check for a change that involves denied access */
        if ((result ^ *reg) & ~mask) {
            /* Report */
            switch (gac_device_priv->action) {
            case VACDEV_REPORT_AND_MASK:
            case VACDEV_REPORT_ONLY:
                printf("[ac/%s] pc 0x"XFMT" | access violation: bits 0x%08x @ 0x%08x\n",
                       d->name, fault_get_ctx(fault)->pc, (result ^ *reg) & ~mask,
                       fault_get_address(fault));
            default:
                break;
            }
            /* Mask */
            switch (gac_device_priv->action) {
            case VACDEV_REPORT_AND_MASK:
            case VACDEV_MASK_ONLY:
                result = (result & mask) | (*reg & ~mask);
                break;
            case VACDEV_REPORT_ONLY:
                break;
            default:
                assert(!"Invalid action");
            }
        }
        *reg = result;
    }

    return advance_fault(fault);
}


int
vm_install_generic_ac_device(vm_t* vm, const struct device* d, void* mask,
                             size_t mask_size, enum vacdev_action action)
{
    struct gac_device_priv* gac_device_priv;
    struct device dev;
    vspace_t* vmm_vspace;
    vmm_vspace = vm->vmm_vspace;
    int err;

    /* initialise private data */
    gac_device_priv = (struct gac_device_priv*)malloc(sizeof(*gac_device_priv));
    if (gac_device_priv == NULL) {
        return -1;
    }
    gac_device_priv->mask = mask;
    gac_device_priv->mask_size = mask_size;
    gac_device_priv->action = action;

    /* Map the device */
    gac_device_priv->regs = map_device(vmm_vspace, vm->vka, vm->simple,
                                       d->pstart, 0, seL4_AllRights);
    if (gac_device_priv->regs == NULL) {
        free(gac_device_priv);
        return -1;
    }

    /* Add the device */
    dev = *d;
    dev.priv = gac_device_priv;
    dev.handle_page_fault = &handle_gac_fault;
    err = vm_add_device(vm, &dev);
    assert(!err);
    if (err) {
        return -1;
    }

    return 0;
}

