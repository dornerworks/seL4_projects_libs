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
#ifndef SEL4ARM_VMM_DEVICES_VGIC_H
#define SEL4ARM_VMM_DEVICES_VGIC_H

#include <sel4arm-vmm/vm.h>

int vm_install_vgic(vm_t* vm);
int vm_reset_vgic(vm_t* vm);

#endif /* SEL4ARM_VMM_DEVICES_VGIC_H */
