/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_DORNERWORKS_BSD)
 */

#include "../../../../vm.h"

extern const struct device dev_vgic_dist;
extern const struct device dev_vgic_redist;
extern const struct device dev_vgic_redist_sgi;

int handle_vgic_maintenance(vm_t* vm, int idx);
