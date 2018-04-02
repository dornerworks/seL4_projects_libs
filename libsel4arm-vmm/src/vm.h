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
#ifndef VM_H
#define VM_H

#include <sel4arm-vmm/vm.h>

struct vm_onode {
    vka_object_t object;
    struct vm_onode *next;
};


/* When differentiating VM's by colour, call this function */
const char* choose_colour(vm_t* vm);

/**
 * Find a device within the VM
 */
struct device* vm_find_device_by_id(vm_t* vm, enum devid id);
struct device* vm_find_device_by_ipa(vm_t* vm, uintptr_t ipa);

struct vchan_device* vm_find_vchan_by_port(vm_t* vm, int port);

static inline seL4_CPtr vm_get_tcb(vm_t* vm)
{
    return vm->tcb.cptr;
}

static inline seL4_CPtr vm_get_vcpu(vm_t* vm)
{
    return vm->vcpu.cptr;
}

vspace_t* vm_get_vspace(vm_t* vm);
vspace_t* vm_get_vmm_vspace(vm_t *vm);

#endif /* VM_H */
