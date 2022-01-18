/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/capops.h>

#include <sel4vm/guest_vm.h>
#include <sel4vm/boot.h>

#include "vm.h"
#include "vgic/vgic.h"

int vm_run(vm_t *vm)
{
    return vm_run_arch(vm);
}

int vm_reset(vm_t *vm)
{
    int err = -1;

    err = vm_reset_vgic(vm);
    if (err) {
        ZF_LOGE("Failed to reset vgic");
        return -1;
    }

    seL4_UserContext regs = {0};
    err = seL4_TCB_WriteRegisters(vm->vcpus[BOOT_VCPU]->tcb.tcb.cptr, false, 0, sizeof(regs) / sizeof(regs.pc), &regs);
    if (err) {
        ZF_LOGE("Failed to clear TCB regs");
        return -1;
    }

    for (int i = 0; i < vm->num_vcpus; i++) {
        vka_free_object(vm->vka, &vm->vcpus[i]->vcpu);
        err = vka_alloc_vcpu(vm->vka, &vm->vcpus[i]->vcpu);
        assert(!err);
        err = seL4_ARM_VCPU_SetTCB(vm->vcpus[i]->vcpu.cptr, vm->vcpus[i]->tcb.tcb.cptr);
        assert(!err);
    }

    return err;
}

int vm_register_unhandled_mem_fault_callback(vm_t *vm, unhandled_mem_fault_callback_fn fault_handler,
                                             void *cookie)
{
    if (!vm) {
        ZF_LOGE("Failed to register mem fault callback: Invalid VM handle");
        return -1;
    }

    if (!fault_handler) {
        ZF_LOGE("Failed to register mem fault callback: Invalid handler");
        return -1;
    }
    vm->mem.unhandled_mem_fault_handler = fault_handler;
    vm->mem.unhandled_mem_fault_cookie = cookie;
    return 0;
}

int vm_register_notification_callback(vm_t *vm, notification_callback_fn notification_callback,
                                      void *cookie)
{
    if (!vm) {
        ZF_LOGE("Failed to register notification callback: Invalid VM handle");
        return -1;
    }

    if (!notification_callback) {
        ZF_LOGE("Failed to register notification callback: Invalid callback");
        return -1;
    }
    vm->run.notification_callback = notification_callback;
    vm->run.notification_callback_cookie = cookie;
    return 0;
}
