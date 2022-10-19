/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4vm/guest_vm.h>
#include <sel4vm/guest_ram.h>

#include <sel4vmmplatsupport/gen_config.h>

#include "virtio_emul_helpers.h"

static int read_guest_mem(vm_t *vm, uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie)
{
#ifdef CONFIG_VMM_PLATSUPPORT_VIRTIO_CLEAN_CACHE
    seL4_CPtr cap = vspace_get_cap(&vm->mem.vmm_vspace, vaddr);
    if (cap == seL4_CapNull) {
        /* Not sure how we would get here, something has gone pretty wrong */
        ZF_LOGE("Failed to get vmm cap for vaddr: %p", vaddr);
        return -1;
    }
    int error = seL4_ARM_Page_CleanInvalidate_Data(cap, 0, size);
    ZF_LOGF_IF(error, "seL4_ARM_Page_CleanInvalidate_Data failed");
#endif

    /* Copy memory from the guest (vaddr) to our given memory destination (cookie) */
    memcpy(cookie + offset, vaddr, size);

    return 0;
}

static int write_guest_mem(vm_t *vm, uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie)
{
    /* Copy memory to our guest (vaddr) from our given memory location (cookie) */
    memcpy(vaddr, cookie + offset, size);

#ifdef CONFIG_VMM_PLATSUPPORT_VIRTIO_CLEAN_CACHE
    seL4_CPtr cap = vspace_get_cap(&vm->mem.vmm_vspace, vaddr);
    if (cap == seL4_CapNull) {
        /* Not sure how we would get here, something has gone pretty wrong */
        ZF_LOGE("Failed to get vmm cap for vaddr: %p", vaddr);
        return -1;
    }
    int error = seL4_ARM_Page_CleanInvalidate_Data(cap, 0, size);
    ZF_LOGF_IF(error, "seL4_ARM_Page_CleanInvalidate_Data failed");
#endif

    return 0;
}

int vm_guest_write_mem(vm_t *vm, void *data, uintptr_t address, size_t size)
{
    return vm_ram_touch(vm, address, size,  write_guest_mem, data);
}

int vm_guest_read_mem(vm_t *vm, void *data, uintptr_t address, size_t size)
{
    return vm_ram_touch(vm, address, size, read_guest_mem, data);
}
