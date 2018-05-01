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
#include <autoconf.h>
#include <sel4utils/mapping.h>
#include "vm.h"
#include <stdlib.h>

#include <sel4arm-vmm/devices.h>
#include <sel4arm-vmm/plat/devices.h>

#include <sel4arm-vmm/fault.h>
#include <vka/capops.h>

//#define DEBUG_MAPPINGS

#ifdef DEBUG_MAPPINGS
#define DMAP(...) printf(__VA_ARGS__)
#else
#define DMAP(...) do{}while(0)
#endif

/* the max number of VMs supported */
#define MAX_NUM_VM  10

typedef struct {
    vm_t    *vm;
    cspacepath_t frame_cap;
} multi_map_dev_entry_t;

typedef struct multi_map_dev_info {
    enum devid   devid;
    uintptr_t    paddr;
    cspacepath_t frame_cap;
    int          vm_index;
    multi_map_dev_entry_t   entries[MAX_NUM_VM];
    struct multi_map_dev_info *next;
} multi_map_dev_info_t;

static multi_map_dev_info_t *multi_map_dev_head = NULL;

static multi_map_dev_info_t *
multi_map_dev_find(enum devid devid)
{
    if (multi_map_dev_head == NULL) return NULL;
    multi_map_dev_info_t *head = multi_map_dev_head;
    while (head != NULL) {
        if (head->devid == devid) return head;
        head = head->next;
    }
    return NULL;
}

static multi_map_dev_info_t *
multi_map_dev_find_by_pa(uintptr_t pa)
{
    if (multi_map_dev_head == NULL) return NULL;
    multi_map_dev_info_t *head = multi_map_dev_head;
    while (head != NULL) {
        if (head->paddr == pa) return head;
        head = head->next;
    }
    return NULL;
}

static multi_map_dev_info_t *
multi_map_dev_alloc(enum devid devid, uintptr_t pa)
{
    multi_map_dev_info_t *info;
    info = (multi_map_dev_info_t *)malloc(sizeof(multi_map_dev_info_t));
    if (info == NULL) return NULL;
    bzero((void *)info, sizeof(multi_map_dev_info_t));
    info->devid = devid;
    info->paddr = pa;
    return info;
}

static void
multi_map_dev_free(multi_map_dev_info_t *info)
{
    assert(info);
    free(info);
}

static void
multi_map_dev_insert(multi_map_dev_info_t *info)
{
    info->next = multi_map_dev_head;
    multi_map_dev_head = info;
}


static int
generic_map_page(vka_t* vka, vspace_t* vmm_vspace, vspace_t* vm_vspace,
                 uintptr_t ipa, size_t size, seL4_CapRights_t vm_rights,
                 int cached, void** vmm_vaddr)
{
    vka_object_t frame_obj;
    cspacepath_t frame[2];
    int err;

    /* No vspace supplied, We have already succeeded */
    if (vmm_vspace == NULL && vm_vspace == NULL) {
        return 0;
    }
    assert(size == 0x1000);

    /* Create a frame */
    err = vka_alloc_frame(vka, 12, &frame_obj);
    assert(!err);
    if (err) {
        return -1;
    }

    /* Copy the cap if required */
    if (vm_vspace && vmm_vspace) {
        vka_cspace_make_path(vka, frame_obj.cptr, &frame[0]);
        err = vka_cspace_alloc_path(vka, &frame[1]);
        assert(!err);
        if (err) {
            vka_free_object(vka, &frame_obj);
            return -1;
        }
        err = vka_cnode_copy(&frame[1], &frame[0], seL4_AllRights);
        assert(!err);
        if (err) {
            vka_cspace_free(vka, frame[1].capPtr);
            vka_free_object(vka, &frame_obj);
            return -1;
        }
    } else {
        frame[1] = frame[0];
    }

    /* Map into the vspace of the VM, or copy the cap to the VMM slot */
    if (vm_vspace != NULL) {
        seL4_CPtr cap = frame[0].capPtr;
        void* addr = (void*)ipa;
        reservation_t res;
        /* Map the frame to the VM */
        res = vspace_reserve_range_at(vm_vspace, addr, size, vm_rights, cached);
        assert(res.res);
        if (!res.res) {
            vka_cspace_free(vka, cap);
            if (vm_vspace && vmm_vspace) {
                vka_cspace_free(vka, frame[1].capPtr);
            }
            vka_free_object(vka, &frame_obj);
            return -1;
        }
        err = vspace_map_pages_at_vaddr(vm_vspace, &cap, NULL, addr, 1, 12, res);
        vspace_free_reservation(vm_vspace, res);
        assert(!err);
        if (err) {
            printf("Failed to provide memory\n");
            vka_cspace_free(vka, cap);
            if (vm_vspace && vmm_vspace) {
                vka_cspace_free(vka, frame[1].capPtr);
            }
            vka_free_object(vka, &frame_obj);
            return -1;
        }
    }

    /* Map into the vspace of the VMM, or do nothing */
    if (vmm_vspace != NULL) {
        void *addr;
        seL4_CapRights_t rights = seL4_AllRights;
        seL4_CPtr cap = frame[1].capPtr;
        addr = vspace_map_pages(vmm_vspace, &cap, NULL, rights, 1, 12, cached);
        if (addr == NULL) {
            printf("Failed to provide memory\n");
            if (vm_vspace) {
                vspace_unmap_pages(vm_vspace, (void*)ipa, 1, 12, vka);
                vka_cspace_free(vka, frame[1].capPtr);
            }
            vka_free_object(vka, &frame_obj);
            return -1;
        }
        *vmm_vaddr = addr;
    }

    return 0;
}


void*
map_device(vspace_t *vspace, vka_t* vka, simple_t* simple, uintptr_t paddr,
           uintptr_t _vaddr, seL4_CapRights_t rights)
{
    cspacepath_t frame;
    void* vaddr;
    int err;

    paddr &= ~0xfff;
    vaddr = (void*)(_vaddr &= ~0xfff);

    /* Alocate a slot */
    err = vka_cspace_alloc_path(vka, &frame);
    assert(!err);
    if (err) {
        printf("Failed to allocate cslot\n");
        return NULL;
    }

    /* Find the device cap */
    seL4_Word cookie;
    err = vka_utspace_alloc_at(vka, &frame, kobject_get_type(KOBJECT_FRAME, 12), 12, paddr, &cookie);
    if (err) {
        err = simple_get_frame_cap(simple, (void*)paddr, 12, &frame);
        if (err) {
            printf("Failed to find device cap for 0x%x\n", (uint32_t)paddr);
            //vka_cspace_free(vka, frame.capPtr);
            return NULL;
        }
    }
    /* Map the device */
    if (vaddr) {
        reservation_t res;
        res = vspace_reserve_range_at(vspace, vaddr, 0x1000, rights, 0);
        assert(res.res);
        if (!res.res) {
            printf("Failed to reserve vspace\n");
            vka_cspace_free(vka, frame.capPtr);
            return NULL;
        }
        /* Map in the page */
        err = vspace_map_pages_at_vaddr(vspace, &frame.capPtr, NULL, vaddr,
                                        1, 12, res);
        vspace_free_reservation(vspace, res);
    } else {
        vaddr = vspace_map_pages(vspace, &frame.capPtr, NULL, rights, 1, 12, 0);
        err = (vaddr == 0);
    }
    assert(!err);
    if (err) {
        printf("Failed to provide memory\n");
        vka_cspace_free(vka, frame.capPtr);
        return NULL;
    }
    DMAP("Mapped device ipa0x%x->p0x%x\n", (uint32_t)vaddr, (uint32_t)paddr);
    return vaddr;
}

void*
map_vm_device(vm_t* vm, uintptr_t pa, uintptr_t va, seL4_CapRights_t rights)
{
    return map_device(vm_get_vspace(vm), vm->vka, vm->simple, pa, va, rights);
}

void*
map_emulated_device(vm_t* vm, struct device *d)
{
    cspacepath_t vm_frame, vmm_frame;
    vspace_t *vm_vspace, *vmm_vspace;
    void* vm_addr, *vmm_addr, *first_vmm = NULL;
    reservation_t res;
    vka_object_t frame;
    vka_t* vka;
    size_t size;
    int err;

    vka = vm->vka;
    vm_addr = (void*)d->pstart;
    size = d->size;
    vm_vspace = vm_get_vspace(vm);
    vmm_vspace = vm->vmm_vspace;

    /* Ensure that the inputted size is at least one page and page aligned  */
    assert(size >= BIT(seL4_PageBits));
    assert((size & (BIT(seL4_PageBits)-1)) == 0);

    unsigned int num_pages = size / BIT(seL4_PageBits);

    /* Reserve the Entire Range of the Emulated Device */
    res = vspace_reserve_range_at(vm_vspace, vm_addr, size, seL4_NoRights, 0);
    assert(res.res);
    if (!res.res) {
        return NULL;
    }

    for (int i = 0; i < num_pages; i++) {

        /* Create a frame (and a copy for the VMM) */
        err = vka_alloc_frame(vka, seL4_PageBits, &frame);
        assert(!err);
        if (err) {
            return NULL;
        }
        vka_cspace_make_path(vka, frame.cptr, &vm_frame);
        err = vka_cspace_alloc_path(vka, &vmm_frame);
        assert(!err);
        if (err) {
            vka_free_object(vka, &frame);
            return NULL;
        }
        err = vka_cnode_copy(&vmm_frame, &vm_frame, seL4_AllRights);
        assert(!err);
        if (err) {
            vka_cspace_free(vka, vm_frame.capPtr);
            vka_free_object(vka, &frame);
            return NULL;
        }

        /* Map the frame to the VM */
        DMAP("Mapping emulated device ipa0x%x\n", (uint32_t)vm_addr);
        err = vspace_map_pages_at_vaddr(vm_vspace, &vm_frame.capPtr, NULL, vm_addr,
                                        1, seL4_PageBits, res);
        assert(!err);
        if (err) {
            printf("Failed to provide memory\n");
            vka_cspace_free(vka, vm_frame.capPtr);
            vka_cspace_free(vka, vmm_frame.capPtr);
            vka_free_object(vka, &frame);
            return NULL;
        }

        vmm_addr = vspace_map_pages(vmm_vspace, &vmm_frame.capPtr, NULL, seL4_AllRights,
                                    1, seL4_PageBits, 0);
        assert(vmm_addr);
        if (vmm_addr == NULL) {
            return NULL;
        }

        if (first_vmm == NULL) {
            first_vmm = vmm_addr;
        }

        vm_addr += BIT(seL4_PageBits);
    }
    vspace_free_reservation(vm_vspace, res);

    return first_vmm;
}


void*
map_multi_map_device(vm_t *vm, uintptr_t pa, uintptr_t va,
                     seL4_CapRights_t rights, struct device *d)
{
    int err;
    vspace_t *vm_vspace = vm_get_vspace(vm);
    vka_t *vka = vm->vka;
    seL4_Word cookie;
    void *vaddr = (void *)(va & ~0xfff);
    uintptr_t paddr = pa & ~0xfff;
    int vm_index = 0;
    multi_map_dev_info_t *info = NULL;
    if (d != NULL) {
        info = multi_map_dev_find(d->devid);
    } else {
        info = multi_map_dev_find_by_pa(pa);
    }

    if (info == NULL) {
        DMAP("Need to find the cap first for paddr %x\n", pa);
        info = multi_map_dev_alloc(((d == NULL)? 0 : d->devid), pa);
        if (info == NULL) {
            multi_map_dev_free(info);
            ZF_LOGE("Failed to alloc multi_map_dev_info_t");
            return NULL;
        }
        err = vka_cspace_alloc_path(vka, &info->frame_cap);
        if (err) {
            multi_map_dev_free(info);
            ZF_LOGE("Failed to alloc cslot for frame cap\n");
            return NULL;
        }
        err = vka_utspace_alloc_at(vka, &info->frame_cap,
                kobject_get_type(KOBJECT_FRAME, 12), 12, paddr, &cookie);
        if (err) {
            err = simple_get_frame_cap(vm->simple, (void *)paddr, 12, &info->frame_cap);
            if (err) {
                multi_map_dev_free(info);
                ZF_LOGE("Failed to find device cap for 0x%x\n", (uint32_t)paddr);
                return NULL;
            }
        }

        info->entries[info->vm_index].vm = vm;
        multi_map_dev_insert(info);
        vm_index = info->vm_index;
        info->vm_index++;
        assert(info->vm_index < MAX_NUM_VM);

    } else {
        vm_index = info->vm_index;
        info->entries[vm_index].vm = vm;
        info->vm_index++;
    }

    err = vka_cspace_alloc_path(vka, &info->entries[vm_index].frame_cap);
    if (err) {
        ZF_LOGE("Failed to alloc cslot for per-vm frame cap\n");
        return NULL;
    }
    err = vka_cnode_copy(&info->entries[vm_index].frame_cap,
                         &info->frame_cap, seL4_AllRights);
    if (err) {
        ZF_LOGE("Failed to copy per-vm frame cap\n");
        return NULL;
    }

    if (vaddr) {
        reservation_t res;
        res = vspace_reserve_range_at(vm_vspace, vaddr, 0x1000, rights, 0);
        assert(res.res);

        err = vspace_map_pages_at_vaddr(vm_vspace,
                &info->entries[vm_index].frame_cap.capPtr,
                NULL, vaddr, 1, 12, res);
        vspace_free_reservation(vm_vspace, res);
    } else {
        vaddr = vspace_map_pages(vm_vspace,
                &info->entries[vm_index].frame_cap.capPtr,
                NULL, rights, 1, 12, 0);
        assert(vaddr != 0);
    }
    DMAP("Mapped multi-map device ipa0x%x->p0x%x\n", (uint32_t)vaddr, (uint32_t)paddr);
    return vaddr;
}

void*
map_ram(vspace_t *vspace, vspace_t *vmm_vspace, vka_t* vka, uintptr_t vaddr)
{
    vka_object_t frame_obj;
    cspacepath_t frame[2];

    reservation_t res;
    void* addr;
    int err;

    addr = (void*)(vaddr & ~0xfff);

    /* reserve vspace */
    res = vspace_reserve_range_at(vspace, addr, 0x1000, seL4_AllRights, 1);
    if (!res.res) {
        ZF_LOGF("Failed to reserve range");
        return NULL;
    }

    /* Create a frame */
    err = vka_alloc_frame_maybe_device(vka, 12, true, &frame_obj);
    if (err) {
        ZF_LOGF("Failed vka_alloc_frame_maybe_device");
        vspace_free_reservation(vspace, res);
        return NULL;
    }

    vka_cspace_make_path(vka, frame_obj.cptr, &frame[0]);

    err = vka_cspace_alloc_path(vka, &frame[1]);
    if (err) {
        ZF_LOGF("Failed vka_cspace_alloc_path");
        vka_free_object(vka, &frame_obj);
        vspace_free_reservation(vspace, res);
        return NULL;
    }

    err = vka_cnode_copy(&frame[1], &frame[0], seL4_AllRights);
    if (err) {
        ZF_LOGF("Failed vka_cnode_copy");
        vka_cspace_free(vka, frame[1].capPtr);
        vka_free_object(vka, &frame_obj);
        vspace_free_reservation(vspace, res);
        return NULL;
    }


    /* Map in the frame */
    err = vspace_map_pages_at_vaddr(vspace, &frame[0].capPtr, NULL, addr, 1, 12, res);
    vspace_free_reservation(vspace, res);
    if (err) {
        ZF_LOGF("Failed vspace_map_pages_at_vaddr");
        vka_cspace_free(vka, frame[1].capPtr);
        vka_free_object(vka, &frame_obj);
        return NULL;
    }

    /* Map into the vspace of the VMM to zero memory */
    void *vmm_addr;
    seL4_CapRights_t rights = seL4_AllRights;
    seL4_CPtr cap = frame[1].capPtr;
    vmm_addr = vspace_map_pages(vmm_vspace, &cap, NULL, rights, 1, 12, true);
    if (vmm_addr == NULL) {
        ZF_LOGF("Failed vspace_map_pages");
        vspace_unmap_pages(vspace, (void*)addr, 1, 12, vka);
        vka_cspace_free(vka, frame[1].capPtr);
        vka_free_object(vka, &frame_obj);
        return NULL;
    }
    memset(vmm_addr, 0, PAGE_SIZE_4K);
    /* This also frees the cspace slot we made.  */
    vspace_unmap_pages(vmm_vspace, (void*)vmm_addr, 1, 12, vka);

    return addr;
}

void*
map_vm_ram(vm_t* vm, uintptr_t vaddr)
{
    return map_ram(vm_get_vspace(vm), vm->vmm_vspace, vm->vka, vaddr);
}

void*
map_shared_page(vm_t* vm, uintptr_t ipa, seL4_CapRights_t rights)
{
    void* addr = NULL;
    int ret;
    ret = generic_map_page(vm->vka, vm->vmm_vspace, &vm->vm_vspace, ipa, BIT(12), rights, 0, &addr);
    return ret ? NULL : addr;
}

int
vm_install_ram_only_device(vm_t *vm, const struct device* device) {
    struct device d;
    uintptr_t paddr;
    int err;
    d = *device;
    for (paddr = d.pstart; paddr - d.pstart < d.size; paddr += 0x1000) {
        void* addr;
        addr = map_vm_ram(vm, paddr);
        if (!addr) {
            return -1;
        }
    }
    err = vm_add_device(vm, &d);
    assert(!err);
    return err;
}

int
vm_install_passthrough_device(vm_t* vm, const struct device* device)
{
    struct device d;
    uintptr_t paddr;
    int err;
    d = *device;
    for (paddr = d.pstart; paddr - d.pstart < d.size; paddr += 0x1000) {
        void* addr;
        if (d.attr & DEV_ATTR_MULTI_MAP) {
            addr = map_multi_map_device(vm, paddr, paddr, seL4_AllRights, &d);
        } else {
            addr = map_vm_device(vm, paddr, paddr, seL4_AllRights);
        }
        if (!addr) {
            return -1;
        }
    }
    err = vm_add_device(vm, &d);
    assert(!err);
    return err;
}

int
vm_map_frame(vm_t *vm, seL4_CPtr cap, uintptr_t ipa, size_t size_bits, int cached, seL4_CapRights_t vm_rights)
{
    void* addr = (void*)ipa;
    reservation_t res;
    vspace_t *vm_vspace = vm_get_vspace(vm);
    int err;

    assert(vm_vspace != NULL);
    assert(addr != NULL);

    res = vspace_reserve_range_at(vm_vspace, addr, BIT(size_bits), vm_rights, cached);
    if (!res.res) {
        return -1;
    }
    err = vspace_map_pages_at_vaddr(vm_vspace, &cap, NULL, addr, 1, size_bits, res); //  NULL = cookies 1 = num caps
    vspace_free_reservation(vm_vspace, res);
    if (err) {
        printf("Failed to provide memory\n");
        return -1;
    }

    return 0;
}

static int
handle_listening_fault(struct device* d, vm_t* vm,
                       fault_t* fault)
{
    volatile uint32_t *reg;
    int offset;
    void** map;

    assert(d->priv);
    map = (void**)d->priv;
    offset = fault_get_address(fault) - d->pstart;

    reg = (volatile uint32_t*)(map[offset >> 12] + (offset & MASK(12)));

    printf("[Listener/%s] ", d->name);
    if (fault_is_read(fault)) {
        printf("read ");
        fault_set_data(fault, *reg);
    } else {
        printf("write");
        *reg = fault_emulate(fault, *reg);
    }
    printf(" ");
    fault_print_data(fault);
    printf(" address 0x%08x @ pc 0x%08x\n", fault_get_address(fault),
           fault_get_ctx(fault)->pc);
    return advance_fault(fault);
}


int
vm_install_listening_device(vm_t* vm, const struct device* dev_listening)
{
    struct device d;
    int pages;
    int i;
    void** map;
    int err;
    pages = dev_listening->size >> 12;
    d = *dev_listening;
    d.handle_page_fault = handle_listening_fault;
    /* Build device memory map */
    map = (void**)malloc(sizeof(void*) * pages);
    if (map == NULL) {
        return -1;
    }
    d.priv = map;
    for (i = 0; i < pages; i++) {
        map[i] = map_device(vm->vmm_vspace, vm->vka, vm->simple,
                            d.pstart + (i << 12), 0, seL4_AllRights);
    }
    err = vm_add_device(vm, &d);
    return err;
}


static int
handle_listening_ram_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    volatile uint32_t *reg;
    int offset;

    assert(d->priv);
    offset = fault_get_address(fault) - d->pstart;

    reg = (volatile uint32_t*)(d->priv + offset);

    if (fault_is_read(fault)) {
        fault_set_data(fault, *reg);
        printf("Listener pc0x%x| r0x%x:0x%x\n", fault_get_ctx(fault)->pc,
               fault_get_address(fault), fault_get_data(fault));
    } else {
        printf("Listener pc0x%x| w0x%x:0x%x\n", fault_get_ctx(fault)->pc,
               fault_get_address(fault), fault_get_data(fault));
        *reg = fault_emulate(fault, *reg);
    }
    return advance_fault(fault);
}


const struct device dev_listening_ram = {
    .devid = DEV_CUSTOM,
    .name = "<listing_ram>",
    .pstart = 0x0,
    .size = 0x1000,
    .handle_page_fault = handle_listening_ram_fault,
    .priv = NULL
};


int
vm_install_listening_ram(vm_t* vm, uintptr_t addr, size_t size)
{
    struct device d;
    int err;
    d = dev_listening_ram;
    d.pstart = addr;
    d.size = size;
    d.priv = malloc(0x1000);
    assert(d.priv);
    if (!d.priv) {
        printf("malloc failed\n");
        return -1;
    }
    err = vm_add_device(vm, &d);
    assert(!err);
    if (err) {
        printf("alloc failed\n");
    }
    return err;
}
