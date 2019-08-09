/*
 * Copyright 2019, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#pragma once

#include <sel4arm-vmm/plat/device_map.h>
#include <sel4arm-vmm/vm.h>

#define GIC_PADDR   0xF9000000
#define MAX_VIRQS   200

/* Devices that the VM Needs */
extern const struct device dev_vram;

extern const struct device dev_uart0;
extern const struct device dev_uart1;

extern const struct device dev_gem3;

typedef void (*print_func_t)(int);

int vm_install_vconsole(vm_t* vm, int virq, struct device *d, print_func_t func);
void vuart_handle_irq(int c);
