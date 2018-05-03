/*
 * Copyright 2018, DornerWorks
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

#define GIC_DIST_PADDR     0x51A00000
#define GIC_REDIST_PADDR   0x51B00000
#define MAX_VIRQS          512

#define dev_vconsole       dev_uart0
#define INTERRUPT_VCONSOLE INTERRUPT_UART0_MOD
#define VCONSOLE_ID        0

/* Devices that the VM Needs */
extern const struct device dev_vram;

extern const struct device dev_uart0;
extern const struct device dev_mu;
extern const struct device dev_uart0_dma;

typedef struct vuart_priv vuart_device_t;

int vm_install_vconsole(vm_t* vm, int virq);
int vm_uninstall_vconsole(vm_t* vm);
struct ps_chardevice* vuart_init(struct ps_io_ops* io_ops);

void vuart_handle_irq(void);
