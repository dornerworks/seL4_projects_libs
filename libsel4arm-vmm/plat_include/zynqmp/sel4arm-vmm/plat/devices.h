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
#include <platsupport/io.h>
#include <platsupport/chardev.h>

#define GIC_PADDR   0xF9000000
#define MAX_VIRQS   200

#define dev_vconsole       dev_uart1
#define INTERRUPT_VCONSOLE INTERRUPT_UART1
#define VCONSOLE_ID        1

/* Devices that the VM Needs */
extern const struct device dev_vram;

extern const struct device dev_uart0;
extern const struct device dev_uart1;

extern const struct device dev_gem3;

typedef struct vuart_priv vuart_device_t;

int vm_install_vconsole(vm_t* vm, int virq);
int vm_uninstall_vconsole(vm_t* vm);
struct ps_chardevice* vuart_init(struct ps_io_ops* io_ops);

void vuart_handle_irq(void);
