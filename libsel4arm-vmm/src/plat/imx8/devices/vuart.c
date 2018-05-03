/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sel4arm-vmm/plat/devices.h>
#include "../../../vm.h"
#include "../../../devices.h"

#include <sel4platsupport/serial.h>
#include <platsupport/serial.h>

#define VUART_BUFLEN 256

#define VERID      0x00
#define PARAM      0x04
#define GLOBAL     0x08
#define PINCFG     0x0C
#define BAUD       0x10
#define STAT       0x14
#define CTRL       0x18
#define DATA       0x1C
#define MATCH      0x20
#define FIFO       0x28
#define WATER      0x2C
#define UART_SIZE  0x30

typedef volatile struct imx8_uart_regs imx8_uart_regs_t;

#define CTRL_CHAR                   (29)

#define COLOR_BUF_SZ      6
#define NAME_BUF_SZ       64

struct vuart_priv {
    void* regs;
    char buffer[VUART_BUFLEN];
    virq_handle_t virq;
    int buf_pos;
    int int_pending;
    vm_t* vm;
};

struct vuart_node {
  struct vuart_priv* vuart_data;
  struct vuart_node* next;
};
typedef struct vuart_node vuart_node_t;

vuart_node_t* vuarts_active_cursor = NULL;

vuart_node_t* create_vuart_node(struct vuart_priv* vuart_data)
{
  static vuart_node_t* vuarts_last;
  vuart_node_t* new_node = (vuart_node_t*)malloc(sizeof(vuart_node_t));
  if(new_node == NULL)
  {
    return NULL;
  }
  new_node->vuart_data = vuart_data;
  if(NULL == vuarts_last)
  {
    new_node->next = new_node;
    vuarts_active_cursor = new_node;
    vuarts_last = new_node;
  }

  new_node->next = vuarts_last->next;
  vuarts_last->next = new_node;
  vuarts_last = new_node;

  return new_node;
}

void vuart_destroy(vm_t *vm)
{
    vuart_node_t* vuarts_prev = NULL;
    vuart_node_t* vuarts_curr;

    for(vuarts_curr = vuarts_active_cursor; vuarts_curr != NULL;
        vuarts_prev = vuarts_curr, vuarts_curr = vuarts_curr->next)
    {
        if(vuarts_curr->vuart_data->vm == vm)
        {
            if (vuarts_prev == NULL) {
                vuarts_active_cursor = vuarts_curr->next;
            }
            else {
                vuarts_prev->next = vuarts_curr->next;
            }
            free(vuarts_curr->vuart_data);
            free(vuarts_curr);
            return;
        }
    }
}

struct ps_chardevice char_dev;

struct ring_buf {
  char *buf;
  size_t prod;
  size_t cons;
  size_t size;
};
typedef struct ring_buf ring_buf_t;

int ring_buf_empty(ring_buf_t* rbuf)
{
    return (rbuf->prod == rbuf->cons);
}

int ring_buf_full(ring_buf_t* rbuf)
{
    return (((rbuf->prod + 1) % rbuf->size) == rbuf->cons);
}

int ring_buf_put(ring_buf_t* rbuf, char data)
{
    int err = -1;

    if(rbuf)
    {
        rbuf->buf[rbuf->prod] = data;
        rbuf->prod = (rbuf->prod + 1) % rbuf->size;

        if(rbuf->prod == rbuf->cons)
        {
            rbuf->cons = (rbuf->cons + 1) % rbuf->size;
        }

        err = 0;
    }

    return err;
}

int ring_buf_get(ring_buf_t* rbuf, char *data)
{
    int err = -1;

    if(rbuf && data && !ring_buf_empty(rbuf))
    {
        *data = rbuf->buf[rbuf->cons];
        rbuf->cons = (rbuf->cons + 1) % rbuf->size;

        err = 0;
    }

    return err;
}

void ring_buf_reset(ring_buf_t* rbuf)
{
  rbuf->prod = 0;
  rbuf->cons = 0;
  memset(rbuf->buf, 0, rbuf->size);
}

static ring_buf_t input_buffer_ring;

static inline void* vuart_priv_get_regs(struct device* d)
{
    return ((struct vuart_priv*)d->priv)->regs;
}

static inline void cdev_putstring(char * buf, int len)
{
    for(int i = 0; i < len; i++)
    {
        ps_cdev_putchar(&char_dev, buf[i]);
    }
}

struct ps_chardevice* vuart_init(struct ps_io_ops* io_ops)
{
  struct ps_chardevice temp_device;

  /* Initialize input ring buffer */
  input_buffer_ring.buf = (char *)malloc(sizeof(char) * VUART_BUFLEN);
  if (NULL == input_buffer_ring.buf) {
      return NULL;
  }
  input_buffer_ring.size = VUART_BUFLEN;
  ring_buf_reset(&input_buffer_ring);

  /* Initialize virtual console character device */
  if (ps_cdev_init(VCONSOLE_ID, io_ops, &temp_device)) {
    char_dev = temp_device;
  } else {
    printf("Failed to intialize vuart\n");
    return NULL;
  }

  return &char_dev;
}

static void vuart_data_reset(struct device* d)
{
    void* uart_regs = vuart_priv_get_regs(d);

    /* Reset Data gathered from iMX8 TRM - 15.4.3.1.1 */
    const uint32_t reset_data[] = { 0x04010001,  /* verid */
                                    0x00000606,  /* param */
                                    0x00000000,  /* global */
                                    0x00000000,  /* pincfg */
                                    0x0f000004,  /* baud */
                                    0x00c00000,  /* stat */
                                    0x00000000,  /* ctrl */
                                    0x00001000,  /* data */
                                    0x00000000,  /* match */
                                    0x00000000,  /* res0 */
                                    0x00c00055,  /* fifo */
                                    0x00000000}; /* water */

    memcpy(uart_regs, reset_data, sizeof(reset_data));
}

/* Called by the VM to ACK a virtual IRQ */
static void
vuart_ack(void* token)
{
    struct vuart_priv* vuart_data = token;
    imx8_uart_regs_t* uart_regs = (imx8_uart_regs_t*)vuart_data->regs;
    if (uart_regs->stat & LPUART_STAT_RDRF) {
        /* Another IRQ occured */
        vm_inject_IRQ(vuart_data->virq);
    } else {
        vuart_data->int_pending = 0;
    }
}

static void next_active_uart(void)
{
  struct vuart_priv* vuart_data;
  char color_buf[COLOR_BUF_SZ];
  char name[NAME_BUF_SZ];

  vuarts_active_cursor = vuarts_active_cursor->next;
  vuart_data = vuarts_active_cursor->vuart_data;

  ring_buf_reset(&input_buffer_ring);

  sprintf(color_buf, "%s", choose_colour(vuart_data->vm));
  cdev_putstring(color_buf, strlen(color_buf));

  sprintf(name, "\nSwitched to %s",vuart_data->vm->name);
  cdev_putstring(name, strlen(name));

  memset(color_buf, 0, COLOR_BUF_SZ);

  sprintf(color_buf, "%s", choose_colour(NULL));
  cdev_putstring(color_buf, strlen(color_buf));
}

static void
vuart_inject_irq(struct vuart_priv* vuart)
{
    if (vuart->int_pending == 0) {
        vuart->int_pending = 1;
        vm_inject_IRQ(vuart->virq);
    }
}

void vuart_handle_irq(void)
{
  int c;
  imx8_uart_regs_t* uart_regs = (imx8_uart_regs_t*)vuarts_active_cursor->vuart_data->regs;

  do
  {
    c = ps_cdev_getchar(&char_dev);
    if(c == CTRL_CHAR)
    {
      next_active_uart();

      /* By forcing a newline in the console the user will automatically get a prompt after switching.
       * This does mean that if there is a command that wasn't completed when switching, it will go through when
       * switching back.
       */
      ring_buf_put(&input_buffer_ring, '\n');

      uart_regs = (imx8_uart_regs_t*)vuarts_active_cursor->vuart_data->regs;
    }
    else if(c != -1)
    {
      /* Since it is a ring buffer, any old data will just get overwritten */
      ring_buf_put(&input_buffer_ring, (char) c);
    }
  } while(c != -1);

  if(!ring_buf_empty(&input_buffer_ring))
  {
    uart_regs->stat |= LPUART_STAT_RDRF;
    uart_regs->fifo &= ~FIFO_RXEMPT;
    uart_regs->water |= WATERMARK_SET_RXCOUNT(1);
    vuart_inject_irq(vuarts_active_cursor->vuart_data);
  }

}

static void
flush_vconsole_device(struct device* d)
{
    struct vuart_priv *vuart_data;
    char* buf;

    vuart_data = (struct vuart_priv*)d->priv;
    assert(d->priv);
    buf = vuart_data->buffer;

    cdev_putstring(buf, vuart_data->buf_pos);

    vuart_data->buf_pos = 0;
}

static void
vuart_putchar(struct device* d, char c)
{
    struct vuart_priv *vuart_data;
    assert(d->priv);
    imx8_uart_regs_t* uart_regs = (imx8_uart_regs_t*)vuarts_active_cursor->vuart_data->regs;
    vuart_data = (struct vuart_priv*)d->priv;

    if (vuart_data->buf_pos == VUART_BUFLEN) {
        flush_vconsole_device(d);
    }
    assert(vuart_data->buf_pos < VUART_BUFLEN);
    vuart_data->buffer[vuart_data->buf_pos++] = c;

    /* We flush after every character is sent instead of only at newlines. This is so typing in characters on the
     * console doesn't look weird. This can be slow when displaying a lot of information quickly.
     *
     * We could probably implement some SW timeout that flushes every so often if there is data available.
     */
    flush_vconsole_device(d);

    if(uart_regs->stat & ~LPUART_STAT_TDRE)
    {
        uart_regs->stat |= LPUART_STAT_TDRE | LPUART_STAT_TC;
    }

    vuart_inject_irq(vuart_data);
}

static int
handle_vuart_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    uint32_t *reg;
    int offset;
    uint32_t mask;
    UNUSED uint32_t v;
    UNUSED int data;

    imx8_uart_regs_t* uart_regs;

    uart_regs = (imx8_uart_regs_t*)vuart_priv_get_regs(d);

    /* Gather fault information */
    offset = fault_get_address(fault) - d->pstart;
    mask = fault_get_data_mask(fault);

    reg = (uint32_t*)( vuart_priv_get_regs(d) + offset - (offset % 4));

    /* Handle the fault */
    if (offset < 0 || UART_SIZE <= offset) {
        /* Out of range, treat as SBZ */
        fault_set_data(fault, 0);
        return ignore_fault(fault);
    } else if (fault_is_read(fault)) {
        switch(offset) {
        case DATA:
            if(vm->vmid == vuarts_active_cursor->vuart_data->vm->vmid) {
                if(!ring_buf_empty(&input_buffer_ring))
                {
                    ring_buf_get(&input_buffer_ring, (char *)&data);
                    fault_set_data(fault, data);
                }
            }
            if(ring_buf_empty(&input_buffer_ring))
            {
                uart_regs->fifo |= FIFO_RXEMPT;
                uart_regs->stat &= ~LPUART_STAT_RDRF;
                uart_regs->water &= ~WATERMARK_SET_RXCOUNT(1);
            }
            return advance_fault(fault);
        default:
            /* Blindly read out data */
            fault_set_data(fault, *reg);
        }
        return advance_fault(fault);

    } else { /* if(fault_is_write(fault))*/
        switch(offset) {
        case STAT:
            return advance_fault(fault);
        case DATA:
            /* Write character to the uart for the active VM */
            if(vm->vmid == vuarts_active_cursor->vuart_data->vm->vmid) {
                vuart_putchar(d, fault_get_data(fault));
            }
            return advance_fault(fault);
        default:
            /* Blindly write to the device */
            v = *reg & ~mask;
            v |= fault_get_data(fault) & mask;
            *reg = v;
            return advance_fault(fault);
        }
    }
    abandon_fault(fault);
    return -1;
}

const struct device dev_uart0 = {
    .devid = DEV_UART0,
    .attr = DEV_ATTR_EMU,
    .name = "uart0",
    .pstart = UART0_PADDR,
    .size = 0x1000,
    .handle_page_fault = &handle_vuart_fault,
    .priv = NULL
};

int vm_install_vconsole(vm_t* vm, int virq)
{
    int err;
    struct vuart_priv *vuart_data;
    vuart_node_t* vuart_node;
    struct device d;

    d = dev_vconsole;

    /* Initialise the virtual device */
    vuart_data = malloc(sizeof(struct vuart_priv));
    if (NULL == vuart_data) {
        assert(vuart_data);
        return -1;
    }
    memset(vuart_data, 0, sizeof(*vuart_data));
    vuart_data->vm = vm;
    vuart_data->int_pending = 0;

    vuart_data->regs = map_emulated_device(vm, &d);
    assert(vuart_data->regs);
    if (NULL == vuart_data->regs) {
        free(vuart_data);
        return -1;
    }

    d.priv = vuart_data;

    vuart_node = create_vuart_node(vuart_data);
    assert(NULL != vuart_node);
    if (NULL == vuart_node) {
        free(vuart_data);
        return -1;
    }

    vuart_data_reset(&d);

    /* Initialise virtual IRQ */
    vuart_data->virq = vm_virq_new(vm, virq, &vuart_ack, vuart_data);
    if (vuart_data->virq == NULL) {
        vuart_destroy(vm);
        return -1;
    }

    err = vm_add_device(vm, &d);
    assert(!err);
    if (err) {
        vuart_destroy(vm);
        return -1;
    }

    return 0;
}

int vm_uninstall_vconsole(vm_t* vm)
{
    vuart_destroy(vm);
    return 0;
}
