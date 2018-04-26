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

/*
 * This component controls and maintains the GIC for the VM.
 * IRQs must be registered at init time with vm_virq_new(...)
 * This function creates and registers an IRQ data structure which will be used for IRQ maintenance
 * b) ENABLING: When the VM enables the IRQ, it checks the pending flag for the VM.
 *   - If the IRQ is not pending, we either
 *        1) have not received an IRQ so it is still enabled in seL4
 *        2) have received an IRQ, but ignored it because the VM had disabled it.
 *     In either case, we simply ACK the IRQ with seL4. In case 1), the IRQ will come straight through,
       in case 2), we have ACKed an IRQ that was not yet pending anyway.
 *   - If the IRQ is already pending, we can assume that the VM has yet to ACK the IRQ and take no further
 *     action.
 *   Transitions: b->c
 * c) PIRQ: When an IRQ is received from seL4, seL4 disables the IRQ and sends an async message. When the VMM
 *    receives the message.
 *   - If the IRQ is enabled, we set the pending flag in the VM and inject the appropriate IRQ
 *     leading to state d)
 *   - If the IRQ is disabled, the VMM takes no further action, leading to state b)
 *   Transitions: (enabled)? c->d :  c->b
 * d) When the VM acknowledges the IRQ, an exception is raised and delivered to the VMM. When the VMM
 *    receives the exception, it clears the pending flag and acks the IRQ with seL4, leading back to state c)
 *    Transition: d->c
 * g) When/if the VM disables the IRQ, we may still have an IRQ resident in the GIC. We allow
 *    this IRQ to be delivered to the VM, but subsequent IRQs will not be delivered as seen by state c)
 *    Transitions g->c
 *
 *   NOTE: There is a big assumption that the VM will not manually manipulate our pending flags and
 *         destroy our state. The affects of this will be an IRQ that is never acknowledged and hence,
 *         will never occur again.
 */

#include "vgic.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <vka/vka.h>
#include <vka/capops.h>

#include "../../../../devices.h"

//#define DEBUG_IRQ
//#define DEBUG_DIST

#ifdef DEBUG_IRQ
#define DIRQ(...) do{ printf("VDIST: "); printf(__VA_ARGS__); }while(0)
#else
#define DIRQ(...) do{}while(0)
#endif

#ifdef DEBUG_DIST
#define DDIST(...) do{ printf("VDIST: "); printf(__VA_ARGS__); }while(0)
#else
#define DDIST(...) do{}while(0)
#endif

#define GIC_500_GRP0     (1 << 0)
#define GIC_500_GRP1_NS  (1 << 1)
#define GIC_500_GRP1_S   (1 << 2)
#define GIC_500_ARE_S    (1 << 4)

#define GIC_500_ENABLED GIC_500_ARE_S | GIC_500_GRP1_NS | GIC_500_GRP0

#define GIC_SGI_OFFSET  0x10000

#define GIC_SGI_IRQ_MIN 16
#define GIC_SGI_IRQ_MAX 32

#define IRQ_IDX(irq) ((irq) / 32)
#define IRQ_BIT(irq) (1U << ((irq) % 32))

#define not_pending(...) !is_pending(__VA_ARGS__)
#define sgi_not_pending(...) !sgi_is_pending(__VA_ARGS__)
#define not_active(...)  !is_active(__VA_ARGS__)
#define not_enabled(...) !is_enabled(__VA_ARGS__)
#define sgi_not_enabled(...) !sgi_is_enabled(__VA_ARGS__)

enum gic_dist_action {
    ACTION_READONLY,
    ACTION_PASSTHROUGH,
    ACTION_ENABLE,
    ACTION_ENABLE_SET,
    ACTION_ENABLE_CLR,
    ACTION_PENDING_SET,
    ACTION_PENDING_CLR,
    ACTION_SGI,
    ACTION_UNKNOWN
};

static inline vm_t* virq_get_vm(struct virq_handle* irq)
{
    return irq->vm;
}

static inline void virq_ack(struct virq_handle* irq)
{
    irq->ack(irq->token);
}

/* Memory map for GIC distributer */
struct gic_dist_map {
    uint32_t ctlr;                /* 0x0000 */
    uint32_t typer;               /* 0x0004 */
    uint32_t iidr;                /* 0x0008 */
    uint32_t res1[13];            /* [0x000C, 0x0040) */
    uint32_t setspi_nsr;          /* 0x0040 */
    uint32_t res2;                /* 0x0044 */
    uint32_t clrspi_nsr;          /* 0x0048 */
    uint32_t res3;                /* 0x004C */
    uint32_t setspi_sr;           /* 0x0050 */
    uint32_t res4;                /* 0x0054 */
    uint32_t clrspi_sr;           /* 0x0058 */
    uint32_t res5[9];             /* [0x005C, 0x0080) */
    uint32_t igrouprn[32];        /* [0x0080, 0x0100) */

    uint32_t enable_set[32];        /* [0x100, 0x180) */
    uint32_t enable_clr[32];        /* [0x180, 0x200) */
    uint32_t pending_set[32];       /* [0x200, 0x280) */
    uint32_t pending_clr[32];       /* [0x280, 0x300) */
    uint32_t active_set[32];        /* [0x300, 0x380) */
    uint32_t active_clr[32];        /* [0x380, 0x400) */

    uint32_t priority[255];         /* [0x400, 0x7FC) */
    uint32_t res6;                  /* 0x7FC */

    uint32_t targets[255];          /* [0x800, 0xBFC) */
    uint32_t res7;                  /* 0xBFC */

    uint32_t config[64];            /* [0xC00, 0xD00) */
    uint32_t group_mod[64];         /* [0xD00, 0xE00) */
    uint32_t nsacr[64];             /* [0xE00, 0xF00) */
    uint32_t sgir;                  /* 0xF00 */
    uint32_t res8[3];               /* [0xF00, 0xF10) */
    uint32_t sgi_pending_clr[4];    /* [0xF10, 0xF20) */
    uint32_t sgi_pending_set[4];    /* [0xF20, 0xF30) */
    uint32_t res9[5235];            /* [0x0F30, 0x6100) */

    uint64_t irouter[960];          /* [0x6100, 0x7F00) */
    uint64_t res10[2080];           /* [0x7F00, 0xC000) */
    uint32_t estatusr;              /* 0xC000 */
    uint32_t errtestr;              /* 0xC004 */
    uint32_t res11[31];             /* [0xC008, 0xC084) */
    uint32_t spisr[30];             /* [0xC084, 0xC0FC) */
    uint32_t res12[4021];           /* [0xC0FC, 0xFFD0) */

    uint32_t pidrn[8];              /* [0xFFD0, 0xFFF0) */
    uint32_t cidrn[4];              /* [0xFFD0, 0xFFFC] */
};

/* Memory map for GIC Redistributor Registers for control and physical LPI's */
struct gic_rdist_map {          /* Starting */
    uint32_t    ctlr;           /* 0x0000 */
    uint32_t    iidr;           /* 0x0004 */
    uint64_t    typer;          /* 0x008 */
    uint32_t    res0;           /* 0x0010 */
    uint32_t    waker;          /* 0x0014 */
    uint32_t    res1[21];       /* 0x0018 */
    uint64_t    propbaser;      /* 0x0070 */
    uint64_t    pendbaser;      /* 0x0078 */
    uint32_t    res2[16340];    /* 0x0080 */
    uint32_t    pidr4;          /* 0xFFD0 */
    uint32_t    pidr5;          /* 0xFFD4 */
    uint32_t    pidr6;          /* 0xFFD8 */
    uint32_t    pidr7;          /* 0xFFDC */
    uint32_t    pidr0;          /* 0xFFE0 */
    uint32_t    pidr1;          /* 0xFFE4 */
    uint32_t    pidr2;          /* 0xFFE8 */
    uint32_t    pidr3;          /* 0xFFEC */
    uint32_t    cidr0;          /* 0xFFF0 */
    uint32_t    cidr1;          /* 0xFFF4 */
    uint32_t    cidr2;          /* 0xFFF8 */
    uint32_t    cidr3;          /* 0xFFFC */
};

/* Memory map for the GIC Redistributor Registers for the SGI and PPI's */
struct gic_rdist_sgi_ppi_map {  /* Starting */
    uint32_t    res0[32];       /* 0x0000 */
    uint32_t    igroup[32];     /* 0x0080 */
    uint32_t    isenable[32];   /* 0x0100 */
    uint32_t    icenable[32];   /* 0x0180 */
    uint32_t    ispend[32];     /* 0x0200 */
    uint32_t    icpend[32];     /* 0x0280 */
    uint32_t    isactive[32];   /* 0x0300 */
    uint32_t    icactive[32];   /* 0x0380 */
    uint32_t    ipriorityrn[8]; /* 0x0400 */
    uint32_t    res1[504];      /* 0x0420 */
    uint32_t    icfgrn_ro;      /* 0x0C00 */
    uint32_t    icfgrn_rw;      /* 0x0C04 */
    uint32_t    res2[62];       /* 0x0C08 */
    uint32_t    igrpmod[64];    /* 0x0D00 */
    uint32_t    nsac;           /* 0x0E00 */
    uint32_t    res11[11391];   /* 0x0E04 */
    uint32_t    miscstatsr;     /* 0xC000 */
    uint32_t    res3[31];       /* 0xC004 */
    uint32_t    ppisr;          /* 0xC080 */
    uint32_t    res4[4062];     /* 0xC084 */
};

struct lr_of {
    struct virq_handle* virq_data;
    struct lr_of* next;
};

struct vgic {
/// Mirrors the vcpu list registers
    struct virq_handle* irq[63];
/// IRQs that would not fit in the vcpu list registers
    struct lr_of* lr_overflow;
/// Complete set of virtual irqs
    struct virq_handle* virqs[MAX_VIRQS];
/// Virtual distributer registers
    struct gic_dist_map *dist;
/// Virtual redistributer registers for control and physical LPIs
    struct gic_rdist_map *rdist;
/// Virtual redistributer for SGI and PPIs
    struct gic_rdist_sgi_ppi_map *sgi;
};

static struct virq_handle* virq_find_irq_data(struct vgic* vgic, int virq) {
    int i;
    for (i = 0; i < MAX_VIRQS; i++) {
        if (vgic->virqs[i] && vgic->virqs[i]->virq == virq) {
            return vgic->virqs[i];
        }
    }
    return NULL;
}

static int virq_add(struct vgic* vgic, struct virq_handle* virq_data)
{
    int i;
    for (i = 0; i < MAX_VIRQS; i++) {
        if (vgic->virqs[i] == NULL) {
            vgic->virqs[i] = virq_data;
            return 0;
        }
    }
    return -1;
}

static int virq_init(struct vgic* vgic)
{
    memset(vgic->irq, 0, sizeof(vgic->irq));
    memset(vgic->virqs, 0, sizeof(vgic->virqs));
    vgic->lr_overflow = NULL;
    return 0;
}

static inline struct vgic* vgic_device_get_vgic(struct device* d) {
    assert(d);
    assert(d->priv);
    return (struct vgic*)d->priv;
}

static inline struct gic_dist_map* vgic_priv_get_dist(struct device* d) {
    assert(d);
    assert(d->priv);
    return vgic_device_get_vgic(d)->dist;
}

static inline struct gic_rdist_map* vgic_priv_get_rdist(struct device* d) {
    assert(d);
    assert(d->priv);
    return vgic_device_get_vgic(d)->rdist;
}

static inline struct gic_rdist_sgi_ppi_map* vgic_priv_get_rdist_sgi(struct device* d) {
    assert(d);
    assert(d->priv);
    return vgic_device_get_vgic(d)->sgi;
}

static inline struct virq_handle** vgic_priv_get_lr(struct device* d) {
    assert(d);
    assert(d->priv);
    return vgic_device_get_vgic(d)->irq;
}



static inline void set_pending(struct gic_dist_map* gic_dist, int irq, int v)
{
    if (v) {
        gic_dist->pending_set[IRQ_IDX(irq)] |= IRQ_BIT(irq);
        gic_dist->pending_clr[IRQ_IDX(irq)] |= IRQ_BIT(irq);
    } else {
        gic_dist->pending_set[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
        gic_dist->pending_clr[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
    }
}

static inline int is_pending(struct gic_dist_map* gic_dist, int irq)
{
    return !!(gic_dist->pending_set[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static inline void sgi_set_pending(struct gic_rdist_sgi_ppi_map* gic_sgi, int irq, int v)
{
    if (v) {
        gic_sgi->ispend[IRQ_IDX(irq)] |= IRQ_BIT(irq);
        gic_sgi->icpend[IRQ_IDX(irq)] |= IRQ_BIT(irq);
    } else {
        gic_sgi->ispend[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
        gic_sgi->icpend[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
    }
}

static inline int sgi_is_pending(struct gic_rdist_sgi_ppi_map* gic_sgi, int irq)
{
    return !!(gic_sgi->ispend[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static inline void set_enable(struct gic_dist_map* gic_dist, int irq, int v)
{
    if (v) {
        gic_dist->enable_set[IRQ_IDX(irq)] |= IRQ_BIT(irq);
        gic_dist->enable_clr[IRQ_IDX(irq)] |= IRQ_BIT(irq);
    } else {
        gic_dist->enable_set[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
        gic_dist->enable_clr[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
    }
}

static inline void sgi_set_enable(struct gic_rdist_sgi_ppi_map* gic_sgi, int irq, int v)
{
    if (v) {
        gic_sgi->isenable[IRQ_IDX(irq)] |= IRQ_BIT(irq);
        gic_sgi->icenable[IRQ_IDX(irq)] |= IRQ_BIT(irq);
    } else {
        gic_sgi->isenable[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
        gic_sgi->icenable[IRQ_IDX(irq)] &= ~IRQ_BIT(irq);
    }
}

static inline int is_enabled(struct gic_dist_map* gic_dist, int irq)
{
    return !!(gic_dist->enable_set[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static inline int sgi_is_enabled(struct gic_rdist_sgi_ppi_map* gic_sgi, int irq)
{
    return !!(gic_sgi->isenable[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static inline int is_active(struct gic_dist_map* gic_dist, int irq)
{
    return !!(gic_dist->active_set[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static inline int sgi_is_active(struct gic_rdist_sgi_ppi_map* gic_sgi, int irq)
{
    return !!(gic_sgi->isactive[IRQ_IDX(irq)] & IRQ_BIT(irq));
}

static int list_size = 0;

static int
vgic_vcpu_inject_irq(struct device* d, vm_t *vm, struct virq_handle *irq)
{
    struct vgic* vgic;
    int err;
    int i;

    vgic = vgic_device_get_vgic(d);

    seL4_CPtr vcpu;
    vcpu = vm->vcpu.cptr;
    for (i = 0; i < 64; i++) {
        if (vgic->irq[i] == NULL) {
            break;
        }
    }
    err = seL4_ARM_VCPU_InjectIRQ(vcpu, irq->virq, 0, 0, i);
    assert((i < 4) || err);
    if (!err) {
        /* Shadow */
        vgic->irq[i] = irq;
        return err;
    } else {
        /* Add to overflow list */
        struct lr_of** lrof_ptr;
        struct lr_of* lrof;
        lrof_ptr = &vgic->lr_overflow;
        while (*lrof_ptr != NULL) {
            lrof_ptr = &(*lrof_ptr)->next;
        }
        list_size++;
        lrof = (struct lr_of*)malloc(sizeof(*lrof));
        assert(lrof);
        if (lrof == NULL) {
            return -1;
        }
        lrof->virq_data = irq;
        lrof->next = NULL;
        *lrof_ptr = lrof;
        return 0;
    }
}


int handle_vgic_maintenance(vm_t* vm, int idx)
{
#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->lock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    /* STATE d) */
    struct device* d;
    struct gic_dist_map* gic_dist;
    struct gic_rdist_sgi_ppi_map* gic_sgi;
    struct virq_handle** lr;
    struct lr_of** lrof_ptr;

    d = vm_find_device_by_id(vm, DEV_VGIC_DIST);
    assert(d);
    gic_sgi = vgic_priv_get_rdist_sgi(d);
    gic_dist = vgic_priv_get_dist(d);
    lr = vgic_priv_get_lr(d);
    assert(lr[idx]);

    /* Clear pending */
    DIRQ("Maintenance IRQ %d\n", lr[idx]->virq);
    if (lr[idx]->virq >= GIC_SGI_IRQ_MAX) {
        set_pending(gic_dist, lr[idx]->virq, false);
    } else {
        sgi_set_pending(gic_sgi, lr[idx]->virq, false);
    }
    virq_ack(lr[idx]);

    /* Check the overflow list for pending IRQs */
    lr[idx] = NULL;
    lrof_ptr = &vgic_device_get_vgic(d)->lr_overflow;
    if (*lrof_ptr) {
        struct lr_of* lrof;
        int err;
        lrof = *lrof_ptr;
        *lrof_ptr = lrof->next;
        err = vgic_vcpu_inject_irq(d, vm, lrof->virq_data);
        assert(!err);
        free(lrof);
        list_size--;
    }

#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->unlock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    return 0;
}


static enum gic_dist_action gic_dist_get_action(int offset)
{
    /* Handle the fault
     * The only fields we care about are enable_set/clr
     * We have 2 options for other registers:
     *  a) ignore writes and hope the VM acts appropriately
     *  b) allow write access so the VM thinks there is no problem,
     *     but do not honour them
     */
    if (0x000 <= offset && offset < 0x004) {        /* enable          */
        return ACTION_ENABLE;
    } else if (0x080 <= offset && offset < 0x100) { /* Security        */
        return ACTION_PASSTHROUGH;
    } else if (0x100 <= offset && offset < 0x180) { /* enable_set      */
        return ACTION_ENABLE_SET;
    } else if (0x180 <= offset && offset < 0x200) { /* enable_clr      */
        return ACTION_ENABLE_CLR;
    } else if (0x200 <= offset && offset < 0x280) { /* pending_set     */
        return ACTION_PENDING_SET;
    } else if (0x280 <= offset && offset < 0x300) { /* pending_clr     */
        return ACTION_PENDING_CLR;
    } else if (0xF00 <= offset && offset < 0xF04) { /* sgi_control     */
        return ACTION_PASSTHROUGH;
    } else if (0xF10 <= offset && offset < 0xF10) { /* sgi_pending_clr */
        return ACTION_SGI;
    } else {
        return ACTION_READONLY;
    }
    return ACTION_UNKNOWN;
}

static enum gic_dist_action gic_rdist_get_action(int offset)
{
    return ACTION_READONLY;
}

static enum gic_dist_action gic_sgi_get_action(int offset)
{
    if (0x100 <= offset && offset < 0x180) {        /* enable_set      */
        return ACTION_ENABLE_SET;
    } else if (0x180 <= offset && offset < 0x200) { /* enable_clr      */
        return ACTION_ENABLE_CLR;
    } else {
        return ACTION_READONLY;
    }
    return ACTION_UNKNOWN;
}

static int
vgic_dist_enable(struct device* d, vm_t* vm)
{
    struct gic_dist_map* gic_dist = vgic_priv_get_dist(d);
    DDIST("enabling gic distributer\n");
    gic_dist->ctlr |= GIC_500_GRP1_NS | GIC_500_ARE_S;
    return 0;
}

static int
vgic_dist_disable(struct device* d, vm_t* vm)
{
    struct gic_dist_map* gic_dist = vgic_priv_get_dist(d);
    DDIST("disabling gic distributer\n");
    gic_dist->ctlr &= ~(GIC_500_GRP1_NS | GIC_500_ARE_S);
    return 0;
}

static int
vgic_dist_enable_irq(struct device* d, vm_t* vm, int irq)
{
    struct gic_dist_map* gic_dist;
    struct virq_handle* virq_data;
    struct vgic* vgic;
    gic_dist = vgic_priv_get_dist(d);
    vgic = vgic_device_get_vgic(d);
    if (irq >= GIC_SGI_IRQ_MAX) {
        DDIST("dist enabling irq %d\n", irq);
        set_enable(gic_dist, irq, true);
        virq_data = virq_find_irq_data(vgic, irq);
        if (virq_data) {
            /* STATE b) */
            if (not_pending(gic_dist, virq_data->virq)) {
                DDIST("IRQ not pending\n");
                virq_ack(virq_data);
            }
        } else {
            DDIST("enabled irq %d has no handle\n", irq);
        }
    }
    return 0;
}

static int
vgic_dist_disable_irq(struct device* d, vm_t* vm, int irq)
{
    /* STATE g) */
    struct gic_dist_map* gic_dist = vgic_priv_get_dist(d);
    if (irq >= GIC_SGI_IRQ_MAX) {
        DDIST("dist disabling irq %d\n", irq);
        set_enable(gic_dist, irq, false);
    }
    return 0;
}

static int
vgic_sgi_enable_irq(struct device* d, vm_t* vm, int irq)
{
    struct gic_rdist_sgi_ppi_map* gic_sgi;
    struct virq_handle* virq_data;
    struct vgic* vgic;
    gic_sgi = vgic_priv_get_rdist_sgi(d);
    vgic = vgic_device_get_vgic(d);
    if (irq >= GIC_SGI_IRQ_MIN) {
        DDIST("sgi enabling irq %d\n", irq);
        sgi_set_enable(gic_sgi, irq, true);
        virq_data = virq_find_irq_data(vgic, irq);
        if (virq_data) {
            /* STATE b) */
            if (sgi_not_pending(gic_sgi, virq_data->virq)) {
                DDIST("IRQ not pending\n");
                virq_ack(virq_data);
            }
        } else {
            DDIST("enabled irq %d has no handle\n", irq);
        }
    }
    return 0;
}

static int
vgic_sgi_disable_irq(struct device* d, vm_t* vm, int irq)
{
    /* STATE g) */
    struct gic_rdist_sgi_ppi_map* gic_sgi = vgic_priv_get_rdist_sgi(d);
    if (irq >= GIC_SGI_IRQ_MIN) {
        DDIST("sgi disabling irq %d\n", irq);
        sgi_set_enable(gic_sgi, irq, false);
    }
    return 0;
}

static int
vgic_dist_set_pending_irq(struct device* d, vm_t* vm, int irq)
{
#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->lock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    /* STATE c) */
    struct gic_dist_map* gic_dist;
    struct vgic* vgic;
    struct virq_handle* virq_data;

    gic_dist = vgic_priv_get_dist(d);
    vgic = vgic_device_get_vgic(d);

    virq_data = virq_find_irq_data(vgic, irq);
    /* If it is enables, inject the IRQ */
    if (virq_data && (gic_dist->ctlr & GIC_500_GRP1_NS) && is_enabled(gic_dist, irq)) {
        int err;
        DDIST("Pending set: Inject IRQ from pending set (%d)\n", irq);

        set_pending(gic_dist, virq_data->virq, true);
        err = vgic_vcpu_inject_irq(d, vm, virq_data);
        assert(!err);

#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
        vm->unlock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
        return err;
    } else {
        /* No further action */
        DDIST("IRQ not enabled (%d) for %s\n", irq, vm->name);
    }

#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->unlock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    return 0;
}

static int
vgic_dist_clr_pending_irq(struct device* d, vm_t* vm, int irq)
{
    struct gic_dist_map* gic_dist = vgic_priv_get_dist(d);
    DDIST("clr pending irq %d\n", irq);
    set_pending(gic_dist, irq, false);
    return 0;
}

static int
vgic_sgi_set_pending_irq(struct device* d, vm_t* vm, int irq)
{
#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->lock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    /* STATE c) */
    struct gic_dist_map* gic_dist;
    struct gic_rdist_sgi_ppi_map* gic_sgi;
    struct vgic* vgic;
    struct virq_handle* virq_data;

    gic_dist = vgic_priv_get_dist(d);
    gic_sgi = vgic_priv_get_rdist_sgi(d);
    vgic = vgic_device_get_vgic(d);

    virq_data = virq_find_irq_data(vgic, irq);
    /* If it is enables, inject the IRQ */
    if (virq_data && (gic_dist->ctlr & GIC_500_GRP1_NS) && sgi_is_enabled(gic_sgi, irq)) {
        int err;
        DDIST("Pending set: Inject IRQ from pending set (%d)\n", irq);

        sgi_set_pending(gic_sgi, virq_data->virq, true);
        err = vgic_vcpu_inject_irq(d, vm, virq_data);
        assert(!err);

#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
        vm->unlock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
        return err;
    } else {
        /* No further action */
        DDIST("IRQ not enabled (%d) for %s\n", irq, vm->name);
    }

#ifdef CONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT
    vm->unlock();
#endif //CONCONFIG_LIB_SEL4_ARM_VMM_VCHAN_SUPPORT

    return 0;
}

static int
vgic_sgi_clr_pending_irq(struct device* d, vm_t* vm, int irq)
{
    struct gic_rdist_sgi_ppi_map* gic_sgi = vgic_priv_get_rdist_sgi(d);
    DDIST("clr pending irq %d\n", irq);
    sgi_set_pending(gic_sgi, irq, false);
    return 0;
}

static int
handle_vgic_dist_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    struct gic_dist_map* gic_dist;
    int offset;
    enum gic_dist_action act;
    uint32_t mask;
    uint32_t *reg;

    gic_dist = vgic_priv_get_dist(d);
    mask = fault_get_data_mask(fault);
    offset = fault_get_address(fault) - d->pstart;

    reg = (uint32_t*)( (uintptr_t)gic_dist + (offset - (offset % 4)));

    act = gic_dist_get_action(offset);

    assert(offset >= 0 && offset < d->size);
    /* Out of range */
    if (offset < 0 || offset >= sizeof(struct gic_dist_map)) {
        DDIST("offset out of range %x %x\n", offset, sizeof(struct gic_dist_map));
        return ignore_fault(fault);

    /* Read fault */
    } else if (fault_is_read(fault)) {
        fault_set_data(fault, *reg);
        return advance_fault(fault);
    } else {
        uint32_t data;
        switch (act) {
        case ACTION_READONLY:
            return ignore_fault(fault);

        case ACTION_PASSTHROUGH:
            *reg = fault_emulate(fault, *reg);
            return advance_fault(fault);

        case ACTION_ENABLE:
            *reg = fault_emulate(fault, *reg);
            data = fault_get_data(fault);
            if (data == GIC_500_ENABLED) {
                vgic_dist_enable(d, vm);
            } else if (data == 0) {
                vgic_dist_disable(d, vm);
            } else {
                assert(!"Unknown enable register encoding\n");
            }
            return advance_fault(fault);

        case ACTION_ENABLE_SET:
            data = fault_get_data(fault);
            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already set */
            data &= ~(*reg);
            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x100) * 8;
                vgic_dist_enable_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_ENABLE_CLR:
            data = fault_get_data(fault);
            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already clear */
            data &= *reg;
            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x180) * 8;
                vgic_dist_disable_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_PENDING_SET:
            data = fault_get_data(fault);
            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already set */
            data &= ~(*reg);
            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x200) * 8;
                vgic_dist_set_pending_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_PENDING_CLR:
            data = fault_get_data(fault);
            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already clear */
            data &= *reg;
            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x280) * 8;
                vgic_dist_clr_pending_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_SGI:
            assert(!"vgic SGI not implemented!\n");
            return ignore_fault(fault);

        case ACTION_UNKNOWN:
        default:
            DDIST("Unknown action on offset 0x%x\n", offset);
            return ignore_fault(fault);
        }
    }
    abandon_fault(fault);
    return -1;
}

static int
handle_vgic_rdist_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    struct gic_rdist_map* gic_rdist;
    int offset;
    enum gic_dist_action act;
    uint32_t *reg;

    gic_rdist = vgic_priv_get_rdist(d);
    offset = fault_get_address(fault) - d->pstart;

    reg = (uint32_t*)( (uintptr_t)gic_rdist + (offset - (offset % 4)));

    assert(offset >= 0 && offset < d->size);

    act = gic_rdist_get_action(offset);

    /* Out of range */
    if (offset < 0 || offset >= sizeof(struct gic_rdist_map)) {
        DDIST("rdist offset out of range %x %x\n", offset, sizeof(struct gic_rdist_map));
        return ignore_fault(fault);

    /* Read fault */
    } else if (fault_is_read(fault)) {
        fault_set_data(fault, *reg);
        return advance_fault(fault);
    } else {
        switch (act) {
        case ACTION_READONLY:
            return ignore_fault(fault);

        case ACTION_UNKNOWN:
        default:
            DDIST("Unknown action on offset 0x%x\n", offset);
            return ignore_fault(fault);
        }
    }
    abandon_fault(fault);
    return -1;
}

static int
handle_vgic_sgi_fault(struct device* d, vm_t* vm, fault_t* fault)
{
    struct gic_rdist_sgi_ppi_map* gic_rdist_sgi;
    int offset;
    enum gic_dist_action act;
    uint32_t mask;
    uint32_t *reg;

    gic_rdist_sgi = vgic_priv_get_rdist_sgi(d);
    mask = fault_get_data_mask(fault);
    offset = fault_get_address(fault) - d->pstart;

    reg = (uint32_t*)( (uintptr_t)gic_rdist_sgi + (offset - (offset % 4)));

    assert(offset >= 0 && offset < d->size);

    act = gic_sgi_get_action(offset);

    /* Out of range */
    if (offset < 0 || offset >= sizeof(struct gic_rdist_sgi_ppi_map)) {
        DDIST("sgi offset out of range %x %x\n", offset, sizeof(struct gic_rdist_sgi_ppi_map));
        return ignore_fault(fault);

    /* Read fault */
    } else if (fault_is_read(fault)) {
        fault_set_data(fault, *reg);
        return advance_fault(fault);
    } else {
        uint32_t data;
        switch (act) {
        case ACTION_READONLY:
            return ignore_fault(fault);
        case ACTION_ENABLE_SET:
            data = fault_get_data(fault);

            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already set */
            data &= ~(*reg);

            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x100) * 8;
                vgic_sgi_enable_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_ENABLE_CLR:
            data = fault_get_data(fault);
            /* Mask the data to write */
            data &= mask;
            /* Mask bits that are already clear */
            data &= *reg;
            while (data) {
                int irq;
                irq = CTZ(data);
                data &= ~(1U << irq);
                irq += (offset - 0x180) * 8;
                vgic_sgi_disable_irq(d, vm, irq);
            }
            return ignore_fault(fault);

        case ACTION_UNKNOWN:
        default:
            DDIST("Unknown action on offset 0x%x\n", offset);
            return ignore_fault(fault);
        }
    }
    abandon_fault(fault);
    return -1;
}

static void vgic_dist_reset(struct device* d)
{
    struct gic_dist_map* gic_dist;
    gic_dist = vgic_priv_get_dist(d);
    memset(gic_dist, 0, sizeof(*gic_dist));

    gic_dist->typer            = 0x7B04B0; /* RO */
    gic_dist->iidr             = 0x1043B ; /* RO */

    gic_dist->enable_set[0]    = 0x0000ffff; /* 16bit RO */
    gic_dist->enable_clr[0]    = 0x0000ffff; /* 16bit RO */

    gic_dist->config[0]        = 0xaaaaaaaa; /* RO */

    gic_dist->pidrn[0]         = 0x44;     /* RO */
    gic_dist->pidrn[4]         = 0x92;     /* RO */
    gic_dist->pidrn[5]         = 0xB4;     /* RO */
    gic_dist->pidrn[6]         = 0x3B;     /* RO */

    gic_dist->cidrn[0]         = 0x0D;     /* RO */
    gic_dist->cidrn[1]         = 0xF0;     /* RO */
    gic_dist->cidrn[2]         = 0x05;     /* RO */
    gic_dist->cidrn[3]         = 0xB1;     /* RO */
}

static void vgic_rdist_reset(struct device* d)
{
    struct gic_rdist_map* gic_rdist;
    gic_rdist = vgic_priv_get_rdist(d);

    memset(gic_rdist, 0, sizeof(*gic_rdist));

    gic_rdist->typer           = 0x1;      /* RO */
    gic_rdist->iidr            = 0x1143B;  /* RO */

    gic_rdist->pidr0           = 0x93;     /* RO */
    gic_rdist->pidr1           = 0xB4;     /* RO */
    gic_rdist->pidr2           = 0x3B;     /* RO */
    gic_rdist->pidr4           = 0x44;     /* RO */

    gic_rdist->cidr0           = 0x0D;     /* RO */
    gic_rdist->cidr1           = 0xF0;     /* RO */
    gic_rdist->cidr2           = 0x05;     /* RO */
    gic_rdist->cidr3           = 0xB1;     /* RO */
}

static void vgic_rdist_sgi_reset(struct device* d)
{
    struct gic_rdist_sgi_ppi_map* gic_sgi;
    gic_sgi = vgic_priv_get_rdist_sgi(d);

    memset(gic_sgi, 0, sizeof(*gic_sgi));

    gic_sgi->isactive[0]       = 0xaaaaaaaa;
}

virq_handle_t
vm_virq_new(vm_t* vm, int virq, void (*ack)(void*), void* token)
{
    struct virq_handle* virq_data;
    struct device* vgic_device;
    struct vgic* vgic;
    int err;
    vgic_device = vm_find_device_by_id(vm, DEV_VGIC_DIST);
    assert(vgic_device);
    if (!vgic_device) {
        return NULL;
    }
    vgic = vgic_device_get_vgic(vgic_device);
    assert(vgic);

    virq_data = malloc(sizeof(*virq_data));
    if (!virq_data) {
        return NULL;
    }
    virq_data->virq = virq;
    virq_data->token = token;
    virq_data->ack = ack;
    virq_data->vm = vm;
    virq_data->next = NULL;
    err = virq_add(vgic, virq_data);
    if (err) {
        free(virq_data);
        return NULL;
    }
    return virq_data;
}

int
vm_inject_IRQ(virq_handle_t virq)
{
    struct device* vgic_device;
    vm_t* vm;
    assert(virq);
    vm = virq->vm;

    // vm->lock();

    DIRQ("VM (%s) received IRQ %d\n", vm->name, virq->virq);

    /* Grab a handle to the VGIC */
    vgic_device = vm_find_device_by_id(vm, DEV_VGIC_DIST);
    if (vgic_device == NULL) {
        return -1;
    }

    if (virq->virq >= GIC_SGI_IRQ_MAX) {
        vgic_dist_set_pending_irq(vgic_device, vm, virq->virq);
    } else {
        vgic_sgi_set_pending_irq(vgic_device, vm, virq->virq);
    }

    if (!fault_handled(vm->fault) && fault_is_wfi(vm->fault)) {
        ignore_fault(vm->fault);
    }

    // vm->unlock();

    return 0;
}

/*
 * 1) completely virtualize the distributor
 * 2) completely virtualize the redistributor
 * 3) completely virtualize the SGI page of the redistributor
 */
int
vm_install_vgic(vm_t* vm)
{
    struct device dist;
    struct device rdist;
    struct device sgi;
    struct vgic* vgic;
    int err;

    vgic = malloc(sizeof(*vgic));
    if (!vgic) {
        assert(!"Unable to malloc memory for VGIC");
        return -1;
    }
    err = virq_init(vgic);
    if (err) {
        free(vgic);
        return -1;
    }

    /* Distributor */
    dist = dev_vgic_dist;
    vgic->dist = map_emulated_device(vm, &dev_vgic_dist);
    assert(vgic->dist);
    if (vgic->dist == NULL) {
        return -1;
    }

    dist.priv = (void*)vgic;
    vgic_dist_reset(&dist);
    err = vm_add_device(vm, &dist);
    if (err) {
        free(dist.priv);
        return -1;
    }

    /* Redistributor */
    rdist = dev_vgic_redist;
    vgic->rdist = map_emulated_device(vm, &dev_vgic_redist);
    assert(vgic->rdist);
    if (vgic->rdist == NULL) {
        return -1;
    }

    rdist.priv = (void*)vgic;
    vgic_rdist_reset(&rdist);
    err = vm_add_device(vm, &rdist);
    if (err) {
        free(rdist.priv);
        return -1;
    }

    /* Redistributor SGI */
    sgi = dev_vgic_redist_sgi;
    vgic->sgi = map_emulated_device(vm, &dev_vgic_redist_sgi);
    assert(vgic->sgi);
    if (vgic->sgi == NULL) {
        return -1;
    }

    sgi.priv = (void*)vgic;
    vgic_rdist_sgi_reset(&sgi);
    err = vm_add_device(vm, &sgi);
    if (err) {
        free(sgi.priv);
        return -1;
    }

    return 0;
}

const struct device dev_vgic_dist = {
    .devid = DEV_VGIC_DIST,
    .attr = DEV_ATTR_EMU,
    .name = "vgic.distributor",
    .pstart = GIC_DIST_PADDR,
    .size = 0x10000,
    .handle_page_fault = &handle_vgic_dist_fault,
    .priv = NULL,
};

const struct device dev_vgic_redist = {
    .devid = DEV_VGIC_REDIST,
    .attr = DEV_ATTR_EMU,
    .name = "vgic.redistributor",
    .pstart = GIC_REDIST_PADDR,
    .size = 0x10000,
    .handle_page_fault = &handle_vgic_rdist_fault,
    .priv = NULL,
};

const struct device dev_vgic_redist_sgi = {
    .devid = DEV_VGIC_REDIST_SGI,
    .attr = DEV_ATTR_EMU,
    .name = "vgic.redistributor_sgi",
    .pstart = GIC_REDIST_PADDR + GIC_SGI_OFFSET,
    .size = 0x10000,
    .handle_page_fault = &handle_vgic_sgi_fault,
    .priv = NULL,
};
