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
#include <sel4arm-vmm/fault.h>
#include "vm.h"

#include <sel4/sel4.h>
#include <sel4/messages.h>
#include <vka/capops.h>

#include <stdlib.h>
#include <sel4/sel4_arch/constants.h>

#include <utils/formats.h>

//#define DEBUG_FAULTS
//#define DEBUG_ERRATA

#ifdef DEBUG_FAULTS
#define DFAULT(...) printf(__VA_ARGS__)
#else
#define DFAULT(...) do{}while(0)
#endif

#ifdef DEBUG_ERRATA
#define DERRATA(...) printf(__VA_ARGS__)
#else
#define DERRATA(...) do{}while(0)
#endif

#ifdef PLAT_EXYNOS5250
/* Stores in thumb mode trigger this errata */
#define HAS_ERRATA766422(f) ( fault_is_write(f) && CPSR_IS_THUMB(fault_get_ctx(f)->cpsr))
#else
#define HAS_ERRATA766422(f) 0
#endif

#define COLOR_ERROR "\033[1;31m"
#define COLOR_NORMAL "\033[0m"

#ifdef CONFIG_ARCH_AARCH64
#define SRT_MASK    0x1f
#else
#define SRT_MASK    0xf
#endif

#define CPSR_THUMB                 BIT(5)
#define CPSR_IS_THUMB(x)           ((x) & CPSR_THUMB)
#define HSR_INST32                 BIT(25)
#define HSR_IS_INST32(x)           ((x) & HSR_INST32)
#define HSR_SYNDROME_VALID         BIT(24)
#define HSR_IS_SYNDROME_VALID(hsr) ((hsr) & HSR_SYNDROME_VALID)
#define HSR_SYNDROME_RT(x)         (((x) >> 16) & SRT_MASK)
#define HSR_SYNDROME_WIDTH(x)      (((x) >> 22) & 0x3)

#define CONTENT_REGS               BIT(0)
#define CONTENT_DATA               BIT(1)
#define CONTENT_INST               BIT(2)
#define CONTENT_WIDTH              BIT(3)
#define CONTENT_STAGE              BIT(4)
#define CONTENT_PMODE              BIT(5)

typedef enum processor_mode {
    PMODE_USER       = 0x10,
    PMODE_FIQ        = 0x11,
    PMODE_IRQ        = 0x12,
    PMODE_SUPERVISOR = 0x13,
    PMODE_ABORT      = 0x17,
    PMODE_HYPERVISOR = 0x1a,
    PMODE_UNDEFINED  = 0x1b,
    PMODE_SYSTEM     = 0x1f,
} processor_mode_t;

/**
 * Data structure representating a fault
 */
struct fault {
/// The VM associated with the fault
    vm_t *vm;
/// Reply capability to the faulting TCB
    cspacepath_t reply_cap;
/// VM registers at the time of the fault
    seL4_UserContext regs;

/// The IPA address of the fault
    seL4_Word base_addr;
/// The IPA address of the fault at the current stage
    seL4_Word addr;
/// The IPA of the instruction which caused the fault
    seL4_Word ip;
/// The data which was to be written, or the data to return to the VM
    seL4_Word data;
/// Fault status register (IL and ISS fields of HSR cp15 register)
    seL4_Word fsr;
/// 'true' if the fault was a prefetch fault rather than a data fault
    bool is_prefetch;
/// 'true' if we should wait for an interrupt before finishing the fault
    bool is_wfi;
/// For multiple str/ldr and 32 bit access, the fault is handled in stages
    int stage;
/// If the instruction requires fetching, cache it here
    seL4_Word instruction;
/// The width of the fault
    enum fault_width width;
/// The mode of the processor
    processor_mode_t pmode;
/// The active content within the fault structure to allow lazy loading
    int content;
};
typedef struct fault fault_t;

/*************************
 *** Primary functions ***
 *************************/
static inline int
thumb_is_32bit_instruction(uint32_t instruction)
{
    switch ((instruction >> 11) & 0x1f) {
    case 0b11101:
    case 0b11110:
    case 0b11111:
        return 1;
    default:
        return 0;
    }
}

static int
maybe_fetch_fault_instruction(fault_t* f)
{
    if ((f->content & CONTENT_INST) == 0) {
        uint32_t inst = 0;
        /* Fetch the instruction */
        if (vm_copyin(f->vm, &inst, f->ip, 4) < 0) {
            return -1;
        }
        /* Fixup the instruction */
#ifdef CONFIG_ARCH_AARCH64
        if (CPSR_IS_THUMB(fault_get_ctx(f)->spsr)) {
#else
        if (CPSR_IS_THUMB(fault_get_ctx(f)->cpsr)) {
#endif
            if (thumb_is_32bit_instruction(inst)) {
                f->fsr |= HSR_INST32;
            }
            if (HSR_IS_INST32(f->fsr)) {
                /* Swap half words for a 32 bit instruction */
                inst = ((inst & 0xffff)) << 16 | ((inst >> 16) & 0xffff);
            } else {
                /* Mask instruction for 16 bit instruction */
                inst &= 0xffff;
            }
        } else {
            /* All ARM instructions are 32 bit so force the HSR flag to be set */
            f->fsr |= HSR_INST32;
        }
        f->instruction = inst;
        f->content |= CONTENT_INST;
    }
    return 0;
}

static int
errata766422_get_rt(fault_t* f, uint32_t hsr)
{
    uint32_t inst;
    int err;
    err = maybe_fetch_fault_instruction(f);
    inst = f->instruction;
    if (err) {
        return err;
    }
    if (HSR_IS_INST32(hsr)) {
        DERRATA("Errata766422 @ 0x%08x (0x%08x)\n", fault_get_ctx(f)->pc, inst);
        if ((inst & 0xff700000) == 0xf8400000) {
            return (inst >> 12) & 0xf;
        } else if ((inst & 0xfff00000) == 0xf8800000) {
            return (inst >> 12) & 0xf;
        } else if ((inst & 0xfff00000) == 0xf0000000) {
            return (inst >> 12) & 0xf;
        } else if ((inst & 0x0e500000) == 0x06400000) {
            return (inst >> 12) & 0xf;
        } else if ((inst & 0xfff00000) == 0xf8000000) {
            return (inst >> 12) & 0xf;
        } else {
            printf("Unable to decode inst 0x%08x\n", inst);
            return -1;
        }
    } else {
        DERRATA("Errata766422 @ 0x%08x (0x%04x)\n", fault_get_ctx(f)->pc, inst);
        /* 16 bit insts */
        if ((inst & 0xf800) == 0x6000) {
            return (inst >> 0) & 0x7;
        } else if ((inst & 0xf800) == 0x9000) {
            return (inst >> 8) & 0x7;
        } else if ((inst & 0xf800) == 0x5000) {
            return (inst >> 0) & 0x7;
        } else if ((inst & 0xfe00) == 0x5400) {
            return (inst >> 0) & 0x7;
        } else if ((inst & 0xf800) == 0x7000) {
            return (inst >> 0) & 0x7;
        } else if ((inst & 0xf800) == 0x8000) {
            return (inst >> 0) & 0x7;
        } else {
            printf("Unable to decode inst 0x%04x\n", inst);
            return -1;
        }
    }
}

static int
decode_instruction(fault_t* f)
{
    uint32_t inst;
    maybe_fetch_fault_instruction(f);
    inst = f->instruction;
    /* Single stage by default */
    f->stage = 1;
    f->content |= CONTENT_STAGE;
    /* Decode */
#ifdef CONFIG_ARCH_AARCH64
    if (CPSR_IS_THUMB(fault_get_ctx(f)->spsr)) {
#else
    if (CPSR_IS_THUMB(fault_get_ctx(f)->cpsr)) {
#endif
        if (thumb_is_32bit_instruction(inst)) {
            f->fsr |= BIT(25); /* 32 bit instruction */
            /* 32 BIT THUMB insts */
            if ((inst & 0xff700000) == 0xf8400000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 12) & 0xf;
            } else if ((inst & 0xfff00000) == 0xf8800000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 12) & 0xf;
            } else if ((inst & 0xfff00000) == 0xf0000000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 12) & 0xf;
            } else if ((inst & 0x0e500000) == 0x06400000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 12) & 0xf;
            } else if ((inst & 0xfff00000) == 0xf8000000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 12) & 0xf;
            } else if ((inst & 0xfe400000) == 0xe8400000) { /* LDRD/STRD */
                int rt;
                if ((f->content & CONTENT_STAGE) == 0) {
                    f->stage = 2;
                    f->width = WIDTH_DOUBLEWORD;
                    f->content |= CONTENT_WIDTH | CONTENT_STAGE;
                }
                f->addr = f->base_addr + ((2 - f->stage) * sizeof(uint32_t));
                rt = ((inst >> 12) & 0xf) + (2 - f->stage);
                return rt;
            } else {
                printf("Unable to decode THUMB32 inst 0x%08x\n", inst);
                print_fault(f);
                return -1;
            }
        } else {
            /* 16 bit THUMB insts */
            if ((inst & 0xf800) == 0x6000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 0) & 0x7;
            } else if ((inst & 0xf800) == 0x9000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 8) & 0x7;
            } else if ((inst & 0xf800) == 0x5000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 0) & 0x7;
            } else if ((inst & 0xfe00) == 0x5400) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 0) & 0x7;
            } else if ((inst & 0xf800) == 0x7000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 0) & 0x7;
            } else if ((inst & 0xf800) == 0x8000) {
                print_fault(f);
                assert(!"No data width");
                return (inst >> 0) & 0x7;
            } else {
                printf("Unable to decode THUMB16 inst 0x%04x\n", inst);
                print_fault(f);
                return -1;
            }
        }
    } else {
        printf("32 bit ARM insts not decoded\n");
        print_fault(f);
        return -1;
    }
}

#ifdef CONFIG_ARCH_AARCH64

static seL4_Word wzr = 0;
static seL4_Word*
decode_rt(int reg, seL4_UserContext* c)
{
    switch (reg) {
    case  0:
        return &c->x0;
    case  1:
        return &c->x1;
    case  2:
        return &c->x2;
    case  3:
        return &c->x3;
    case  4:
        return &c->x4;
    case  5:
        return &c->x5;
    case  6:
        return &c->x6;
    case  7:
        return &c->x7;
    case  8:
        return &c->x8;
    case  9:
        return &c->x9;
    case 10:
        return &c->x10;
    case 11:
        return &c->x11;
    case 12:
        return &c->x12;
    case 13:
        return &c->x13;
    case 14:
        return &c->x14; /* lr */
    case 15:
        return &c->x15;
    case 16:
        return &c->x16;
    case 17:
        return &c->x17;
    case 18:
        return &c->x18;
    case 19:
        return &c->x19;
    case 20:
        return &c->x20;
    case 21:
        return &c->x21;
    case 22:
        return &c->x22;
    case 23:
        return &c->x23;
    case 24:
        return &c->x24;
    case 25:
        return &c->x25;
    case 26:
        return &c->x26;
    case 27:
        return &c->x27;
    case 28:
        return &c->x28;
    case 29:
        return &c->x29;
    case 30:
        return &c->x30;
    case 31:
        return &wzr;
    default:
        printf("invalid reg %d\n", reg);
        assert(!"Invalid register");
        return NULL;
    }
};

#else

static seL4_Word*
decode_rt(int reg, seL4_UserContext* c)
{
    switch (reg) {
    case  0:
        return &c->r0;
    case  1:
        return &c->r1;
    case  2:
        return &c->r2;
    case  3:
        return &c->r3;
    case  4:
        return &c->r4;
    case  5:
        return &c->r5;
    case  6:
        return &c->r6;
    case  7:
        return &c->r7;
    case  8:
        return &c->r8;
    case  9:
        return &c->r9;
    case 10:
        return &c->r10;
    case 11:
        return &c->r11;
    case 12:
        return &c->r12;
    case 13:
        return &c->sp;
    case 14:
        return &c->r14; /* lr */
    case 15:
        return &c->pc;
    default:
        assert(!"Invalid register");
        return NULL;
    }
};

#endif  /* CONFIG_ARCH_AARCH64 */

static int
get_rt(fault_t *f)
{

    /* Save processor mode in fault struct */
    if ((f->content & CONTENT_PMODE)  == 0) {
#ifdef CONFIG_ARCH_AARCH64
#else
        f->pmode = fault_get_ctx(f)->cpsr & 0x1f;
#endif
        f->content |= CONTENT_PMODE;
    }

    int rt;
    if (HSR_IS_SYNDROME_VALID(f->fsr)) {
        if (HAS_ERRATA766422(f)) {
            rt = errata766422_get_rt(f, f->fsr);
        } else {
            rt = HSR_SYNDROME_RT(f->fsr);
        }
    } else {
#ifdef CONFIG_ARCH_AARCH64
        printf("decode_instruction for arm64 not implemented\n");
#endif
        rt = decode_instruction(f);
    }
    assert(rt >= 0);
    return rt;
}

/**
 * Returns a seL4_VCPUReg if the fault affects a banked register.  Otherwise
 * seL4_VCPUReg_Num is returned.  It uses the fault to look up what mode the
 * processor is in and based on rt returns a banked register.
 */
int decode_vcpu_reg(int rt, fault_t* f) {

#ifdef CONFIG_ARCH_AARCH64
    return seL4_VCPUReg_Num;
#else

    assert(f->pmode != PMODE_HYPERVISOR);
    if (f->pmode == PMODE_USER || f->pmode == PMODE_SYSTEM) {
      return seL4_VCPUReg_Num;
    }

    int reg = seL4_VCPUReg_Num;
    if (f->pmode == PMODE_FIQ) {
      switch (rt) {
          case 8:
              reg = seL4_VCPUReg_R8fiq;
              break;
          case 9:
              reg = seL4_VCPUReg_R9fiq;
              break;
          case 10:
              reg = seL4_VCPUReg_R10fiq;
              break;
          case 11:
              reg = seL4_VCPUReg_R11fiq;
              break;
          case 12:
              reg = seL4_VCPUReg_R12fiq;
              break;
          case 13:
              reg = seL4_VCPUReg_SPfiq;
              break;
          case 14:
              reg = seL4_VCPUReg_LRfiq;
              break;
          default:
              reg = seL4_VCPUReg_Num;
          break;
      }

    } else if (rt == 13) {
        switch (f->pmode) {
            case PMODE_IRQ:
                reg = seL4_VCPUReg_SPirq;
                break;
            case PMODE_SUPERVISOR:
                reg = seL4_VCPUReg_SPsvc;
                break;
            case PMODE_ABORT:
                reg = seL4_VCPUReg_SPabt;
                break;
            case PMODE_UNDEFINED:
                reg = seL4_VCPUReg_SPund;
                break;
            default:
                ZF_LOGF("Invalid processor mode");
        }

    } else if (rt == 14) {
        switch (f->pmode) {
            case PMODE_IRQ:
                reg = seL4_VCPUReg_LRirq;
                break;
            case PMODE_SUPERVISOR:
                reg = seL4_VCPUReg_LRsvc;
                break;
            case PMODE_ABORT:
                reg = seL4_VCPUReg_LRabt;
                break;
            case PMODE_UNDEFINED:
                reg = seL4_VCPUReg_LRund;
                break;
            default:
                ZF_LOGF("Invalid processor mode");
        }

    }

    return reg;
#endif
}


fault_t*
fault_init(vm_t* vm)
{
    fault_t *fault;
    int err;
    fault = (fault_t*)malloc(sizeof(*fault));
    if (fault != NULL) {
        fault->vm = vm;
        /* Reserve a slot for saving reply caps */
        err = vka_cspace_alloc_path(vm->vka, &fault->reply_cap);
        if (err) {
            free(fault);
            fault = NULL;
        }
    }
    return fault;
}

int
new_wfi_fault(fault_t *fault)
{
    int err;
    assert(fault_handled(fault));
    fault->is_wfi = 1;
    fault->is_prefetch = 0;
    fault->fsr = 0;
    fault->instruction = 0;
    fault->data = 0;
    fault->width = -1;
    fault->content = 0;
    fault->stage = 1;
    assert(fault->reply_cap.capPtr);
    err = vka_cnode_saveCaller(&fault->reply_cap);
    assert(!err);

    return err;
}

int
new_fault(fault_t* fault)
{
    seL4_Word ip, addr, fsr;
    uint32_t is_prefetch;
    int err;
    vm_t *vm;

    vm = fault->vm;
    assert(vm);

    assert(fault_handled(fault));

    /* First store message registers on the stack to free our message regs */
    is_prefetch = seL4_GetMR(seL4_VMFault_PrefetchFault);
    addr = seL4_GetMR(seL4_VMFault_Addr),
    fsr = seL4_GetMR(seL4_VMFault_FSR);
    ip = seL4_GetMR(seL4_VMFault_IP);
    DFAULT("%s: New fault @ 0x%x from PC 0x%x\n", vm->name, addr, ip);
    /* Create the fault object */
    fault->is_wfi = 0;
    fault->is_prefetch = is_prefetch;
    fault->ip = ip;
    fault->base_addr = fault->addr = addr;
    fault->fsr = fsr;
    fault->instruction = 0;
    fault->data = 0;
    fault->width = -1;
    if (fault_is_data(fault)) {
        if (fault_is_read(fault)) {
            /* No need to load data */
            fault->content = CONTENT_DATA;
        } else {
            fault->content = 0;
        }
        if (HSR_IS_SYNDROME_VALID(fault->fsr)) {
            fault->stage = 1;
            fault->content |= CONTENT_STAGE;
        } else {
            fault->stage = -1;
        }
    } else {
        /* No need to load width or data */
        fault->content = CONTENT_DATA | CONTENT_WIDTH;
    }

    /* Gather additional information */
    assert(fault->reply_cap.capPtr);
    err = vka_cnode_saveCaller(&fault->reply_cap);
    assert(!err);

    return err;
}

int abandon_fault(fault_t* fault)
{
    /* Nothing to do here */
    DFAULT("%s: Release fault @ 0x%x from PC 0x%x\n",
           fault->vm->name, fault->addr, fault->ip);
    return 0;
}


int restart_fault(fault_t* fault)
{
    /* Send the reply */
    fault->stage = 0;
    seL4_MessageInfo_t reply;
    reply = seL4_MessageInfo_new(0, 0, 0, 0);
    DFAULT("%s: Restart fault @ 0x%x from PC 0x%x\n",
           fault->vm->name, fault->addr, fault->ip);
    seL4_Send(fault->reply_cap.capPtr, reply);
    /* Clean up */
    return abandon_fault(fault);
}

int ignore_fault(fault_t* fault)
{
    seL4_UserContext *regs;
    int err;

    regs = fault_get_ctx(fault);
    /* Advance the PC */
    regs->pc += fault_is_32bit_instruction(fault) ? 4 : 2;
    /* Write back CPU registers */
    err = seL4_TCB_WriteRegisters(vm_get_tcb(fault->vm), false, 0,
                                  sizeof(*regs) / sizeof(regs->pc), regs);
    assert(!err);
    if (err) {
        abandon_fault(fault);
        return err;
    }
    /* Reply to thread */
    return restart_fault(fault);
}

int advance_fault(fault_t* fault)
{
    /* If data was to be read, load it into the user context */
    if (fault_is_data(fault) && fault_is_read(fault)) {
        /* Get register opearand */
        int rt  = get_rt(fault);

        /* Decode whether operand is banked */
        int reg = decode_vcpu_reg(rt, fault);
        if (reg == seL4_VCPUReg_Num) {
            /* register is not banked, use seL4_UserContext */
            seL4_Word* reg_ctx = decode_rt(rt, fault_get_ctx(fault));
            *reg_ctx = fault_emulate(fault, *reg_ctx);
        } else {
            /* register is banked, use vcpu invocations */
            seL4_ARM_VCPU_ReadRegs_t res = seL4_ARM_VCPU_ReadRegs(vm_get_vcpu(fault->vm), reg);
            if (res.error) {
              ZF_LOGF("Read registers failed");
              return -1;
            }
            int error = seL4_ARM_VCPU_WriteRegs(vm_get_vcpu(fault->vm), reg, fault_emulate(fault, res.value));
            if (error) {
              ZF_LOGF("Write registers failed");
              return -1;
            }
        }
    }
    DFAULT("%s: Emulate fault @ 0x%x from PC 0x%x\n",
           fault->vm->name, fault->addr, fault->ip);
    /* If this is the final stage of the fault, return to user */
    assert(fault->stage > 0);
    fault->stage--;
    if (fault->stage) {
        /* Data becomes invalid */
        fault->content &= ~CONTENT_DATA;
        return 0;
    } else {
        return ignore_fault(fault);
    }
}

uint32_t fault_emulate(fault_t* f, uint32_t o)
{
    uint32_t n, m, s;
    s = (f->addr & 0x3) * 8;
    m = fault_get_data_mask(f);
    n = fault_get_data(f);
    if (fault_is_read(f)) {
        /* Read data must be shifted to lsb */
        return (o & ~(m >> s)) | ((n & m) >> s);
    } else {
        /* Data to write must be shifted left to compensate for alignment */
        return (o & ~m) | ((n << s) & m);
    }
}

void print_ctx_regs(seL4_UserContext * regs)
{
#define PREG(regs, r)    printf(#r ": 0x%lx\n", (long unsigned int)regs->r)

#ifdef CONFIG_ARCH_AARCH64
    PREG(regs, x0);
    PREG(regs, x1);
    PREG(regs, x2);
    PREG(regs, x3);
    PREG(regs, x4);
    PREG(regs, x5);
    PREG(regs, x6);
    PREG(regs, x7);
    PREG(regs, x8);
    PREG(regs, x9);
    PREG(regs, x10);
    PREG(regs, x11);
    PREG(regs, x12);
    PREG(regs, pc);
    PREG(regs, x14);
    PREG(regs, sp);
    PREG(regs, spsr);

    PREG(regs, x13);
    PREG(regs, x15);
    PREG(regs, x16);
    PREG(regs, x17);
    PREG(regs, x18);
    PREG(regs, x19);
    PREG(regs, x20);
    PREG(regs, x21);

    PREG(regs, x22);
    PREG(regs, x23);
    PREG(regs, x24);
    PREG(regs, x25);
    PREG(regs, x26);
    PREG(regs, x27);
    PREG(regs, x28);
    PREG(regs, x29);
    PREG(regs, x30);
#else
    PREG(regs, r0);
    PREG(regs, r1);
    PREG(regs, r2);
    PREG(regs, r3);
    PREG(regs, r4);
    PREG(regs, r5);
    PREG(regs, r6);
    PREG(regs, r7);
    PREG(regs, r8);
    PREG(regs, r9);
    PREG(regs, r10);
    PREG(regs, r11);
    PREG(regs, r12);
    PREG(regs, pc);
    PREG(regs, r14);
    PREG(regs, sp);
    PREG(regs, cpsr);
#endif

#undef PREG
}

void print_fault(fault_t* fault)
{
    printf("--------\n");
    printf(COLOR_ERROR);
    printf("Pagefault from [%s]: %s %s "
           "@ PC: 0x"XFMT" IPA: 0x"XFMT", FSR: 0x"XFMT "\n",
           fault->vm->name,
           fault_is_read(fault) ? "read" : "write",
           fault_is_prefetch(fault) ? "prefetch fault" : "fault",
           fault->ip,
           fault->addr,
           fault->fsr);
    printf("Context:\n");
    print_ctx_regs(fault_get_ctx(fault));
    printf(COLOR_NORMAL);
    printf("--------\n");
}

uint32_t fault_get_data_mask(fault_t* f)
{
    uint32_t mask = 0;
    uint32_t addr = f->addr;
    switch (fault_get_width(f)) {
    case WIDTH_BYTE:
        mask = 0x000000ff;
        assert(!(addr & 0x0));
        break;
    case WIDTH_HALFWORD:
        mask = 0x0000ffff;
        assert(!(addr & 0x1));
        break;
    case WIDTH_WORD:
    case WIDTH_DOUBLEWORD:
        mask = 0xffffffff;
        assert(!(addr & 0x3));
        break;
    default:
        /* Should never get here... Keep the compiler happy */
        assert(0);
        return 0;
    }
    mask <<= (addr & 0x3) * 8;
    return mask;
}

/*************************
 *** Getters / Setters ***
 *************************/

uint32_t
fault_get_data(fault_t* f)
{
    if ((f->content & CONTENT_DATA) == 0) {
        /* Get register opearand */
        int rt  = get_rt(f);

        /* Decode whether register is banked */
        int reg = decode_vcpu_reg(rt, f);
        uint32_t data;
        if (reg == seL4_VCPUReg_Num) {
            /* Not banked, use seL4_UserContext */
            data = *decode_rt(rt, fault_get_ctx(f));
        } else {
            /* Banked, use VCPU invocations */
            seL4_ARM_VCPU_ReadRegs_t res = seL4_ARM_VCPU_ReadRegs(vm_get_vcpu(f->vm), reg);
            if (res.error) {
              ZF_LOGF("Read registers failed");
            }
            data = res.value;
        }
        fault_set_data(f, data);
    }
    return f->data;
}

void
fault_set_data(fault_t* f, uint32_t data)
{
    f->data = data;
    f->content |= CONTENT_DATA;
}

uint32_t
fault_get_address(fault_t* f)
{
    return f->addr;
}

uint32_t
fault_get_fsr(fault_t* f)
{
    return f->fsr;
}

seL4_UserContext*
fault_get_ctx(fault_t *f)
{
    if ((f->content & CONTENT_REGS) == 0) {
        int err;
        err = seL4_TCB_ReadRegisters(vm_get_tcb(f->vm), false, 0,
                                     sizeof(f->regs) / sizeof(f->regs.pc),
                                     &f->regs);
        assert(!err);
        f->content |= CONTENT_REGS;
    }
    return &f->regs;
}

int fault_handled(fault_t* f)
{
    return f->stage == 0;
}

int fault_is_prefetch(fault_t* f)
{
    return f->is_prefetch;
}

int fault_is_wfi(fault_t *f) {
    return f->is_wfi;
}

int fault_is_32bit_instruction(fault_t* f)
{
    if (fault_is_wfi(f)) {
#ifdef CONFIG_ARCH_AARCH64
        return !CPSR_IS_THUMB(fault_get_ctx(f)->spsr);
#else
        return !CPSR_IS_THUMB(fault_get_ctx(f)->cpsr);
#endif
    }
    if (!HSR_IS_SYNDROME_VALID(f->fsr)) {
        /* (maybe) Trigger a decode to update the fsr. */
        fault_get_width(f);
    }
    return fault_get_fsr(f) & BIT(25);
}

enum fault_width fault_get_width(fault_t* f)
{
    if ((f->content & CONTENT_WIDTH) == 0) {
        if (HSR_IS_SYNDROME_VALID(f->fsr)) {
            switch (HSR_SYNDROME_WIDTH(f->fsr)) {
            case 0:
                f->width = WIDTH_BYTE;
                break;
            case 1:
                f->width = WIDTH_HALFWORD;
                break;
            case 2:
                f->width = WIDTH_WORD;
                break;
            case 3:
                f->width = WIDTH_DOUBLEWORD;
                break;
            default:
                print_fault(f);
                assert(0);
                return 0;
            }
            f->content |= CONTENT_WIDTH;
        } else {
            int rt;
            rt = decode_instruction(f);
            assert(rt >= 0);
        }
    }
    return f->width;
}
