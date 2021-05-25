/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* This file contains macros for CPUID emulation in x86.
 * Most of the code in this file is from arch/x86/kvm/cpuid.h Linux 3.8.8

 *     Authors:
 *         Qian Ge
 */

#include <stdio.h>
#include <stdlib.h>

#include <sel4/sel4.h>

#include <sel4vm/guest_vm.h>
#include <sel4vm/arch/guest_x86_context.h>

#include "processor/cpuid.h"
#include "processor/cpufeature.h"

#include "vm.h"
#include "guest_state.h"

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
                 : "=a"(*eax),
                 "=b"(*ebx),
                 "=c"(*ecx),
                 "=d"(*edx)
                 : "0"(*eax), "2"(*ecx)
                 : "memory");
}

static int vm_cpuid_virt(unsigned int function, unsigned int index, struct cpuid_val *val, vm_vcpu_t *vcpu)
{
    unsigned int eax, ebx, ecx, edx;

    eax = function;
    ecx = index;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    /* cpuid 1.edx */
    const unsigned int kvm_supported_word0_x86_features =
#ifdef CONFIG_ARCH_X86_64
        F(FPU) | 0 /*F(VME)*/ | 0 /*F(DE)*/ | F(PSE) |
        F(TSC) | F(MSR) | F(PAE) | 0/*F(MCE)*/ |
#else
        F(FPU) | 0 /*F(VME)*/ | 0 /*F(DE)*/ | 0/*F(PSE)*/ |
        F(TSC) | 0/*F(MSR)*/ | 0 /*F(PAE)*/ | 0/*F(MCE)*/ |
#endif
        0 /*F(CX8)*/ | F(APIC) | 0 /* Reserved */ | F(SEP) |
        /*F(MTRR)*/ 0 | F(PGE) | 0/*F(MCA)*/ | F(CMOV) |
        0 /*F(PAT)*/ | 0 /* F(PSE36)*/ | 0 /* PSN */ | 0/*F(CLFLSH)*/ |
        0 /* Reserved, DS, ACPI */ | F(MMX) |
        F(FXSR) | F(XMM) | F(XMM2) | 0/*F(SELFSNOOP)*/ |
        0 /* HTT, TM, Reserved, PBE */;

    /* cpuid 1.ecx */
    const unsigned int kvm_supported_word4_x86_features =
        F(XMM3) | 0 /*F(PCLMULQDQ)*/ | 0 /* DTES64, MONITOR */ |
        0 /* DS-CPL, VMX, SMX, EST */ |
        0 /* TM2 */ | F(SSSE3) | 0 /* CNXT-ID */ | 0 /* Reserved */ |
        0 /*F(FMA)*/ | 0 /*F(CX16)*/ | 0 /* xTPR Update, PDCM */ |
        0 /*F(PCID)*/ | 0 /* Reserved, DCA */ | F(XMM4_1) |
        F(XMM4_2) | 0 /*F(X2APIC)*/ | 0 /*F(MOVBE)*/ | 0 /*F(POPCNT)*/ |
        0 /* Reserved*/ | 0 /*F(AES)*/ | 0/*F(XSAVE)*/ | 0/*F(OSXSAVE)*/ | 0 /*F(AVX)*/ |
        0 /*F(F16C)*/ | 0 /*F(RDRAND)*/;

    /* cpuid 0x80000001.edx */
    const unsigned int kvm_supported_word1_x86_features =
#ifdef CONFIG_ARCH_X86_64
        0 /*F(NX)*/ | F(LM) | F(GBPAGES) | F(SYSCALL) | 0/*F(RDTSCP)*/;  /*support x86 64*/
#else
        0 /*F(NX)*/ | 0/*F(RDTSCP)*/;  /*do not support x86 64*/
#endif

    /* cpuid 0x80000001.ecx */
    const unsigned int kvm_supported_word6_x86_features =
#ifdef CONFIG_ARCH_X86_64
        F(LAHF_LM);
#else
        0;
#endif

#if 0
    /* cpuid 0xC0000001.edx */
    const unsigned int kvm_supported_word5_x86_features =
        F(XSTORE) | F(XSTORE_EN) | F(XCRYPT) | F(XCRYPT_EN) |
        F(ACE2) | F(ACE2_EN) | F(PHE) | F(PHE_EN) |
        F(PMM) | F(PMM_EN);
#endif

    /* cpuid 7.0.ebx */
    const unsigned int kvm_supported_word9_x86_features =
        F(FSGSBASE) | F(BMI1) | F(HLE) | F(AVX2) | F(SMEP) |
        F(BMI2) | F(ERMS) | 0 /*F(INVPCID)*/ | F(RTM);

    /* Virtualize the return value according to the function. */

    ZF_LOGD("cpuid function 0x%x index 0x%x eax 0x%x ebx 0%x ecx 0x%x edx 0x%x\n", function, index, eax, ebx, ecx, edx);

    /* ref: http://www.sandpile.org/x86/cpuid.htm */

    switch (function) {
    case 0: /* Get highest function supported plus vendor ID */
        if (eax > 0xb) {
            eax = 0xb;
        }
        break;

    case 1: /* Processor, info and feature. family, model, stepping */
        edx &= kvm_supported_word0_x86_features;
        ecx &= kvm_supported_word4_x86_features;
        break;

    case 2:
    case 4: /* Cache and TLB descriptor information */
        /* Simply pass through information from native CPUID. */
        break;

    case 7: /* Extended flags */
        ebx &= kvm_supported_word9_x86_features;
        break;

    case 0xa: /* disable performance monitoring */
        eax = ebx = ecx = edx = 0;
        break;

    case 0xb: /* Disable topology information */
        eax = ebx = ecx = edx = 0;
        break;

    case VMM_CPUID_KVM_SIGNATURE: /* Unsupported KVM features. We are not KVM. */
    case VMM_CPUID_KVM_FEATURES:
        eax = ebx = ecx = edx = 0;
        break;

    case 0x80000000: /* Get highest extended function supported */
        break;

    case 0x80000001: /* extended processor info and feature bits */
        ecx &= kvm_supported_word6_x86_features;
        edx &= kvm_supported_word1_x86_features;
        break;

    case 0x80000002: /* Get processor name string. */
    case 0x80000003:
    case 0x80000004:
    case 0x80000005:
    case 0x80000006: /* Cache information. */
        /* Pass through brand name from native CPUID. */
        break;

    case 0x80000008: /* Virtual and Physics address sizes */
        break;

    case 3: /* Processor serial number. */
        break;
    case 5: /* MONITOR / MWAIT */
    case 6: /* Thermal management */
    case 0x80000007: /* Advanced power management - unsupported. */
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        eax = ebx = ecx = edx = 0;
        break;

    /* KVM CPUID functions */
    case 0x40000100:
    case 0x40000200:
    case 0x40000300:
    case 0x40000400:
    case 0x40000500:
    case 0x40000600:
    case 0x40000700:
    case 0x40000800:
    case 0x40000900:
    case 0x40000a00:
    case 0x40000b00:
    case 0x40000c00:
    case 0x40000d00:
    case 0x40000e00:
    case 0x40000f00:
    case 0x40001000:
    case 0x40001100:
    case 0x40001200:
    case 0x40001300:
    case 0x40001400:
    case 0x40001500:
    case 0x40001600:
    case 0x40001700:
    case 0x40001800:
    case 0x40001900:
    case 0x40001a00:
    case 0x40001b00:
    case 0x40001c00:
    case 0x40001d00:
    case 0x40001e00:
    case 0x40001f00:
    case 0x40002000:
    case 0x40002100:
    case 0x40002200:
    case 0x40002300:
    case 0x40002400:
    case 0x40002500:
    case 0x40002600:
    case 0x40002700:
    case 0x40002800:
    case 0x40002900:
    case 0x40002a00:
    case 0x40002b00:
    case 0x40002c00:
    case 0x40002d00:
    case 0x40002e00:
    case 0x40002f00:
    case 0x40003000:
    case 0x40003100:
    case 0x40003200:
    case 0x40003300:
    case 0x40003400:
    case 0x40003500:
    case 0x40003600:
    case 0x40003700:
    case 0x40003800:
    case 0x40003900:
    case 0x40003a00:
    case 0x40003b00:
    case 0x40003c00:
    case 0x40003d00:
    case 0x40003e00:
    case 0x40003f00:
    case 0x40004000:
    case 0x40004100:
    case 0x40004200:
    case 0x40004300:
    case 0x40004400:
    case 0x40004500:
    case 0x40004600:
    case 0x40004700:
    case 0x40004800:
    case 0x40004900:
    case 0x40004a00:
    case 0x40004b00:
    case 0x40004c00:
    case 0x40004d00:
    case 0x40004e00:
    case 0x40004f00:
    case 0x40005000:
    case 0x40005100:
    case 0x40005200:
    case 0x40005300:
    case 0x40005400:
    case 0x40005500:
    case 0x40005600:
    case 0x40005700:
    case 0x40005800:
    case 0x40005900:
    case 0x40005a00:
    case 0x40005b00:
    case 0x40005c00:
    case 0x40005d00:
    case 0x40005e00:
    case 0x40005f00:
    case 0x40006000:
    case 0x40006100:
    case 0x40006200:
    case 0x40006300:
    case 0x40006400:
    case 0x40006500:
    case 0x40006600:
    case 0x40006700:
    case 0x40006800:
    case 0x40006900:
    case 0x40006a00:
    case 0x40006b00:
    case 0x40006c00:
    case 0x40006d00:
    case 0x40006e00:
    case 0x40006f00:
    case 0x40007000:
    case 0x40007100:
    case 0x40007200:
    case 0x40007300:
    case 0x40007400:
    case 0x40007500:
    case 0x40007600:
    case 0x40007700:
    case 0x40007800:
    case 0x40007900:
    case 0x40007a00:
    case 0x40007b00:
    case 0x40007c00:
    case 0x40007d00:
    case 0x40007e00:
    case 0x40007f00:
    case 0x40008000:
    case 0x40008100:
    case 0x40008200:
    case 0x40008300:
    case 0x40008400:
    case 0x40008500:
    case 0x40008600:
    case 0x40008700:
    case 0x40008800:
    case 0x40008900:
    case 0x40008a00:
    case 0x40008b00:
    case 0x40008c00:
    case 0x40008d00:
    case 0x40008e00:
    case 0x40008f00:
    case 0x40009000:
    case 0x40009100:
    case 0x40009200:
    case 0x40009300:
    case 0x40009400:
    case 0x40009500:
    case 0x40009600:
    case 0x40009700:
    case 0x40009800:
    case 0x40009900:
    case 0x40009a00:
    case 0x40009b00:
    case 0x40009c00:
    case 0x40009d00:
    case 0x40009e00:
    case 0x40009f00:
    case 0x4000a000:
    case 0x4000a100:
    case 0x4000a200:
    case 0x4000a300:
    case 0x4000a400:
    case 0x4000a500:
    case 0x4000a600:
    case 0x4000a700:
    case 0x4000a800:
    case 0x4000a900:
    case 0x4000aa00:
    case 0x4000ab00:
    case 0x4000ac00:
    case 0x4000ad00:
    case 0x4000ae00:
    case 0x4000af00:
    case 0x4000b000:
    case 0x4000b100:
    case 0x4000b200:
    case 0x4000b300:
    case 0x4000b400:
    case 0x4000b500:
    case 0x4000b600:
    case 0x4000b700:
    case 0x4000b800:
    case 0x4000b900:
    case 0x4000ba00:
    case 0x4000bb00:
    case 0x4000bc00:
    case 0x4000bd00:
    case 0x4000be00:
    case 0x4000bf00:
    case 0x4000c000:
    case 0x4000c100:
    case 0x4000c200:
    case 0x4000c300:
    case 0x4000c400:
    case 0x4000c500:
    case 0x4000c600:
    case 0x4000c700:
    case 0x4000c800:
    case 0x4000c900:
    case 0x4000ca00:
    case 0x4000cb00:
    case 0x4000cc00:
    case 0x4000cd00:
    case 0x4000ce00:
    case 0x4000cf00:
    case 0x4000d000:
    case 0x4000d100:
    case 0x4000d200:
    case 0x4000d300:
    case 0x4000d400:
    case 0x4000d500:
    case 0x4000d600:
    case 0x4000d700:
    case 0x4000d800:
    case 0x4000d900:
    case 0x4000da00:
    case 0x4000db00:
    case 0x4000dc00:
    case 0x4000dd00:
    case 0x4000de00:
    case 0x4000df00:
    case 0x4000e000:
    case 0x4000e100:
    case 0x4000e200:
    case 0x4000e300:
    case 0x4000e400:
    case 0x4000e500:
    case 0x4000e600:
    case 0x4000e700:
    case 0x4000e800:
    case 0x4000e900:
    case 0x4000ea00:
    case 0x4000eb00:
    case 0x4000ec00:
    case 0x4000ed00:
    case 0x4000ee00:
    case 0x4000ef00:
    case 0x4000f000:
    case 0x4000f100:
    case 0x4000f200:
    case 0x4000f300:
    case 0x4000f400:
    case 0x4000f500:
    case 0x4000f600:
    case 0x4000f700:
    case 0x4000f800:
    case 0x4000f900:
    case 0x4000fa00:
    case 0x4000fb00:
    case 0x4000fc00:
    case 0x4000fd00:
    case 0x4000fe00:
    case 0x4000ff00:
    case 0x40010000:
        eax = ebx = ecx = edx = 0;
        break;
    default:
        /* TODO: Adding more CPUID functions whenever necessary */
        ZF_LOGE("CPUID unimplemented function 0x%x\n", function);
        return -1;

    }

    val->eax = eax;
    val->ebx = ebx;
    val->ecx = ecx;
    val->edx = edx;

    ZF_LOGD("cpuid virt value eax 0x%x ebx 0x%x ecx 0x%x edx 0x%x\n", eax, ebx, ecx, edx);

    return 0;

}

#if 0
/* function 2 entries are STATEFUL. That is, repeated cpuid commands
 * may return different values. This forces us to get_cpu() before
 * issuing the first command, and also to emulate this annoying behavior
 * in kvm_emulate_cpuid() using KVM_CPUID_FLAG_STATE_READ_NEXT */
case 2:
{
    int t, times = entry->eax & 0xff;

    entry->flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
    entry->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
    for (t = 1; t < times; ++t) {
        if (*nent >= maxnent) {
            goto out;
        }

        do_cpuid_1_ent(&entry[t], function, 0);
        entry[t].flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
        ++*nent;
    }
    break;
}
/* function 4 has additional index. */
case 4:
{
    int i, cache_type;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* read more entries until cache_type is zero */
    for (i = 1; ; ++i) {
        if (*nent >= maxnent) {
            goto out;
        }

        cache_type = entry[i - 1].eax & 0x1f;
        if (!cache_type) {
            break;
        }
        do_cpuid_1_ent(&entry[i], function, i);
        entry[i].flags |=
            KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
        ++*nent;
    }
    break;
}
case 7:
{
    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* Mask ebx against host capability word 9 */
    if (index == 0) {
        entry->ebx &= kvm_supported_word9_x86_features;
        cpuid_mask(&entry->ebx, 9);
        // TSC_ADJUST is emulated
        entry->ebx |= F(TSC_ADJUST);
    } else {
        entry->ebx = 0;
    }
    entry->eax = 0;
    entry->ecx = 0;
    entry->edx = 0;
    break;
}
case 9:
break;
case 0xa:   /* Architectural Performance Monitoring */
{
    struct x86_pmu_capability cap;
    union cpuid10_eax eax;
    union cpuid10_edx edx;

    perf_get_x86_pmu_capability(&cap);

    /*
     * Only support guest architectural pmu on a host
     * with architectural pmu.
     */
    if (!cap.version) {
        memset(&cap, 0, sizeof(cap));
    }

    eax.split.version_id = min(cap.version, 2);
    eax.split.num_counters = cap.num_counters_gp;
    eax.split.bit_width = cap.bit_width_gp;
    eax.split.mask_length = cap.events_mask_len;

    edx.split.num_counters_fixed = cap.num_counters_fixed;
    edx.split.bit_width_fixed = cap.bit_width_fixed;
    edx.split.reserved = 0;

    entry->eax = eax.full;
    entry->ebx = cap.events_mask;
    entry->ecx = 0;
    entry->edx = edx.full;
    break;
}
/* function 0xb has additional index. */
case 0xb:
{
    int i, level_type;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* read more entries until level_type is zero */
    for (i = 1; ; ++i) {
        if (*nent >= maxnent) {
            goto out;
        }

        level_type = entry[i - 1].ecx & 0xff00;
        if (!level_type) {
            break;
        }
        do_cpuid_1_ent(&entry[i], function, i);
        entry[i].flags |=
            KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
        ++*nent;
    }
    break;
}
case 0xd:
{
    int idx, i;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    for (idx = 1, i = 1; idx < 64; ++idx) {
        if (*nent >= maxnent) {
            goto out;
        }

        do_cpuid_1_ent(&entry[i], function, idx);
        if (entry[i].eax == 0 || !supported_xcr0_bit(idx)) {
            continue;
        }
        entry[i].flags |=
            KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
        ++*nent;
        ++i;
    }
    break;
}
case KVM_CPUID_SIGNATURE:
{
    static const char signature[12] = "KVMKVMKVM\0\0";
    const unsigned int *sigptr = (const unsigned int *)signature;
    entry->eax = KVM_CPUID_FEATURES;
    entry->ebx = sigptr[0];
    entry->ecx = sigptr[1];
    entry->edx = sigptr[2];
    break;
}
case KVM_CPUID_FEATURES:
entry->eax = (BIT(KVM_FEATURE_CLOCKSOURCE)) |
             (BIT(KVM_FEATURE_NOP_IO_DELAY)) |
             (BIT(KVM_FEATURE_CLOCKSOURCE2)) |
             (BIT(KVM_FEATURE_ASYNC_PF)) |
             (BIT(KVM_FEATURE_PV_EOI)) |
             (BIT(KVM_FEATURE_CLOCKSOURCE_STABLE_BIT));

if (sched_info_on())
{
    entry->eax |= (BIT(KVM_FEATURE_STEAL_TIME));
}

entry->ebx = 0;
entry->ecx = 0;
entry->edx = 0;
break;
case 0x80000019:
entry->ecx = entry->edx = 0;
break;
case 0x8000001a:
break;
case 0x8000001d:
break;
/*Add support for Centaur's CPUID instruction*/
case 0xC0000000:
/*Just support up to 0xC0000004 now*/
entry->eax = min(entry->eax, 0xC0000004);
break;
case 0xC0000001:
entry->edx &= kvm_supported_word5_x86_features;
cpuid_mask(&entry->edx, 5);
break;
case 3: /* Processor serial number */
case 5: /* MONITOR/MWAIT */
case 6: /* Thermal management */
case 0x80000007: /* Advanced power management */
case 0xC0000002:
case 0xC0000003:
case 0xC0000004:
default:
entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
break;
}
#endif

/* VM exit handler: for the CPUID instruction. */
int vm_cpuid_handler(vm_vcpu_t *vcpu)
{

    int ret;
    struct cpuid_val val;

    /* Read parameter information. */
    seL4_Word function, index;
    if (vm_get_thread_context_reg(vcpu, VCPU_CONTEXT_EAX, &function)
        || vm_get_thread_context_reg(vcpu, VCPU_CONTEXT_ECX, &index)) {
        return VM_EXIT_HANDLE_ERROR;
    }

    /* Virtualise the CPUID instruction. */
    ret = vm_cpuid_virt(function, index, &val, vcpu);
    if (ret) {
        return VM_EXIT_HANDLE_ERROR;
    }

    /* Set the return values in guest context. */
    vm_set_thread_context_reg(vcpu, VCPU_CONTEXT_EAX, val.eax);
    vm_set_thread_context_reg(vcpu, VCPU_CONTEXT_EBX, val.ebx);
    vm_set_thread_context_reg(vcpu, VCPU_CONTEXT_ECX, val.ecx);
    vm_set_thread_context_reg(vcpu, VCPU_CONTEXT_EDX, val.edx);

    vm_guest_exit_next_instruction(vcpu->vcpu_arch.guest_state, vcpu->vcpu.cptr);

    /* Return success. */
    return VM_EXIT_HANDLED;
}
