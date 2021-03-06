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
#pragma once

#include <autoconf.h>
#include <sel4arm-vmm/gen_config.h>

/***** Physical Map ****/
#define RAM_BASE  0x40000000
#define RAM_END   0xC0000000
#define RAM_SIZE (RAM_END - RAM_BASE)


/* GPIO */
#if defined CONFIG_PLAT_EXYNOS54XX   /* Odroid-XU/XU3 */
#define GPIO_LEFT_PADDR       0x14000000
#elif defined CONFIG_PLAT_EXYNOS5250 /* Arndale */
#define GPIO_LEFT_PADDR       0x11400000
#else
#error UNKNOWN SoC
#endif
#define GPIO_RIGHT_PADDR      0x13400000

/* DMA */
#define NS_MDMA1_PADDR        0x11C10000
#define NS_MDMA0_PADDR        0x10800000
#define PDMA1_PADDR           0x121B0000
#define PDMA0_PADDR           0x121A0000

/* Video */
#define I2C_HDMI_PADDR        0x12CE0000
#define TV_MIXER_PADDR        0x14450000
#define HDMI_0_PADDR          0x14530000
#define HDMI_1_PADDR          0x14540000
#define HDMI_2_PADDR          0x14550000
#define HDMI_3_PADDR          0x14560000
#define HDMI_4_PADDR          0x14570000
#define HDMI_5_PADDR          0x14580000
#define HDMI_6_PADDR          0x14590000

/* I2C */
#define I2C1_PADDR            0x12C70000
#define I2C2_PADDR            0x12C80000
#define I2C4_PADDR            0x12CA0000

/* USB */
#define USB2_HOST_OHCI_PADDR  0x12120000
#define USB2_HOST_EHCI_PADDR  0x12110000
#define USB2_HOST_CTRL_PADDR  0x12130000

/* UART */
#define UART0_PADDR           0x12C00000
#define UART1_PADDR           0x12C10000
#define UART2_PADDR           0x12C20000
#define UART3_PADDR           0x12C30000

/* System */
#define CHIP_ID_PADDR         0x10000000
#define ALIVE_PADDR           0x10040000
#define SYSREG_PADDR          0x10050000
#define IRQ_COMBINER_PADDR    0x10440000
#define MCT_ADDR              0x101C0000
#define PWM_PADDR             0x12DD0000

/* Clocks */
#define CMU_CPU_PADDR         0x10010000
#define CMU_CORE_PADDR        0x10014000
#define CMU_TOP_PADDR         0x10020000
#define CMU_CDREX_PADDR       0x10030000
#define CMU_MEM_PADDR         0x10038000
#define CMU_ISP_PADDR         0x1001C000
#define CMU_ACP_PADDR         0x10018000

/* SD/eMMC */
#define MSH0_PADDR            0x12200000
#define MSH2_PADDR            0x12220000

/* Timers */
#define WDT_PADDR             0x101d0000

/* System MMU's */
#define SYSMMU_MDMA0_PADDR    0x10A40000
#define SYSMMU_SSS_PADDR      0x10A50000
#define SYSMMU_2D_PADDR       0x10A60000
#define SYSMMU_MFC0_PADDR     0x11200000
#define SYSMMU_MFC1_PADDR     0x11210000
#define SYSMMU_ROTATOR_PADDR  0x11D40000
#define SYSMMU_MDMA1_PADDR    0x11D50000
#define SYSMMU_JPEG_PADDR     0x11F20000
#define SYSMMU_IOPROC_PADDR   0x12360000
#define SYSMMU_RTIC_PADDR     0x12370000
#define SYSMMU_GPS_PADDR      0x12630000
#define SYSMMU_FIMCISP_PADDR  0x13260000
#define SYSMMU_FIMCDRC_PADDR  0x13270000
#define SYSMMU_FIMCSCLC_PADDR 0x13280000
#define SYSMMU_FIMCSCLP_PADDR 0x13290000
#define SYSMMU_FIMCFD_PADDR   0x132A0000
#define SYSMMU_ISPCPU_PADDR   0x132B0000
#define SYSMMU_FIMCODC_PADDR  0x132C0000
#define SYSMMU_FIMCDIS0_PADDR 0x132D0000
#define SYSMMU_FIMCDIS1_PADDR 0x132E0000
#define SYSMMU_FIMC3DNR_PADDR 0x132F0000
#define SYSMMU_FIMCLT0_PADDR  0x13C40000
#define SYSMMU_FIMCLT1_PADDR  0x13C50000
#define SYSMMU_FIMCLT2_PADDR  0x13CA0000
#define SYSMMU_GSCALER0_PADDR 0x13E80000
#define SYSMMU_GSCALER1_PADDR 0x13E90000
#define SYSMMU_GSCALER2_PADDR 0x13EA0000
#define SYSMMU_GSCALER3_PADDR 0x13EB0000
#define SYSMMU_DISP1_PADDR    0x14640000
#define SYSMMU_TV_PADDR       0x14650000

/***** IRQS ******/
