/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#include <autoconf.h>

#ifdef CONFIG_HAVE_GIC_500
#include "vgic500.h"
#else
#include "vgic390.h"
#endif
