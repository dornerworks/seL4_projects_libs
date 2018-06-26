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

enum vchan_event {
    VCHAN_READ,
    VCHAN_WRITE
};

enum vchan_regs {
    VCHAN_PORT,
    VCHAN_EVENT,
    VCHAN_CHECKSUM,
    VCHAN_LEN,
    VCHAN_NUM_MSG
};

enum vchan_return {
    VCHAN_LEN_RET,
    VCHAN_CHECKSUM_RET,
    VCHAN_NUM_RET
};

#define VCHAN_LEN_SHUTDOWN      0xdead
#define VCHAN_CHECKSUM_SHUTDOWN 0xbeef
