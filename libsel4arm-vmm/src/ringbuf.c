/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#include <string.h>
#include <sel4arm-vmm/ringbuf.h>

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
