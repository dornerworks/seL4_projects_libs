/*
 * Copyright 2018, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DORNERWORKS_BSD)
 */

#include <stddef.h>

typedef struct ring_buf {
  char *buf;
  size_t prod;
  size_t cons;
  size_t size;
} ring_buf_t;

int ring_buf_empty(ring_buf_t* rbuf);
int ring_buf_full(ring_buf_t* rbuf);
int ring_buf_put(ring_buf_t* rbuf, char data);
int ring_buf_get(ring_buf_t* rbuf, char *data);
void ring_buf_reset(ring_buf_t* rbuf);
