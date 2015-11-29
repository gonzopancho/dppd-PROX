/*
  Copyright(c) 2010-2015 Intel Corporation.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _HEAP_H_
#define _HEAP_H_

#include <inttypes.h>

#include "log.h"

struct heap_ref {
	struct heap_elem *elem;   /* timer management */
};

struct heap_elem {
	struct heap_ref *ref;
	uint64_t priority;
};

struct heap {
	uint64_t n_elems;
	struct heap_elem elems[0];
};

static uint64_t heap_size(const struct heap *h)
{
	return h->elems[0].priority;
}

static uint64_t heap_peek_prio(struct heap *h)
{
	return h->elems[1].priority;
}

struct heap *heap_create(uint32_t max_elems, int socket_id);
void heap_dbg(struct heap *h, uint64_t offset);
int heap_contains(struct heap *h, struct heap_ref *ref);
void heap_add(struct heap *h, struct heap_ref *ref, uint64_t priority);
void heap_del(struct heap *h, struct heap_ref *del);
struct heap_ref *heap_pop(struct heap *h);

#endif /* _HEAP_H_ */
