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

#include <string.h>
#include <stddef.h>
#include <rte_malloc.h>
#include <rte_version.h>

#include "heap.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

static void _heap_dbg2(struct heap *h, int i, size_t indent_len, uint64_t offset)
{
	char indent[64] = {0};
	uint32_t left_child = i*2;
	uint32_t right_child = i*2 + 1;

	for (size_t j = 0; j < indent_len*2 && j < sizeof(indent); ++j)
		indent[j] = ' ';

	if (right_child <= h->n_elems) {
		plogx_info("%s%"PRIu64"\n", indent, h->elems[left_child].priority - offset);
		_heap_dbg2(h, left_child, indent_len + 1, offset);
		plogx_info("%s%"PRIu64"\n", indent, h->elems[right_child].priority - offset);
		_heap_dbg2(h, right_child, indent_len + 1, offset);
	}
	else if (left_child <= h->n_elems) {
		plogx_info("%s%"PRIu64"\n", indent, h->elems[left_child].priority - offset);
		_heap_dbg2(h, left_child, indent_len + 1, offset);
	}
}

void heap_dbg(struct heap *h, uint64_t offset)
{
	plogx_info("Heap occupancy: %"PRIu64"/%"PRIu64"", h->n_elems, heap_size(h));
	if (h->n_elems) {
		plogx_info("%"PRIu64"\n", h->elems[1].priority - offset);
		_heap_dbg2(h, 1, 0, offset);
	}
}

int heap_contains(struct heap *h, struct heap_ref *ref)
{
	int occur = 0;

	for (uint32_t i = 0; i < h->n_elems; ++i) {
		occur += h->elems[i + 1].ref == ref;
	}
	return occur;
}

static int heap_check_prop(struct heap *h, uint32_t parent)
{
	uint32_t left_child = parent*2;
	uint32_t right_child = parent*2 + 1;

	if (right_child <= h->n_elems) {
		return h->elems[right_child].priority > h->elems[parent].priority &&
			h->elems[left_child].priority > h->elems[parent].priority &&
			heap_check_prop(h, right_child) &&
			heap_check_prop(h, left_child);
	}
	else if (left_child <= h->n_elems) {
		return 	h->elems[left_child].priority > h->elems[parent].priority &&
			heap_check_prop(h, left_child);
	}
	else
		return 1;
}

struct heap *heap_create(uint32_t max_elems, int socket_id)
{
	struct heap *ret;
	size_t mem_size = 0;

	/* max_elems + 1 since index start at 1. Store total number of
	   elements in the first entry (which is unused otherwise). */
	mem_size += sizeof(struct heap);
	mem_size += sizeof(((struct heap *)(0))->elems[0]) * (max_elems + 1);

	ret = rte_zmalloc_socket(NULL, mem_size, RTE_CACHE_LINE_SIZE, socket_id);

	ret->elems[0].priority = max_elems;

	return ret;
}

void heap_add(struct heap *h, struct heap_ref *ref, uint64_t priority)
{
	int new_idx = 1 + h->n_elems;
	int parent = new_idx/2;
	while (new_idx != 1 && priority < h->elems[parent].priority) {
		h->elems[new_idx] = h->elems[parent];
		h->elems[new_idx].ref->elem = &h->elems[new_idx];
		new_idx /= 2;
		parent /= 2;
	}

	h->elems[new_idx].ref = ref;
	h->elems[new_idx].priority = priority;
	h->n_elems++;

	ref->elem = &h->elems[new_idx];
}

void heap_del(struct heap *h, struct heap_ref *del)
{
	uint32_t smaller_child, left_child, right_child, parent;
	int del_idx = del->elem - h->elems;
	del->elem = NULL;

	uint64_t priority = h->elems[h->n_elems].priority;
	struct heap_ref *dest = h->elems[h->n_elems].ref;
	h->n_elems--;

	/* Deleting the last entry from the heap is done without
	   updating other elements. */

	if ((uint32_t)del_idx == h->n_elems + 1)
		return ;


	/* Deleting an element from the heap at an arbitrary position
	   requires using the last element as a replacement
	   (represented by priority/dest). */
	while (1) {
		parent = del_idx/2;

		if (parent == 0) {
			break;
		}
		else if (h->elems[parent].priority < priority) {
			h->elems[del_idx].priority = priority;
			h->elems[del_idx].ref = dest;
			break;
		}
		else {
			h->elems[del_idx] = h->elems[parent];
			h->elems[del_idx].ref->elem = &h->elems[del_idx];
			del_idx = parent;
		}
	}

	while (1) {
		left_child = del_idx*2;
		right_child = del_idx*2 + 1;
		if (right_child <= h->n_elems) {
			if (h->elems[left_child].priority > priority && h->elems[right_child].priority > priority) {
				h->elems[del_idx].priority = priority;
				h->elems[del_idx].ref = dest;
				dest->elem = &h->elems[del_idx];
				break;
			}
			else {
				smaller_child = h->elems[left_child].priority < h->elems[right_child].priority? left_child : right_child;
				h->elems[del_idx] = h->elems[smaller_child];
				h->elems[del_idx].ref->elem = &h->elems[del_idx];
				del_idx = smaller_child;
			}
		}
		else if (left_child <= h->n_elems) {
			if (h->elems[left_child].priority > priority) {
				h->elems[del_idx].priority = priority;
				h->elems[del_idx].ref = dest;
				dest->elem = &h->elems[del_idx];
			}
			else {
				h->elems[del_idx] = h->elems[left_child];
				h->elems[left_child].priority = priority;
				h->elems[left_child].ref = dest;

				h->elems[del_idx].ref->elem = &h->elems[del_idx];
				dest->elem = &h->elems[left_child];
			}
			break;
		}
		else {
			h->elems[del_idx].priority = priority;
			h->elems[del_idx].ref = dest;
			dest->elem = &h->elems[del_idx];
			break;
		}
	}
}

struct heap_ref *heap_pop(struct heap *h)
{
	struct heap_ref *ret = h->elems[1].ref;
	if (h->n_elems == 0)
		return NULL;

	heap_del(h, h->elems[1].ref);
	return ret;
}
