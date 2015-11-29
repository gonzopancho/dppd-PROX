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
#include <rte_malloc.h>
#include <rte_version.h>

#include "task_init.h"
#include "rx_pkt.h"
#include "tx_pkt.h"
#include "log.h"
#include "quit.h"
#include "lconf.h"
#include "thread_generic.h"
#include "prox_assert.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

static unsigned first_task = 1;
LIST_HEAD(,task_init) head;

void reg_task(struct task_init* t)
{
	PROX_PANIC(t->handle == NULL, "No handle function specified for task with name %d\n", t->mode);

	if (t->thread_x == NULL)
		t->thread_x = thread_generic;

	if (first_task) {
		first_task = 0;
		LIST_INIT(&head);
	}

	LIST_INSERT_HEAD(&head, t, entries);
}

struct task_init *to_task_init(const char *mode_str, const char *sub_mode_str)
{
	struct task_init *cur_t;

	LIST_FOREACH(cur_t, &head, entries) {
		if (!strcmp(mode_str, cur_t->mode_str) &&
		    !strcmp(sub_mode_str, cur_t->sub_mode_str)) {
			return cur_t;
		}
	}

	return NULL;
}

void tasks_list(void)
{
	struct task_init *cur_t;

	plog_info("Supported modes are: \n");
	LIST_FOREACH(cur_t, &head, entries) {
		plog_info("mode=%s, sub_mode = %s\n", cur_t->mode_str, cur_t->sub_mode_str);
	}
}

static size_t calc_memsize(struct task_args *targ, size_t task_size)
{
	size_t memsize = task_size;

	memsize += sizeof(struct task_base_aux);

	if (targ->nb_rxports != 0) {
		memsize += 2 * sizeof(uint8_t)*targ->nb_rxports;
	}
	if (targ->nb_rxrings != 0 || targ->tx_opt_ring_task) {
		memsize += sizeof(struct rte_ring *)*targ->nb_rxrings;
	}
	if (targ->nb_txrings != 0) {
		memsize += sizeof(struct rte_ring *) * targ->nb_txrings;
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * targ->nb_txrings;
	}
	else if (targ->nb_txports != 0) {
		memsize += sizeof(struct port_queue) * targ->nb_txports;
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * targ->nb_txports;
	}
	else {
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]);
	}

	return memsize;
}

static void *flush_function(struct task_args *targ)
{
	if (targ->flags & TASK_ARG_DROP) {
		return targ->nb_txrings ? flush_queues_sw : flush_queues_hw;
	}
	else {
		return targ->nb_txrings ? flush_queues_no_drop_sw : flush_queues_no_drop_hw;
	}
}

static size_t init_rx_tx_rings_ports(struct task_args *targ, struct task_base *tbase, size_t offset)
{
	if (targ->tx_opt_ring_task) {
		tbase->rx_pkt = rx_pkt_self;
	}
	else if (targ->nb_rxrings != 0) {

		if (targ->nb_rxrings == 1) {
			tbase->rx_pkt = rx_pkt_sw1;
			tbase->rx_params_sw1.rx_ring = targ->rx_rings[0];
		}
		else {
			tbase->rx_pkt = rx_pkt_sw;
			tbase->rx_params_sw.nb_rxrings = targ->nb_rxrings;
			tbase->rx_params_sw.rx_rings = (struct rte_ring **)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct rte_ring *)*tbase->rx_params_sw.nb_rxrings;

			for (uint8_t i = 0; i < tbase->rx_params_sw.nb_rxrings; ++i) {
				tbase->rx_params_sw.rx_rings[i] = targ->rx_rings[i];
			}

			if (rte_is_power_of_2(targ->nb_rxrings)) {
				tbase->rx_pkt = rx_pkt_sw_pow2;
				tbase->rx_params_sw.rxrings_mask = targ->nb_rxrings - 1;
			}
		}
	}
	else {
		if (targ->nb_rxports == 1) {
			tbase->rx_pkt = (targ->task_init->flag_features & TASK_TWICE_RX)? rx_pkt_hw1_twice : rx_pkt_hw1;
			tbase->rx_params_hw1.rx_pq.port =  targ->rx_ports[0];
			tbase->rx_params_hw1.rx_pq.queue = targ->rx_queues[0];
		}
		else {
			PROX_ASSERT((targ->nb_rxports != 0) || (targ->task_init->flag_features & TASK_NO_RX));
			tbase->rx_pkt = (targ->task_init->flag_features & TASK_TWICE_RX)? rx_pkt_hw_twice : rx_pkt_hw;
			tbase->rx_params_hw.nb_rxports = targ->nb_rxports;
			tbase->rx_params_hw.rx_pq = (struct port_queue *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct port_queue) * tbase->rx_params_hw.nb_rxports;
			for (int i = 0; i< targ->nb_rxports; i++) {
				tbase->rx_params_hw.rx_pq[i].port = targ->rx_ports[i];
				tbase->rx_params_hw.rx_pq[i].queue = targ->rx_queues[i];
			}

			if (rte_is_power_of_2(targ->nb_rxports)) {
				tbase->rx_pkt = (targ->task_init->flag_features & TASK_TWICE_RX)? rx_pkt_hw_pow2_twice : rx_pkt_hw_pow2;
				tbase->rx_params_hw.rxport_mask = targ->nb_rxports - 1;
			}
		}
	}


	if (!targ->tx_opt_ring) {
		if (targ->nb_txrings != 0) {
			tbase->tx_params_sw.nb_txrings = targ->nb_txrings;
			tbase->tx_params_sw.tx_rings = (struct rte_ring **)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct rte_ring *)*tbase->tx_params_sw.nb_txrings;

			for (uint8_t i = 0; i < tbase->tx_params_sw.nb_txrings; ++i) {
				tbase->tx_params_sw.tx_rings[i] = targ->tx_rings[i];
			}

			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * tbase->tx_params_sw.nb_txrings;
		}
		else if (targ->nb_txports != 0) {
			tbase->tx_params_hw.nb_txports = targ->nb_txports;
			tbase->tx_params_hw.tx_port_queue = (struct port_queue *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct port_queue) * tbase->tx_params_hw.nb_txports;
			for (uint8_t i = 0; i < tbase->tx_params_hw.nb_txports; ++i) {
				tbase->tx_params_hw.tx_port_queue[i].port = targ->tx_port_queue[i].port;
				tbase->tx_params_hw.tx_port_queue[i].queue = targ->tx_port_queue[i].queue;
			}

			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * tbase->tx_params_hw.nb_txports;
		}
		else {
			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]);
		}

		struct ws_mbuf* w = tbase->ws_mbuf;
		struct task_args *prev = targ->tx_opt_ring_task;

		while (prev) {
			prev->tbase->ws_mbuf = w;
			prev = prev->tx_opt_ring_task;
		}
	}
	if (targ->nb_txrings == 1 || targ->nb_txports == 1 || targ->tx_opt_ring) {
		if (targ->task_init->flag_features & TASK_NEVER_DROPS) {
			if (targ->tx_opt_ring) {
				tbase->tx_pkt = tx_pkt_1dst_self;
			}
			else if (targ->flags & TASK_ARG_DROP) {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_1dst_sw1 : tx_pkt_1dst_hw1;
			}
			else {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_1dst_sw1 : tx_pkt_no_drop_1dst_hw1;
			}
		}
		else {
			if (targ->tx_opt_ring) {
				tbase->tx_pkt = tx_pkt_self;
			}
			else if (targ->flags & TASK_ARG_DROP) {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_sw1 : tx_pkt_hw1;
			}
			else {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_sw1 : tx_pkt_no_drop_hw1;
			}
		}
	        tbase->flags |= FLAG_NEVER_FLUSH;
	}
	else {
		if (targ->flags & TASK_ARG_DROP) {
			tbase->tx_pkt = targ->nb_txrings ? tx_pkt_sw : tx_pkt_hw;
		}
		else {
			tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_sw : tx_pkt_no_drop_hw;
		}

		targ->lconf->flush_queues[targ->task] = flush_function(targ);
	}

	if (targ->task_init->flag_features & TASK_NO_RX) {
		tbase->rx_pkt = rx_pkt_dummy;
	}

	return offset;
}

struct task_base *init_task_struct(struct task_args *targ)
{
	struct task_init* t = targ->task_init;
	size_t offset = 0;
	size_t memsize = calc_memsize(targ, t->size);
	uint8_t task_socket = rte_lcore_to_socket_id(targ->lconf->id);
	struct task_base *tbase = rte_zmalloc_socket(NULL, memsize, RTE_CACHE_LINE_SIZE, task_socket);
	PROX_PANIC(tbase == NULL, "Failed to allocate memory for task (%zu bytes)", memsize);
	offset += t->size;

	offset = init_rx_tx_rings_ports(targ, tbase, offset);


	tbase->aux = (struct task_base_aux *)(((uint8_t *)tbase) + offset);
	offset += sizeof(struct task_base_aux);

	tbase->handle_bulk = t->handle;

	targ->tbase = tbase;
	if (t->init) {
		t->init(tbase, targ);
	}

	return tbase;
}
