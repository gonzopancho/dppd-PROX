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
#include <locale.h>

#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_table_hash.h>
#include <rte_memzone.h>

#include "run.h"
#include "main.h"
#include "log.h"
#include "quit.h"
#include "clock.h"
#include "defines.h"
#include "version.h"
#include "prox_args.h"
#include "prox_assert.h"
#include "prox_cfg.h"
#include "prox_shared.h"
#include "prox_port_cfg.h"
#include "toeplitz.h"
#include "hash_utils.h"
#include "handle_lb_net.h"
#include "prox_cksum.h"
#include "thread_nop.h"
#include "thread_generic.h"
#include "thread_pipeline.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

uint8_t lb_nb_txrings = 0xff;
struct rte_ring *ctrl_rings[RTE_MAX_LCORE*MAX_TASKS_PER_CORE];

static void __attribute__((noreturn)) prox_usage(const char *prgname)
{
	plog_info("\nUsage: %s [-f CONFIG_FILE] [-a|-e] [-s|-i] [-w DEF] [-u] [-t]\n"
		  "\t-f CONFIG_FILE : configuration file to load, ./prox.cfg by default\n"
		  "\t-l LOG_FILE : log file name, ./prox.log by default\n"
		  "\t-p : include PID in log file name if default log file is used\n"
		  "\t-a : autostart all cores (by default)\n"
		  "\t-e : don't autostart\n"
		  "\t-s : check configuration file syntax and exit\n"
		  "\t-i : check initialization sequence and exit\n"
		  "\t-u : Listen on UDS /tmp/prox.sock\n"
		  "\t-t : Listen on TCP port 8474\n"
		  "\t-w : define variable using syntax varname=value\n"
		  "\t     takes precedence over variables defined in CONFIG_FILE\n"
		  , prgname);
	exit(EXIT_FAILURE);
}

static void check_consistent_cfg(void)
{
	const struct lcore_cfg *lconf;
	const struct task_args *targ;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			targ = &lconf->targs[task_id];
			PROX_PANIC((targ->flags & TASK_ARG_RX_RING) && targ->rx_rings[0] == 0 && !targ->tx_opt_ring_task,
			           "Configuration Error - Core %u task %u Receiving from ring, but nobody xmitting to this ring\n", lcore_id, task_id);

			for (uint8_t ring_idx = 0; ring_idx < targ->nb_rxrings; ++ring_idx) {
				plog_info("\tCore %u, task %u, rx_ring[%u] %p\n", lcore_id, task_id, ring_idx, targ->rx_rings[ring_idx]);
			}
			if (targ->nb_txports == 0 && targ->nb_txrings == 0) {
				PROX_PANIC(!(targ->task_init->flag_features & TASK_NO_TX),
				           "\tCore %u task %u: no tx_ports and no tx_rings configured while required by mode %s\n", lcore_id, task_id, targ->task_init->mode_str);
			}
			if (targ->nb_rxports == 0 && targ->nb_rxrings == 0) {
				PROX_PANIC(!(targ->task_init->flag_features & TASK_NO_RX),
				           "\tCore %u task %u: no rx_ports and no rx_rings configured while required by mode %s\n", lcore_id, task_id, targ->task_init->mode_str);
			}
		}
	}
}

static int chain_uses_refcnt(struct task_args *targ)
{
	if (targ->task_init->flag_features & TASK_TXQ_FLAGS_REFCOUNT)
		return 1;

	int ret = 0;
	for (uint32_t i = 0; i < targ->n_prev_tasks; ++i) {
		ret = chain_uses_refcnt(targ->prev_tasks[i]);
		if (ret)
			return 1;
	}
	return 0;
}

static void configure_if_tx_queues(struct task_args *targ, uint8_t socket)
{
	uint8_t if_port;

	for (uint8_t i = 0; i < targ->nb_txports; ++i) {
		if_port = targ->tx_port_queue[i].port;

		PROX_PANIC(if_port == NO_PORT_AVAIL, "port misconfigured, exiting\n");

		PROX_PANIC(!prox_port_cfg[if_port].active, "\tPort %u not used, skipping...\n", if_port);

		int dsocket = prox_port_cfg[if_port].socket;
		if (dsocket != -1 && dsocket != socket) {
			plog_warn("TX core on socket %d while device on socket %d\n", socket, dsocket);
		}

		if (prox_port_cfg[if_port].tx_ring[0] == '\0') {  // Rings-backed port can use single queue
			targ->tx_port_queue[i].queue = prox_port_cfg[if_port].n_txq;
			prox_port_cfg[if_port].n_txq++;
		} else {
			prox_port_cfg[if_port].n_txq = 1;
			targ->tx_port_queue[i].queue = 0;
		}
		/* Set the ETH_TXQ_FLAGS_NOREFCOUNT flag if none of
		   the tasks up to the task transmitting to the port
		   does not use refcnt. */
		if (!chain_uses_refcnt(targ)) {
			prox_port_cfg[if_port].tx_conf.txq_flags = ETH_TXQ_FLAGS_NOREFCOUNT;
			plog_info("\t\tEnabling No refcnt on port %d\n", if_port);
		}
		else {
			plog_info("\t\tRefcnt used on port %d\n", if_port);
		}

		/* By default OFFLOAD is enabled */
		if (targ->task_init->flag_features & TASK_TXQ_FLAGS_NOOFFLOADS) {
			if (targ->nb_rxports == 0) {
				/* When receiving from a ring, packet might have been modified in previous core and still need offload */
				plog_info("\t\tNot disabling TX offloads on port %d, as not receiving from physical port\n", if_port);
			} else {
				prox_port_cfg[if_port].tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOOFFLOADS;
				plog_info("\t\tDisabling TX offloads on port %d\n", if_port);
			}
		}
		/* By default NOMULTSEGS is disabled, as drivers/NIC might split packets on RX
		   It should only be enabled when we know for sure that the RX does not split packets.
		*/
		if (targ->task_init->flag_features & TASK_TXQ_FLAGS_NOMULTSEGS) {
			prox_port_cfg[if_port].tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
			plog_info("\t\tEnabling No MultiSegs on port %d\n", if_port);
		}
	}
}

static void configure_if_rx_queues(struct task_args *targ, uint8_t socket)
{
	for (int i = 0; i < targ->nb_rxports; i++) {
		uint8_t if_port = targ->rx_ports[i];

		if (if_port == NO_PORT_AVAIL) {
			return;
		}

		PROX_PANIC(!prox_port_cfg[if_port].active, "Port %u not used, aborting...\n", if_port);

		if(prox_port_cfg[if_port].rx_ring[0] != '\0') {
			prox_port_cfg[if_port].n_rxq = 0;
		}

		targ->rx_queues[i] = prox_port_cfg[if_port].n_rxq;
		prox_port_cfg[if_port].pool[targ->rx_queues[i]] = targ->pool;
		prox_port_cfg[if_port].pool_size[targ->rx_queues[i]] = targ->nb_mbuf - 1;
		prox_port_cfg[if_port].n_rxq++;

		int dsocket = prox_port_cfg[if_port].socket;
		if (dsocket != -1 && dsocket != socket) {
			plog_warn("RX core on socket %d while device on socket %d\n", socket, dsocket);
		}
	}
}

static void configure_if_queues(void)
{
	struct lcore_cfg *lconf;
	uint8_t socket;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		socket = rte_lcore_to_socket_id(lcore_id);
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			configure_if_tx_queues(targ, socket);
			configure_if_rx_queues(targ, socket);
		}
	}
}

static const char *gen_ring_name(uint32_t idx)
{
	static char retval[] = "XX";
	static const char* ring_names =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"[\\]^_`!\"#$%&'()*+,-./:;<="
		">?@{|}0123456789";

	retval[0] = ring_names[idx % strlen(ring_names)];
	idx /= strlen(ring_names);
	retval[1] = idx ? ring_names[(idx - 1) % strlen(ring_names)] : 0;

	return retval;
}

static void init_rings(void)
{
	struct lcore_cfg *lconf, *lworker;
	struct task_args *starg, *dtarg;
	struct rte_ring *ring;
	uint32_t n_pkt_rings = 0, n_ctrl_rings = 0, ring_count = 0, n_opt_ring = 0;
	uint32_t lcore_id;

	lcore_id = -1;
	while(prox_core_next(&lcore_id, 1) == 0) {
		lconf = &lcore_cfg[lcore_id];
		uint8_t socket = rte_lcore_to_socket_id(lcore_id);
		plog_info("\t*** Initializing rings on core %u ***\n", lcore_id);
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			starg = &lconf->targs[task_id];
			uint8_t tot_nb_txrings = 0;
			for (uint8_t idx = 0; idx < MAX_PROTOCOLS; ++idx) {
				if (!starg->thread_list[idx].active) {
					continue;
				}

				for (uint8_t ring_idx = 0; ring_idx < starg->thread_list[idx].nb_threads; ++ring_idx, ++tot_nb_txrings) {
					PROX_ASSERT(ring_idx < MAX_WT_PER_LB);
					PROX_ASSERT(tot_nb_txrings < MAX_RINGS_PER_TASK);

					uint8_t lcore_worker = starg->thread_list[idx].thread_id[ring_idx];
					PROX_ASSERT(prox_core_active(lcore_worker, 0));
					lworker = &lcore_cfg[lcore_worker];
					uint8_t dest_task = starg->thread_list[idx].dest_task;

					plog_info("\t\tCreating ring (size: %u) to connect core %u (socket %u) with worker core %u (socket %u) worker %u ...\n",
					        starg->ring_size, lcore_id, socket, lcore_worker, rte_lcore_to_socket_id(lcore_worker), ring_idx);
					/* socket used is the one that the sending core resides on */

					if (starg->thread_list[idx].type) {
						struct rte_ring **dring = NULL;

						if (starg->thread_list[idx].type == CTRL_TYPE_MSG)
							dring = &lworker->ctrl_rings_m[dest_task];
						else if (starg->thread_list[idx].type == CTRL_TYPE_PKT) {
							dring = &lworker->ctrl_rings_p[dest_task];
							starg->flags |= TASK_ARG_CTRL_RINGS_P;
						}

						if (*dring == NULL)
							ring = rte_ring_create(gen_ring_name(ring_count++), starg->ring_size, socket, RING_F_SC_DEQ);
						else
							ring = *dring;
						PROX_PANIC(ring == NULL, "Cannot create ring to connect I/O core %u with worker core %u\n", lcore_id, lcore_worker);

						starg->tx_rings[tot_nb_txrings] = ring;
						*dring = ring;
						if (lcore_id == prox_cfg.master) {
							ctrl_rings[lcore_worker*MAX_TASKS_PER_CORE + dest_task] = ring;
						}

						plog_info("\t\tCore %u task %u to -> core %u task %u ctrl_ring %s %p %s\n",
							lcore_id, task_id, lcore_worker, dest_task, starg->thread_list[idx].type == CTRL_TYPE_PKT?
							"pkt" : "msg", ring, ring->name);
						n_ctrl_rings++;
						continue;
					}

					dtarg = &lworker->targs[dest_task];
					lworker->targs[dest_task].worker_thread_id = ring_idx;
					PROX_ASSERT(dtarg->flags & TASK_ARG_RX_RING);
					PROX_ASSERT(dest_task < lworker->n_tasks_all);
					/* will skip inactive rings */

					/* If all the following conditions are met, the ring can be optimized away. */
					if (starg->lconf->id == dtarg->lconf->id &&
					    starg->nb_txrings == 1 && idx == 0 && dtarg->task &&
					    dtarg->tot_rxrings == 1 && starg->task == dtarg->task - 1) {
						plog_info("\t\tOptimizing away ring on core %u from task %u to task %u\n", dtarg->lconf->id, starg->task, dtarg->task);
						/* No need to set up ws_mbuf. */
						starg->tx_opt_ring = 1;
						/* During init of destination task, the buffer in the
						   source task will be initialized. */
						dtarg->tx_opt_ring_task = starg;
						n_opt_ring++;
						++dtarg->nb_rxrings;
						continue;
					}

					ring = rte_ring_create(gen_ring_name(ring_count++), starg->ring_size, socket, RING_F_SP_ENQ | RING_F_SC_DEQ);
					PROX_PANIC(ring == NULL, "Cannot create ring to connect I/O core %u with worker core %u\n", lcore_id, lcore_worker);

					starg->tx_rings[tot_nb_txrings] = ring;
					dtarg->rx_rings[dtarg->nb_rxrings] = ring;
					++dtarg->nb_rxrings;
					PROX_ASSERT(dtarg->nb_rxrings < MAX_RINGS_PER_TASK);
					dtarg->nb_slave_threads = starg->thread_list[idx].nb_threads;
					dtarg->lb_friend_core = lcore_id;
					dtarg->lb_friend_task = task_id;
					plog_info("\t\tWorker thread %d has core %d, task %d as a lb friend\n", lcore_worker, lcore_id, task_id);
					plog_info("\t\tCore %u task %u tx_ring[%u] -> core %u task %u rx_ring[%u] %p %s %u WT\n",
					        lcore_id, task_id, ring_idx, lcore_worker, dest_task, dtarg->nb_rxrings, ring, ring->name,
					        dtarg->nb_slave_threads);
					++n_pkt_rings;
				}
			}
		}
	}

	plog_info("\tInitialized %d rings (%d pkt rings, %d ctrl rings)\n", ring_count, n_pkt_rings, n_ctrl_rings);
	if (n_opt_ring) {
		plog_info("\tOptimized away %d rings\n", n_opt_ring);
	}
}

static void shuffle_mempool(struct rte_mempool* mempool, uint32_t nb_mbuf)
{
	struct rte_mbuf** pkts = rte_zmalloc_socket(NULL, nb_mbuf*sizeof(struct rte_mbuf*), RTE_CACHE_LINE_SIZE, rte_socket_id());
	uint64_t got = 0;

	while (rte_mempool_get_bulk(mempool, (void**)(pkts + got), 1) == 0)
		++got;

	while (got) {
		int idx;
		do {
			idx = rand() % nb_mbuf - 1;
		} while (pkts[idx] == 0);

		rte_mempool_put_bulk(mempool, (void**)&pkts[idx], 1);
		pkts[idx] = 0;
		--got;
	};
	rte_free(pkts);
}

static void setup_mempools(struct lcore_cfg* lcore_cfg)
{
	struct lcore_cfg *lconf;
	struct task_args *targ;
	char name[64];
	const struct rte_memzone *mz;
	struct rte_mempool *mp = NULL;
	char memzone_name[64];
	uint32_t lcore_id = -1;
	uint32_t flags = 0;

	if (prox_cfg.flags & UNIQUE_MEMPOOL_PER_SOCKET) {
		struct rte_mempool     *pool[MAX_SOCKETS];
		uint32_t mbuf_count[MAX_SOCKETS] = {0};
		uint32_t nb_cache_mbuf[MAX_SOCKETS] = {0};
		uint32_t mbuf_size[MAX_SOCKETS] = {0};

		while(prox_core_next(&lcore_id, 0) == 0) {
			lconf = &lcore_cfg[lcore_id];
			uint8_t socket = rte_lcore_to_socket_id(lcore_id);
			PROX_ASSERT(socket < MAX_SOCKETS);
			for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
				targ = &lconf->targs[task_id];
				if (targ->mbuf_size_set_explicitely)
					flags = MEMPOOL_F_NO_SPREAD;
				if ((!targ->mbuf_size_set_explicitely) && (targ->task_init->mbuf_size != 0)) {
					targ->mbuf_size = targ->task_init->mbuf_size;
				}
				if (targ->rx_ports[0] != NO_PORT_AVAIL) {
					struct prox_port_cfg* port_cfg = &prox_port_cfg[targ->rx_ports[0]];
					PROX_ASSERT(targ->nb_mbuf != 0);
					mbuf_count[socket] += targ->nb_mbuf;
					if (nb_cache_mbuf[socket] == 0)
						nb_cache_mbuf[socket] = targ->nb_cache_mbuf;
					else {
						PROX_PANIC(nb_cache_mbuf[socket] != targ->nb_cache_mbuf,
							   "all mbuf_cache must have the same size if using a unique mempool per socket\n");
					}
					if (mbuf_size[socket] == 0)
						mbuf_size[socket] = targ->mbuf_size;
					else {
						PROX_PANIC(mbuf_size[socket] != targ->mbuf_size,
							   "all mbuf_size must have the same size if using a unique mempool per socket\n");
					}
					if ((!targ->mbuf_size_set_explicitely) && (strcmp(port_cfg->driver_name, "rte_vmxnet3_pmd") == 0)) {
						if (mbuf_size[socket] < MBUF_SIZE + RTE_PKTMBUF_HEADROOM)
							mbuf_size[socket] = MBUF_SIZE + RTE_PKTMBUF_HEADROOM;
					}
				}
			}
		}
		for (int i = 0 ; i < MAX_SOCKETS; i++) {
			if (mbuf_count[i] != 0) {
				sprintf(name, "socket_%u_pool", i);
				pool[i] = rte_mempool_create(name,
								mbuf_count[i] - 1, mbuf_size[i],
								nb_cache_mbuf[i],
								sizeof(struct rte_pktmbuf_pool_private),
								rte_pktmbuf_pool_init, NULL,
								prox_pktmbuf_init, NULL,
								i, flags);
				PROX_PANIC(pool[i] == NULL, "\t\tError: cannot create mempool for socket %u\n", i);
				plog_info("\t\tMempool %p size = %u * %u cache %u, socket %d\n", pool[i],
					mbuf_count[i], mbuf_size[i], nb_cache_mbuf[i], i);

				if (prox_cfg.flags & DSF_SHUFFLE) {
					shuffle_mempool(pool[i], mbuf_count[i]);
				}
			}
		}
		lcore_id = -1;
		while(prox_core_next(&lcore_id, 0) == 0) {
			lconf = &lcore_cfg[lcore_id];
			uint8_t socket = rte_lcore_to_socket_id(lcore_id);
			for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
				targ = &lconf->targs[task_id];
				if (targ->rx_ports[0] != NO_PORT_AVAIL) {
					/* use this pool for the interface that the core is receiving from */
					/* If one core receives from multiple ports, all the ports use the same mempool */
					targ->pool = pool[socket];
					/* Set the number of mbuf to the number of the unique mempool, so that the used and free work */
					targ->nb_mbuf = mbuf_count[socket];
					plog_info("\t\tMempool %p size = %u * %u cache %u, socket %d\n", targ->pool,
					targ->nb_mbuf, mbuf_size[socket], targ->nb_cache_mbuf, socket);
				}
			}
		}
	}


	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		uint8_t socket = rte_lcore_to_socket_id(lcore_id);
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			targ = &lconf->targs[task_id];
			if (targ->mbuf_size_set_explicitely)
				flags = MEMPOOL_F_NO_SPREAD;

			if (targ->rx_ports[0] != NO_PORT_AVAIL) {
				struct prox_port_cfg* port_cfg = &prox_port_cfg[targ->rx_ports[0]];
				/* mbuf size can be set
				 *  - from config file (highest priority, overwriting any other config) - should only be used as workaround
				 *  - through each 'mode', overwriting the default mbuf_size
				 *  - defaulted to MBUF_SIZE i.e. 1518 Bytes
				 * Except is set expliciteky, ensure that size is big enough for vmxnet3 driver
				*/
				if ((!targ->mbuf_size_set_explicitely) && (targ->task_init->mbuf_size != 0)) {
					/* mbuf_size not set through config file but set through mode */
					targ->mbuf_size = targ->task_init->mbuf_size;
				}
				if ((!targ->mbuf_size_set_explicitely) && (strcmp(port_cfg->driver_name, "rte_vmxnet3_pmd") == 0)) {
					if (targ->mbuf_size < MBUF_SIZE + RTE_PKTMBUF_HEADROOM)
						targ->mbuf_size = MBUF_SIZE + RTE_PKTMBUF_HEADROOM;
				}

				/* allocate memory pool for packets */
				PROX_ASSERT(targ->nb_mbuf != 0);

				if (targ->pool_name[0] == '\0') {
					sprintf(name, "core_%u_port_%u_pool", lcore_id, task_id);
				}

				snprintf(memzone_name, sizeof(memzone_name)-1, "MP_%s", targ->pool_name);
				mz = rte_memzone_lookup(memzone_name);

				if (mz != NULL) {
					mp = (struct rte_mempool*)mz->addr;

					targ->nb_mbuf = mp->size;
					targ->pool = mp;
				}

#ifdef RTE_LIBRTE_IVSHMEM_FALSE
				if (mz != NULL && mp != NULL && mp->phys_addr != mz->ioremap_addr) {
					/* Init mbufs with ioremap_addr for dma */
					mp->phys_addr = mz->ioremap_addr;
					mp->elt_pa[0] = mp->phys_addr + (mp->elt_va_start - (uintptr_t)mp);

					struct prox_pktmbuf_reinit_args init_args;
					init_args.mp = mp;
					init_args.lconf = lconf;

					uint32_t elt_sz = mp->elt_size + mp->header_size + mp->trailer_size;
					rte_mempool_obj_iter((void*)mp->elt_va_start, mp->size, elt_sz, 1,
						mp->elt_pa, mp->pg_num, mp->pg_shift, prox_pktmbuf_reinit, &init_args);
				}
#endif

				/* use this pool for the interface that the core is receiving from */
				/* If one core receives from multiple ports, all the ports use the same mempool */
				if (targ->pool == NULL) {
					plog_info("\t\tCreating mempool %s\n", targ->pool_name);
					targ->pool = rte_mempool_create(name,
								targ->nb_mbuf - 1, targ->mbuf_size,
								targ->nb_cache_mbuf,
								sizeof(struct rte_pktmbuf_pool_private),
								rte_pktmbuf_pool_init, NULL,
								prox_pktmbuf_init, lconf,
								socket, flags);
				}

				PROX_PANIC(targ->pool == NULL, "\t\tError: cannot create mempool for core %u port %u\n", lcore_id, task_id);
				plog_info("\t\tMempool %p size = %u * %u cache %u, socket %d\n", targ->pool,
					targ->nb_mbuf, targ->mbuf_size, targ->nb_cache_mbuf, socket);
				if (prox_cfg.flags & DSF_SHUFFLE) {
					shuffle_mempool(targ->pool, targ->nb_mbuf);
				}
			}
		}
	}
}

static void set_task_lconf(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			lconf->targs[task_id].lconf = lconf;
		}
	}
}

static void set_dest_threads(void)
{
	struct lcore_cfg *lconf;
	struct task_args *starg;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 1) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			starg = &lconf->targs[task_id];
			if (starg->mode == MASTER)
				continue;
			for (uint8_t idx = 0; idx < MAX_PROTOCOLS; ++idx) {
				if (!starg->thread_list[idx].active) {
					continue;
				}

				for (uint8_t ring_idx = 0; ring_idx < starg->thread_list[idx].nb_threads; ++ring_idx) {
					uint8_t dest_task_id = starg->thread_list[idx].dest_task;
					uint8_t lcore_worker = starg->thread_list[idx].thread_id[ring_idx];
					struct task_args *dest_task = &lcore_cfg[lcore_worker].targs[dest_task_id];
					starg->thread_list[idx].targ_dst[ring_idx] = dest_task;
					dest_task->prev_tasks[dest_task->n_prev_tasks++] = starg;
				}
			}
		}
	}
}

static void setup_all_task_structs(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			lconf->tasks_all[task_id] = init_task_struct(&lconf->targs[task_id]);
		}
	}
}

static void init_port_activate(void)
{
	const struct lcore_cfg *lconf;
	const struct task_args *targ;
	uint8_t port_id = 0;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg_init[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			targ = &lconf->targs[task_id];
			for (int i = 0; i < targ->nb_rxports; i++) {
				port_id = targ->rx_ports[i];
				prox_port_cfg[port_id].active = 1;
			}

			for (int i = 0; i < targ->nb_txports; i++) {
				port_id = targ->tx_port_queue[i].port;
				prox_port_cfg[port_id].active = 1;
			}
		}
	}
}

/* Initialize cores and allocate mempools */
static void init_lcores(void)
{
	struct lcore_cfg *lconf = 0;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		uint8_t socket = rte_lcore_to_socket_id(lcore_id);
		PROX_PANIC(socket + 1 > MAX_SOCKETS, "Can't configure core %u (on socket %u). MAX_SOCKET is set to %d\n", lcore_id, socket, MAX_SOCKETS);
	}

	/* need to allocate mempools as the first thing to use the lowest possible address range */
	plog_info("=== Initializing mempools ===\n");
	setup_mempools(lcore_cfg_init);

	lcore_cfg = rte_zmalloc_socket("lcore_cfg_hp", RTE_MAX_LCORE * sizeof(struct lcore_cfg), RTE_CACHE_LINE_SIZE, rte_socket_id());
	PROX_PANIC(lcore_cfg == NULL, "Could not allocate memory for core control structures\n");
	rte_memcpy(lcore_cfg, lcore_cfg_init, RTE_MAX_LCORE * sizeof(struct lcore_cfg));

	set_dest_threads();
	set_task_lconf();

	plog_info("=== Initializing port addresses ===\n");
	init_port_addr();

	plog_info("=== Initializing queue numbers on cores ===\n");
	configure_if_queues();

	plog_info("=== Initializing rings on cores ===\n");
	init_rings();

	plog_info("=== Checking configuration consistency ===\n");
	check_consistent_cfg();

	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];

		plog_info("\t*** Initializing core %u (%u tasks) ***\n", lcore_id, lconf->n_tasks_all);
		int all_thread_nop = 1;
		int generic = 0;
		int pipeline = 0;
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			all_thread_nop = all_thread_nop &&
				targ->task_init->thread_x == thread_nop;

			pipeline = pipeline || targ->task_init->thread_x == thread_pipeline;
			generic = generic || targ->task_init->thread_x == thread_generic;
		}
		PROX_PANIC(generic && pipeline, "Can't run both pipeline and normal thread on same core\n");

		if (all_thread_nop)
			lconf->thread_x = thread_nop;
		else {
			lconf->thread_x = thread_generic;
		}

		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
#ifdef ENABLE_EXTRA_USER_STATISTICS
			targ->n_users = prox_shared[rte_lcore_to_socket_id(lcore_id)].qinq_to_gre_lookup_count;
#endif
			if (targ->task_init->early_init) {
				targ->task_init->early_init(targ);
			}
		}
	}

	plog_info("=== Initializing tasks ===\n");
	setup_all_task_structs();
}

int main(int argc, char **argv)
{
	/* set en_US locale to print big numbers with ',' */
	setlocale(LC_NUMERIC, "en_US.utf-8");

	if (prox_parse_args(argc, argv) != 0){
		prox_usage(argv[0]);
	}

	plog_init(prox_cfg.log_name, prox_cfg.log_name_pid);
	plog_info("=== " PROGRAM_NAME " " VERSION_STR " ===\n");
	plog_info("\tUsing DPDK %s\n", rte_version() + sizeof(RTE_VER_PREFIX));

	if (prox_read_config_file() != 0 ||
	    prox_setup_rte(argv[0]) != 0) {
		return EXIT_FAILURE;
	}

	if (prox_cfg.flags & DSF_CHECK_SYNTAX) {
		plog_info("=== Configuration file syntax has been checked ===\n\n");
		return EXIT_SUCCESS;
	}

	init_port_activate();
	plog_info("=== Initializing rte devices ===\n");
	init_rte_ring_dev();
	init_rte_dev();
	plog_info("=== Calibrating TSC overhead ===\n");
	prox_init_tsc_overhead();
	plog_info("\tTSC running at %"PRIu64" Hz\n", rte_get_tsc_hz());

	init_lcores();
	plog_info("=== Initializing ports ===\n");
	init_port_all();

	if (prox_cfg.flags & DSF_CHECK_INIT) {
		plog_info("=== Initialization sequence completed ===\n\n");
		return EXIT_SUCCESS;
	}

	/* Current way that works to disable DPDK logging */
	FILE *f = fopen("/dev/null", "r");
	rte_openlog_stream(f);
	plog_info("=== PROX started ===\n");
	run(prox_cfg.flags);

	return EXIT_SUCCESS;
}
