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

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_version.h>
#include <rte_malloc.h>

#include "task_base.h"
#include "tx_pkt.h"
#include "rx_pkt.h"
#include "etypes.h"
#include "log.h"
#include "quit.h"
#include "qinq.h"
#include "lconf.h"
#include "prefetch.h"
#include "defines.h"
#include "prox_cfg.h"
#include "hash_utils.h"
#include "handle_lb_net.h"
#include "toeplitz.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

/* Load balancing based on one byte, figures out what type of packet
   is passed and depending on the type, pass the packet to the correct
   worker thread. If an unsupported packet type is used, the packet is
   simply dropped. This Load balancer can only handling QinQ packets
   (i.e. packets comming from the vCPE). */
void handle_lb_qinq_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
void handle_lb_qinq_bulk_set_port(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);

struct task_lb_qinq {
	struct task_base        base;
	uint8_t                 *worker_table;
	uint8_t			bit_mask;
	uint8_t                 nb_worker_threads;
	uint16_t                qinq_tag;
};

static void init_task_lb_qinq(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_qinq *task = (struct task_lb_qinq *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->qinq_tag = targ->qinq_tag;
	task->nb_worker_threads = targ->nb_worker_threads;
	task->bit_mask = rte_is_power_of_2(targ->nb_worker_threads) ? targ->nb_worker_threads - 1 : 0xff;

	/* The load distributor is sending to a set of cores. These
	   cores are responsible for handling a set of flows
	   identified by a qinq tag. The load distributor identifies
	   the flows and forwards them to the appropriate worker. The
	   mapping from flow to worker is stored within the
	   work_table. Build the worker_table by asking each worker
	   which flows are handled. */

	task->worker_table = rte_zmalloc_socket(NULL, 0x1000000, RTE_CACHE_LINE_SIZE, socket_id);
	for (int i = 0; i < targ->nb_worker_threads; ++i) {
		struct task_args *t = targ->thread_list[0].targ_dst[i];

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		struct flow_iter *it = &t->task_init->flow_iter;

		int cnt = 0;
		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint16_t svlan = it->get_svlan(it, t);
			uint16_t cvlan = it->get_cvlan(it, t);

			task->worker_table[PKT_TO_LUTQINQ(svlan, cvlan)] = i;
		}

	}

	if (targ->flags & TASK_ARG_CTRL_RINGS_P)
		tbase->flags |= FLAG_CTRL_RINGS_P;
	if (targ->task_init->flag_features & FLAG_LUT_QINQ_RSS)
		tbase->flags |=  BASE_FLAG_LUT_QINQ_RSS;
	if (targ->task_init->flag_features & FLAG_LUT_QINQ_HASH)
		tbase->flags |=  BASE_FLAG_LUT_QINQ_HASH;
	plog_info("\t\ttask_lb_qinq flags = 0x%x\n", tbase->flags);
}

static struct task_init task_init_lb_qinq = {
	.mode = LB_QINQ,
	.mode_str = "lbqinq",
	.init = init_task_lb_qinq,
	.handle = handle_lb_qinq_bulk,
	.size = sizeof(struct task_lb_qinq)
};

static struct task_init task_init_lb_qinq_set_port = {
	.mode = LB_QINQ,
	.mode_str = "lbqinq",
	.sub_mode_str = "lut_qinq_set_port",
	.init = init_task_lb_qinq,
	.handle = handle_lb_qinq_bulk_set_port,
	.size = sizeof(struct task_lb_qinq)
};


static struct task_init task_init_lb_qinq_hash_friend = {
	.mode = LB_QINQ,
	.mode_str = "lbqinq",
	.sub_mode_str ="lut_qinq_hash_friend",
	.init = init_task_lb_qinq,
	.handle = handle_lb_qinq_bulk,
	.flag_features = FLAG_LUT_QINQ_HASH,
	.size = sizeof(struct task_lb_qinq)
};

static struct task_init task_init_lb_qinq_rss_friend = {
	.mode = LB_QINQ,
	.mode_str = "lbqinq",
	.sub_mode_str ="lut_qinq_rss_friend",
	.init = init_task_lb_qinq,
	.handle = handle_lb_qinq_bulk,
	.flag_features = FLAG_LUT_QINQ_RSS,
	.size = sizeof(struct task_lb_qinq)
};

__attribute__((constructor)) static void reg_task_lb_qinq(void)
{
	reg_task(&task_init_lb_qinq);
	reg_task(&task_init_lb_qinq_hash_friend);
	reg_task(&task_init_lb_qinq_rss_friend);
	reg_task(&task_init_lb_qinq_set_port);
}

static inline uint8_t handle_lb_qinq(struct task_lb_qinq *task, struct rte_mbuf *mbuf);

void handle_lb_qinq_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_qinq *task = (struct task_lb_qinq *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_qinq(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_qinq(task, mbufs[j]);
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

void handle_lb_qinq_bulk_set_port(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_qinq *task = (struct task_lb_qinq *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
	uint32_t port_id = mbufs[0]->pkt.in_port;
#else
	uint32_t port_id = mbufs[0]->port;
#endif

	if (tbase->rx_pkt == rx_pkt_hw) {
		port_id = tbase->rx_params_hw.last_read_portid + tbase->rx_params_hw.nb_rxports;
		port_id = ( port_id - 1 ) % tbase->rx_params_hw.nb_rxports;
		port_id = tbase->rx_params_hw.rx_pq[port_id].port;
	} else if (tbase->rx_pkt == rx_pkt_hw1) {
		port_id = tbase->rx_params_hw1.rx_pq.port;
	}

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
		mbufs[j]->pkt.in_port = port_id;
#else
		mbufs[j]->port = port_id;
#endif
		out[j] = handle_lb_qinq(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
		mbufs[j]->pkt.in_port = port_id;
#else
		mbufs[j]->port = port_id;
#endif
		out[j] = handle_lb_qinq(task, mbufs[j]);
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

struct qinq_packet {
	struct qinq_hdr qinq_hdr;
	union {
		struct ipv4_hdr ipv4_hdr;
		struct ipv6_hdr ipv6_hdr;
	};
} __attribute__((packed));

struct qinq_packet_data {
	struct ether_addr  d_addr;
	struct ether_addr  s_addr;
	uint64_t qinq;
} __attribute__((packed));

struct ether_packet {
	struct ether_hdr ether_hdr;
	union {
		struct ipv4_hdr ipv4_hdr;
		struct ipv6_hdr ipv6_hdr;
	};
} __attribute__((packed));


struct cpe_packet {
	union {
		struct qinq_packet  qp;
		struct ether_packet ep;
		struct qinq_packet_data qd;
	};
};

static inline uint8_t get_worker(struct task_lb_qinq *task, struct cpe_packet *packet)
{
	uint8_t worker = 0;
	if (((struct task_base *)task)->flags & BASE_FLAG_LUT_QINQ_HASH) {
		// Load Balance on Hash of combination of cvlan and svlan
		uint64_t qinq_net = packet->qd.qinq;
		qinq_net = qinq_net & 0xFF0F0000FF0F0000;	// Mask Proto and QoS bits
		if (task->bit_mask != 0xff) {
			worker = hash_crc32(&qinq_net,8,0) & task->bit_mask;
		}
		else {
			worker = hash_crc32(&qinq_net,8,0) % task->nb_worker_threads;
		}
		plogx_dbg("Sending packet svlan=%x, cvlan=%x, pseudo_qinq=%lx to worker %d\n", rte_bswap16(0xFF0F & packet->qp.qinq_hdr.svlan.vlan_tci), rte_bswap16(0xFF0F & packet->qp.qinq_hdr.cvlan.vlan_tci), qinq_net, worker);
	} else if (((struct task_base *)task)->flags & BASE_FLAG_LUT_QINQ_RSS){
		// Load Balance on rss of combination of cvlan and svlan
		uint32_t qinq = (packet->qp.qinq_hdr.cvlan.vlan_tci & 0xFF0F) << 16;
		uint32_t rss = toeplitz_hash((uint8_t *)&qinq, 4);
		if (task->bit_mask != 0xff) {
			worker = rss & task->bit_mask;
		} else {
			worker = (0x1ff & rss) % task->nb_worker_threads;
		}
		plogx_dbg("Sending packet svlan=%x, cvlan=%x, rss_input=%x, rss=%x to worker %d\n", rte_bswap16(0xFF0F & packet->qp.qinq_hdr.svlan.vlan_tci), rte_bswap16(0xFF0F & packet->qp.qinq_hdr.cvlan.vlan_tci), qinq, rss, worker);
	} else {
		uint16_t svlan = packet->qp.qinq_hdr.svlan.vlan_tci;
		uint16_t cvlan = packet->qp.qinq_hdr.cvlan.vlan_tci;
		prefetch_nta(&task->worker_table[PKT_TO_LUTQINQ(svlan, cvlan)]);
		worker = task->worker_table[PKT_TO_LUTQINQ(svlan, cvlan)];

		const size_t pos = offsetof(struct cpe_packet, qp.qinq_hdr.cvlan.vlan_tci);
		plogx_dbg("qinq = %u, worker = %u, pos = %lu\n", rte_be_to_cpu_16(cvlan), worker, pos);
	}
	return worker;
}

static inline uint8_t handle_lb_qinq(struct task_lb_qinq *task, struct rte_mbuf *mbuf)
{
	struct cpe_packet *packet = rte_pktmbuf_mtod(mbuf, struct cpe_packet*);
	if (packet->ep.ether_hdr.ether_type == ETYPE_IPv4) {
		if (unlikely((packet->ep.ipv4_hdr.version_ihl >> 4) != 4)) {
			plogx_err("Invalid Version %u for ETYPE_IPv4\n", packet->ep.ipv4_hdr.version_ihl);
			return NO_PORT_AVAIL;
		}
		/* use 24 bits from the IP, clients are from the 10.0.0.0/8 network */
		const uint32_t tmp = rte_bswap32(packet->ep.ipv4_hdr.src_addr) & 0x00FFFFFF;
		const uint32_t svlan = rte_bswap16(tmp >> 12);
		const uint32_t cvlan = rte_bswap16(tmp & 0x0FFF);
		prefetch_nta(&task->worker_table[PKT_TO_LUTQINQ(svlan, cvlan)]);
		uint8_t worker = task->worker_table[PKT_TO_LUTQINQ(svlan, cvlan)];
		return worker + IPV4 * task->nb_worker_threads;
	}
	else if (unlikely(packet->qp.qinq_hdr.svlan.eth_proto != task->qinq_tag)) {
		/* might receive LLDP from the L2 switch... */
		if (packet->qp.qinq_hdr.svlan.eth_proto != ETYPE_LLDP) {
			plogdx_err(mbuf, "Invalid packet for LB in QinQ mode\n");
		}
		return NO_PORT_AVAIL;
	}


	uint8_t worker = 0;
	uint8_t proto = 0xFF;
	switch (packet->qp.qinq_hdr.ether_type) {
	case ETYPE_IPv4: {
		if (unlikely((packet->qp.ipv4_hdr.version_ihl >> 4) != 4)) {
			plogx_err("Invalid Version %u for ETYPE_IPv4\n", packet->qp.ipv4_hdr.version_ihl);
			return NO_PORT_AVAIL;
		}
		worker = get_worker(task, packet);
		proto = IPV4;
		break;
	}
	case ETYPE_IPv6: {
		if (unlikely((packet->qp.ipv4_hdr.version_ihl >> 4) != 6)) {
			plogx_err("Invalid Version %u for ETYPE_IPv6\n", packet->qp.ipv4_hdr.version_ihl);
			return NO_PORT_AVAIL;
		}
		/* Use IP Destination when IPV6 QinQ */
		if (task->bit_mask != 0xff) {
			worker = ((uint8_t *)packet)[61] & task->bit_mask;
		}
		else {
			worker = ((uint8_t *)packet)[61] % task->nb_worker_threads;
		}
		proto = IPV6;
		break;
	}
	case ETYPE_ARP: {
		// We can only send to ARP ring if it exists
		if (((struct task_base *)task)->flags & FLAG_CTRL_RINGS_P) {
			proto = ARP;
		} else {
			proto = IPV4;
		}
		worker = get_worker(task, packet);
		break;
	}
	default:
		PROX_PANIC(1, "Error in ETYPE_8021ad: ether_type = %#06x\n", packet->qp.qinq_hdr.ether_type);
	}

	return worker + proto * task->nb_worker_threads;
}
