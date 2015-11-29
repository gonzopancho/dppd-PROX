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
#include <rte_table_hash.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_version.h>

#include "handle_lb_net.h"
#include "task_base.h"
#include "defines.h"
#include "prox_args.h"
#include "tx_pkt.h"
#include "log.h"
#include "stats.h"
#include "mpls.h"
#include "etypes.h"
#include "gre.h"
#include "prefetch.h"
#include "qinq.h"
#include "hash_utils.h"
#include "quit.h"
#include "flow_iter.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct task_lb_net {
	struct task_base                    base;
	uint16_t                            qinq_tag;
	uint8_t				    bit_mask;
	uint8_t                             nb_worker_threads;
	uint8_t				    worker_byte_offset_ipv4;
	uint8_t				    worker_byte_offset_ipv6;
	uint8_t                             runtime_flags;
};

struct task_lb_net_lut {
	struct task_base                    base;
	uint8_t                             nb_worker_threads;
	uint8_t                             runtime_flags;
	struct rte_table_hash               *worker_hash_table;
	uint8_t                             *worker_lut;
	uint32_t                            keys[64];
	struct rte_mbuf                     *fake_packets[64];
};

static inline uint8_t handle_lb_net(struct task_lb_net *task, struct rte_mbuf *mbuf);
static inline int extract_gre_key(struct task_lb_net_lut *task, uint32_t *key, struct rte_mbuf *mbuf);

static struct rte_table_hash *setup_gre_to_wt_lookup(struct task_args *targ, uint8_t n_workers, int socket_id)
{
	uint32_t gre_id, rss;
	void* entry_in_hash;
	int r, key_found = 0;
	struct rte_table_hash *ret;
	uint32_t count = 0;

	for (int i = 0; i < n_workers; ++i) {
		struct task_args *t = targ->thread_list[0].targ_dst[i];

		struct flow_iter *it = &t->task_init->flow_iter;

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			count++;
		}
	}

	struct rte_table_hash_ext_params table_hash_params = {
		.key_size = 4,
		.n_keys = count,
		.n_buckets = count,
		.n_buckets_ext = count >> 1,
		.f_hash = hash_crc32,
		.seed = 0,
		.signature_offset = 0,
		.key_offset = 0,
	};

	ret = rte_table_hash_ext_dosig_ops.f_create(&table_hash_params, socket_id, sizeof(uint8_t));

	for (int i = 0; i < n_workers; ++i) {
		struct task_args *t = targ->thread_list[0].targ_dst[i];

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		struct flow_iter *it = &t->task_init->flow_iter;

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			uint8_t dst = i;

			r = rte_table_hash_ext_dosig_ops.f_add(ret, &gre_id, &dst, &key_found, &entry_in_hash);
			if (r) {
				plog_err("Failed to add gre_id = %x, dest worker = %u\n", gre_id, i);
			}
			else {
				plog_dbg("Core %u added: gre_id %x, dest woker = %u\n", targ->lconf->id, gre_id, i);
			}
		}
	}
	return ret;
}

static uint8_t *setup_wt_indexed_table(struct task_args *targ, uint8_t n_workers, int socket_id)
{
	uint32_t gre_id, rss;
	uint32_t max_gre_id = 0;
	uint8_t queue;
	uint8_t *ret = NULL;
	void* entry_in_hash;
	int key_found = 0;

	for (int i = 0; i < n_workers; ++i) {
		struct task_args *t = targ->thread_list[0].targ_dst[i];

		struct flow_iter *it = &t->task_init->flow_iter;

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			if (gre_id > max_gre_id)
				max_gre_id = gre_id;
		}
	}

	PROX_PANIC(max_gre_id == 0, "Failed to get maximum GRE ID from workers");

	ret = rte_zmalloc_socket(NULL, 1 + max_gre_id, RTE_CACHE_LINE_SIZE, socket_id);
	PROX_PANIC(ret == NULL, "Failed to allocate worker_lut\n");

	for (int i = 0; i < n_workers; ++i) {
		struct task_args *t = targ->thread_list[0].targ_dst[i];

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		struct flow_iter *it = &t->task_init->flow_iter;

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			uint8_t dst = i;

			ret[gre_id] = dst;
		}
	}
	return ret;
}

static void init_task_lb_net(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net *task = (struct task_lb_net *)tbase;

	task->qinq_tag = targ->qinq_tag;
	task->runtime_flags = targ->runtime_flags;
	task->worker_byte_offset_ipv6 = targ->flags & TASK_ARG_INET_SIDE ? 39 : 23;
	task->worker_byte_offset_ipv4 = targ->flags & TASK_ARG_INET_SIDE ? 19 : 15;
	task->nb_worker_threads       = targ->nb_worker_threads;
	/* The optimal configuration is when the number of worker threads
	   is a power of 2. In that case, a bit_mask can be used. Setting
	   the bitmask to 0xff disables the "optimal" usage of bitmasks
	   and the actual number of worker threads will be used instead. */
	task->bit_mask = rte_is_power_of_2(targ->nb_worker_threads) ? targ->nb_worker_threads - 1 : 0xff;
}

static void init_task_lb_net_lut(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->runtime_flags = targ->runtime_flags;
	task->nb_worker_threads       = targ->nb_worker_threads;
	for (uint32_t i = 0; i < 64; ++i) {
		task->fake_packets[i] = (struct rte_mbuf*)((uint8_t*)&task->keys[i] - sizeof (struct rte_mbuf));
	}

	task->worker_hash_table = setup_gre_to_wt_lookup(targ, task->nb_worker_threads, socket_id);
}

static void init_task_lb_net_indexed_table(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->runtime_flags = targ->runtime_flags;
	task->nb_worker_threads       = targ->nb_worker_threads;

	task->worker_lut = setup_wt_indexed_table(targ, task->nb_worker_threads, socket_id);
}

static void handle_lb_net_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net *task = (struct task_lb_net *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_net(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));

	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_net(task, mbufs[j]);
	}
#endif
	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void handle_lb_net_lut_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	uint16_t not_dropped = 0;
	uint8_t out[MAX_PKT_BURST];
	// process packet, i.e. decide if the packet has to be dropped or not and where the packet has to go
	uint16_t j;
	prefetch_first(mbufs, n_pkts);

	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	uint8_t *wt[MAX_PKT_BURST];
	uint64_t lookup_hit_mask = 0;
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		if (extract_gre_key(task, &task->keys[j], mbufs[j])) {
			// Packet will be dropped after lookup
			pkts_mask &= ~(1 << j);
			out[j] = NO_PORT_AVAIL;
		}
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		if (extract_gre_key(task, &task->keys[j], mbufs[j])) {
			pkts_mask &= ~(1 << j);
			out[j] = NO_PORT_AVAIL;
			rte_prefetch0(RTE_MBUF_METADATA_UINT8_PTR(mbufs[j], 0));
		}
	}
#endif
	// keys have been extracted for all packets, now do the lookup
	rte_table_hash_ext_dosig_ops.f_lookup(task->worker_hash_table, task->fake_packets, pkts_mask, &lookup_hit_mask, (void**)wt);
	/* mbufs now contains the packets that have not been dropped */
	if (likely(lookup_hit_mask == RTE_LEN2MASK(n_pkts, uint64_t))) {
		for (j = 0; j < n_pkts; ++j) {
			out[j] = *wt[j];
		}
	}
	else {
		for (j = 0; j < n_pkts; ++j) {
			if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
				plog_warn("Packet %d keys %x can not be sent to worker thread => dropped\n", j, task->keys[j]);
				out[j] = NO_PORT_AVAIL;
			}
			else {
				out[j] = *wt[j];
			}
		}
	}
	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void handle_lb_net_indexed_table_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	uint8_t out[MAX_PKT_BURST];
	// process packet, i.e. decide if the packet has to be dropped or not and where the packet has to go
	uint16_t j;
	uint32_t gre_id;
	prefetch_first(mbufs, n_pkts);

	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		if (extract_gre_key(task, &gre_id, mbufs[j])) {
			// Packet will be dropped after lookup
			pkts_mask &= ~(1 << j);
			out[j] = NO_PORT_AVAIL;
		} else {
			out[j] = task->worker_lut[rte_bswap32(gre_id)];
		}
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		if (extract_gre_key(task, &gre_id, mbufs[j])) {
			pkts_mask &= ~(1 << j);
			out[j] = NO_PORT_AVAIL;
		} else {
			out[j] = task->worker_lut[rte_bswap32(gre_id)];
		}
	}
#endif
	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static inline uint8_t worker_from_mask(struct task_lb_net *task, uint32_t val)
{
	if (task->bit_mask != 0xff) {
		return val & task->bit_mask;
	}
	else {
		return val % task->nb_worker_threads;
	}
}

static inline int extract_gre_key(struct task_lb_net_lut *task, uint32_t *key, struct rte_mbuf *mbuf)
{
	// For all packets, one by one, remove MPLS tag if any and fills in keys used by "fake" packets
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	// Check for MPLS TAG
	struct ipv4_hdr *ip;
	if (peth->ether_type == ETYPE_MPLSU) {
		struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
		uint32_t mpls_len = 0;
		while (!(mpls->bytes & 0x00010000)) {
			mpls++;
			mpls_len += sizeof(struct mpls_hdr);
		}
		mpls_len += sizeof(struct mpls_hdr);
		ip = (struct ipv4_hdr *)(mpls + 1);
		switch (ip->version_ihl >> 4) {
		case 4:
			// Remove MPLS Tag if requested
			if (task->runtime_flags & TASK_MPLS_TAGGING) {
				peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
				peth->ether_type = ETYPE_IPv4;
			}
			break;
		case 6:
			plog_warn("IPv6 not supported in this mode\n");
			return 1;;
		default:
			plog_warn("Unexpected IP version %d\n", ip->version_ihl >> 4);
			return 1;
		}
	}
	else {
		ip = (struct ipv4_hdr *)(peth + 1);
	}
	// Entry point for the packet => check for packet validity
	// => do not use extract_key_core(mbufs[j], &task->keys[j]);
	//
	if (likely(ip->next_proto_id == IPPROTO_GRE)) {
		struct gre_hdr *pgre = (struct gre_hdr *)(ip + 1);
		if (likely(pgre->bits & GRE_KEY_PRESENT)) {
			uint32_t gre_id;
			if (pgre->bits & (GRE_CRC_PRESENT | GRE_ROUTING_PRESENT)) {
				// gre_id = *((uint32_t *)((uint8_t *)pgre + 8));
				*key = *(uint32_t *)((uint8_t *)pgre + 8);
			}
			else {
				// gre_id = *((uint32_t *)((uint8_t *)pgre + 4));
				*key = *(uint32_t *)((uint8_t *)pgre + 4);
			}
		}
		else {
			plog_warn("Key not present\n");
			return 1;
		}
	}
	else {
		plog_warn("Invalid protocol: GRE xas expected, got 0x%x\n", ip->next_proto_id);
		return 1;
	}
	return 0;
}

static inline uint8_t lb_ip4(struct task_lb_net *task, struct ipv4_hdr *ip)
{
	if (unlikely(ip->version_ihl >> 4 != 4)) {
		plog_warn("Expected to receive IPv4 packet but IP version was %d\n",
			ip->version_ihl >> 4);
		return NO_PORT_AVAIL;
	}

	if (ip->next_proto_id == IPPROTO_GRE) {
		struct gre_hdr *pgre = (struct gre_hdr *)(ip + 1);

		if (pgre->bits & GRE_KEY_PRESENT) {
			uint32_t gre_id;
			if (pgre->bits & (GRE_CRC_PRESENT | GRE_ROUTING_PRESENT)) {
				gre_id = *((uint32_t *)((uint8_t *)pgre + 8));
			}
			else {
				gre_id = *((uint32_t *)((uint8_t *)pgre + 4));
			}

			gre_id = rte_be_to_cpu_32(gre_id) & 0xFFFFFFF;
			uint8_t worker = worker_from_mask(task, gre_id);
			plogx_dbg("gre_id = %u worker = %u\n", gre_id, worker);
			return worker + task->nb_worker_threads * IPV4;
		}
		else {
			plog_warn("Key not present\n");
			return NO_PORT_AVAIL;
		}
	}
	else if (ip->next_proto_id == IPPROTO_UDP) {
		uint8_t worker = worker_from_mask(task, rte_bswap32(ip->dst_addr));
		return worker + task->nb_worker_threads * IPV4;
	}
	return NO_PORT_AVAIL;
}

static inline uint8_t lb_ip6(struct task_lb_net *task, struct ipv6_hdr *ip)
{
	if (unlikely((*(uint8_t*)ip) >> 4 != 6)) {
		plog_warn("Expected to receive IPv6 packet but IP version was %d\n",
			*(uint8_t*)ip >> 4);
		return NO_PORT_AVAIL;
	}

	uint8_t worker = worker_from_mask(task, *((uint8_t *)ip + task->worker_byte_offset_ipv6));
	return worker + task->nb_worker_threads * IPV6;
}

static inline uint8_t lb_mpls(struct task_lb_net *task, struct ether_hdr *peth, struct rte_mbuf *mbuf)
{
	struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
	uint32_t mpls_len = 0;
	while (!(mpls->bytes & 0x00010000)) {
		mpls++;
		mpls_len += sizeof(struct mpls_hdr);
	}
	mpls_len += sizeof(struct mpls_hdr);
	struct ipv4_hdr *ip = (struct ipv4_hdr *)(mpls + 1);

	switch (ip->version_ihl >> 4) {
	case 4:
		if (task->runtime_flags & TASK_MPLS_TAGGING) {
			peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
			peth->ether_type = ETYPE_IPv4;
		}
		return lb_ip4(task, ip);
	case 6:
		if (task->runtime_flags & TASK_MPLS_TAGGING) {
			peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
			peth->ether_type = ETYPE_IPv6;
		}
		return lb_ip6(task, (struct ipv6_hdr *)ip);
	default:
		plogd_warn(mbuf, "Failed Decoding MPLS Packet - neither IPv4 neither IPv6: version %u for packet : \n", ip->version_ihl);
		return NO_PORT_AVAIL;
	}
}

static inline uint8_t lb_qinq(struct task_lb_net *task, struct qinq_hdr *qinq)
{
	if (qinq->cvlan.eth_proto != ETYPE_VLAN) {
		plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
		return NO_PORT_AVAIL;
	}
	uint32_t qinq_tags = rte_bswap16(qinq->cvlan.vlan_tci & 0xFF0F);
	return worker_from_mask(task, qinq_tags);
}

static inline uint8_t handle_lb_net(struct task_lb_net *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	const uint16_t len = rte_pktmbuf_pkt_len(mbuf);
	if (len < 60) {
		plogd_warn(mbuf, "Unexpected frame len = %d for packet : \n", len);
		return NO_PORT_AVAIL;
	}

	switch (peth->ether_type) {
	case ETYPE_MPLSU:
		return lb_mpls(task, peth, mbuf);
	case ETYPE_8021ad:
		return lb_qinq(task, (struct qinq_hdr *)peth);
	case ETYPE_IPv4:
		return lb_ip4(task, (struct ipv4_hdr *)(peth + 1));
	case ETYPE_IPv6:
		return lb_ip6(task, (struct ipv6_hdr *)(peth + 1));
	case ETYPE_LLDP:
		return NO_PORT_AVAIL;
	default:
		if (peth->ether_type == task->qinq_tag)
			return lb_qinq(task, (struct qinq_hdr *)peth);
		plogd_warn(mbuf, "Unexpected frame Ether type = %#06x for packet : \n", peth->ether_type);
		return NO_PORT_AVAIL;
	}

	return 1;
}

static struct task_init task_init_lb_net = {
	.mode = LB_NET,
	.mode_str = "lbnetwork",
	.init = init_task_lb_net,
	.handle = handle_lb_net_bulk,
	.size = sizeof(struct task_lb_net),
	.flag_features = FLAG_GRE_ID
};

static struct task_init task_init_lb_net_lut_qinq_rss = {
	.mode = LB_NET,
	.mode_str = "lbnetwork",
	.sub_mode_str = "lut_qinq_rss",
	.init = init_task_lb_net_lut,
	.handle = handle_lb_net_lut_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = FLAG_LUT_QINQ_RSS
};

static struct task_init task_init_lb_net_lut_qinq_hash = {
	.mode = LB_NET,
	.mode_str = "lbnetwork",
	.sub_mode_str = "lut_qinq_hash",
	.init = init_task_lb_net_lut,
	.handle = handle_lb_net_lut_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = FLAG_LUT_QINQ_HASH
};

static struct task_init task_init_lb_net_indexed_table_rss = {
	.mode = LB_NET,
	.mode_str = "lbnetwork",
	.sub_mode_str = "indexed_table_rss",
	.init = init_task_lb_net_indexed_table,
	.handle = handle_lb_net_indexed_table_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = FLAG_LUT_QINQ_RSS
};

static struct task_init task_init_lb_net_indexed_table_hash = {
	.mode = LB_NET,
	.mode_str = "lbnetwork",
	.sub_mode_str = "indexed_table_hash",
	.init = init_task_lb_net_indexed_table,
	.handle = handle_lb_net_indexed_table_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = FLAG_LUT_QINQ_HASH
};

__attribute__((constructor)) static void reg_task_lb_net(void)
{
	reg_task(&task_init_lb_net);
	reg_task(&task_init_lb_net_lut_qinq_rss);
	reg_task(&task_init_lb_net_lut_qinq_hash);
	reg_task(&task_init_lb_net_indexed_table_rss);
	reg_task(&task_init_lb_net_indexed_table_hash);
}
