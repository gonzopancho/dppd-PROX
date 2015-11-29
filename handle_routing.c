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

#include <rte_lpm.h>
#include <rte_cycles.h>
#include <string.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "quit.h"
#include "log.h"
#include "handle_routing.h"
#include "tx_pkt.h"
#include "gre.h"
#include "lconf.h"
#include "prox_port_cfg.h"
#include "etypes.h"
#include "prefetch.h"
#include "hash_entry_types.h"
#include "mpls.h"
#include "qinq.h"
#include "prox_cfg.h"
#include "ip6_addr.h"
#include "prox_shared.h"

struct task_routing {
	struct task_base                base;
	uint8_t                         runtime_flags;
	struct lcore_cfg                *lconf;
	struct rte_lpm                  *ipv4_lpm;
	struct next_hop                 *next_hops;
	uint32_t			number_free_rules;
	uint16_t                        qinq_tag;
	uint32_t                        marking[4];
	uint64_t                        src_mac[PROX_MAX_PORTS];
};

static void routing_update(struct task_base *tbase, void **data, uint16_t n_msgs)
{
	struct task_routing *task = (struct task_routing *)tbase;
	struct route_msg *msg;

	for (uint16_t i = 0; i < n_msgs; ++i) {
		msg = (struct route_msg *)data[i];

		if (task->number_free_rules == 0) {
			plog_warn("Failed adding route: %u.%u.%u.%u/%u: lpm table full\n",
				msg->ip_bytes[0], msg->ip_bytes[1], msg->ip_bytes[2],
				msg->ip_bytes[3], msg->prefix);
		} else {
			if (rte_lpm_add(task->ipv4_lpm, rte_bswap32(msg->ip), msg->prefix, msg->nh)) {
				plog_warn("Failed adding route: %u.%u.%u.%u/%u\n",
					msg->ip_bytes[0], msg->ip_bytes[1], msg->ip_bytes[2],
					msg->ip_bytes[3], msg->prefix);
			} else {
				task->number_free_rules--;
			}
		}
	}
}

static void init_task_routing(struct task_base *tbase, struct task_args *targ)
{
	struct task_routing *task = (struct task_routing *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	struct lpm4 *lpm;

	task->lconf = targ->lconf;
	task->qinq_tag = targ->qinq_tag;
	task->runtime_flags = targ->runtime_flags;

	PROX_PANIC(!strcmp(targ->route_table, ""), "route table not specified\n");
	if (targ->flags & TASK_ARG_LOCAL_LPM) {
		int ret = lua_to_lpm4(prox_lua(), GLOBAL, targ->route_table, socket_id, &lpm);
		PROX_PANIC(ret, "Failed to load IPv4 LPM:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, targ->route_table, lpm);

		task->number_free_rules = lpm->n_free_rules;
	}
	else {
		lpm = prox_sh_find_socket(socket_id, targ->route_table);
		if (!lpm) {
			int ret = lua_to_lpm4(prox_lua(), GLOBAL, targ->route_table, socket_id, &lpm);
			PROX_PANIC(ret, "Failed to load IPv4 LPM:\n%s\n", get_lua_to_errors());
			prox_sh_add_socket(socket_id, targ->route_table, lpm);
		}
	}
	task->ipv4_lpm = lpm->rte_lpm;
	task->next_hops = lpm->next_hops;
	task->number_free_rules = lpm->n_free_rules;


	for (uint32_t i = 0; i < targ->nb_txrings || i < targ->nb_txports; ++i) {
		if (task->runtime_flags & TASK_MPLS_TAGGING) {
			task->src_mac[i] = (0x0000ffffffffffff & ((*(uint64_t*)&prox_port_cfg[i].eth_addr))) | ((uint64_t)ETYPE_MPLSU << (64 - 16));
		}
		else {
			task->src_mac[i] = (0x0000ffffffffffff & ((*(uint64_t*)&prox_port_cfg[i].eth_addr))) | ((uint64_t)ETYPE_IPv4 << (64 - 16));
		}
	}

	for (uint32_t i = 0; i < 4; ++i) {
		task->marking[i] = rte_bswap32(targ->marking[i] << 9);
	}

	targ->lconf->ctrl_func_m[targ->task] = routing_update;
	targ->lconf->ctrl_timeout = rte_get_tsc_hz()/50;
}

static inline uint8_t handle_routing(struct task_routing *task, struct rte_mbuf *mbuf);

static void handle_routing_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_routing *task = (struct task_routing *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_routing(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_routing(task, mbufs[j]);
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void set_l2(struct task_routing *task, struct rte_mbuf *mbuf, uint8_t nh_idx)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	*((uint64_t *)(&peth->d_addr)) = task->next_hops[nh_idx].mac_port_8bytes;
	*((uint64_t *)(&peth->s_addr)) = task->src_mac[task->next_hops[nh_idx].mac_port.out_idx];
}

static void set_l2_mpls(struct task_routing *task, struct rte_mbuf *mbuf, uint8_t nh_idx)
{
	struct ether_hdr *peth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct mpls_hdr));

#ifdef HARD_CRC
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	mbuf->l2_len += sizeof(struct mpls_hdr);
#else
	mbuf->pkt.vlan_macip.data += sizeof(struct mpls_hdr) << 9;
#endif
#endif

	*((uint64_t *)(&peth->d_addr)) = task->next_hops[nh_idx].mac_port_8bytes;
	*((uint64_t *)(&peth->s_addr)) = task->src_mac[task->next_hops[nh_idx].mac_port.out_idx];
	peth->ether_type = ETYPE_MPLSU;
	struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);

	if (task->runtime_flags & TASK_MARK) {
                  enum rte_meter_color color = rte_sched_port_pkt_read_color(mbuf);

                *(uint32_t *)mpls = task->next_hops[nh_idx].mpls | task->marking[color] | 0x00010000; // Set BoS to 1
	}
	else {
		*(uint32_t *)mpls = task->next_hops[nh_idx].mpls | 0x00010000; // Set BoS to 1
	}
}

static uint8_t route_ipv4(struct task_routing *task, uint8_t *beg, uint32_t ip_offset, struct rte_mbuf *mbuf)
{
	struct ipv4_hdr *ip = (struct ipv4_hdr*)(beg + ip_offset);
	struct ether_hdr *peth_out;
	uint8_t tx_port, next_hop_index;
	uint32_t dst_ip;

	if (unlikely(ip->version_ihl >> 4 != 4)) {
                plog_warn("Offset: %d\n", ip_offset);
		plog_warn("Expected to receive IPv4 packet but IP version was %d\n",
			ip->version_ihl >> 4);
		return NO_PORT_AVAIL;
	}

	switch(ip->next_proto_id) {
	case IPPROTO_GRE: {
		struct gre_hdr *pgre = (struct gre_hdr *)(ip + 1);
		dst_ip = ((struct ipv4_hdr *)(pgre + 1))->dst_addr;
		break;
	}
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		dst_ip = ip->dst_addr;
		break;
	default:
		/* Routing for other protocols is not implemented */
		return NO_PORT_AVAIL;
	}

	if (unlikely(rte_lpm_lookup(task->ipv4_lpm, rte_bswap32(dst_ip), &next_hop_index) != 0)) {
		uint8_t* dst_ipp = (uint8_t*)&dst_ip;
		plog_warn("lpm_lookup failed for ip %d.%d.%d.%d: rc = %d\n",
			dst_ipp[0], dst_ipp[1], dst_ipp[2], dst_ipp[3], -ENOENT);
		return NO_PORT_AVAIL;
	}

	tx_port = task->next_hops[next_hop_index].mac_port.out_idx;
	if (task->runtime_flags & TASK_MPLS_TAGGING) {
	        uint16_t padlen = rte_pktmbuf_pkt_len(mbuf) - rte_be_to_cpu_16(ip->total_length) - ip_offset;
		if (padlen) {
			rte_pktmbuf_trim(mbuf, padlen);
                }

                set_l2_mpls(task, mbuf, next_hop_index);
        }
	else {
		set_l2(task, mbuf, next_hop_index);
        }
	return tx_port;
}

static inline uint8_t handle_routing(struct task_routing *task, struct rte_mbuf *mbuf)
{
	struct qinq_hdr *qinq;
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	switch (peth->ether_type) {
	case ETYPE_8021ad: {
		struct qinq_hdr *qinq = (struct qinq_hdr *)peth;
		if ((qinq->cvlan.eth_proto != ETYPE_VLAN)) {
			plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
			return NO_PORT_AVAIL;
		}

		return route_ipv4(task, (uint8_t*)qinq, sizeof(*qinq), mbuf);
	}
	case ETYPE_IPv4:
		return route_ipv4(task, (uint8_t*)peth, sizeof(*peth), mbuf);
	case ETYPE_MPLSU: {
		/* skip MPLS headers if any for routing */
		struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
		uint32_t count = sizeof(struct ether_hdr);
		while (!(mpls->bytes & 0x00010000)) {
			mpls++;
			count += sizeof(struct mpls_hdr);
		}
		count += sizeof(struct mpls_hdr);

		return route_ipv4(task, (uint8_t*)peth, count, mbuf);
	}
	default:
		if (peth->ether_type == task->qinq_tag) {
			struct qinq_hdr *qinq = (struct qinq_hdr *)peth;
			if ((qinq->cvlan.eth_proto != ETYPE_VLAN)) {
				plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
				return NO_PORT_AVAIL;
			}

			return route_ipv4(task, (uint8_t*)qinq, sizeof(*qinq), mbuf);
		}
		plog_warn("Failed routing packet: ether_type %#06x is unknown\n", peth->ether_type);
		return NO_PORT_AVAIL;
	}
}

static struct task_init task_init_routing = {
	.mode_str = "routing",
	.init = init_task_routing,
	.handle = handle_routing_bulk,
	.flag_features = TASK_ROUTING,
	.size = sizeof(struct task_routing)
};

__attribute__((constructor)) static void reg_task_routing(void)
{
	reg_task(&task_init_routing);
}
