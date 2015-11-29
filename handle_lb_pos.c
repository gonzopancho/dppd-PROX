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

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "log.h"
#include "task_base.h"
#include "defines.h"
#include "prox_args.h"
#include "tx_pkt.h"
#include "quit.h"
#include "mpls.h"
#include "etypes.h"
#include "gre.h"
#include "prefetch.h"

struct task_lb_pos {
	struct task_base base;
	uint16_t         byte_offset;
	uint8_t          n_workers;
};

static void init_task_lb_pos(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_pos *task = (struct task_lb_pos *)tbase;

	task->n_workers = targ->nb_worker_threads;
	task->byte_offset = targ->byte_offset;
}

static void handle_lb_pos_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_pos *task = (struct task_lb_pos *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t offset = task->byte_offset;
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		uint8_t* pkt = rte_pktmbuf_mtod(mbufs[j], uint8_t*);
		out[j] = pkt[offset] % task->n_workers;
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		uint8_t* pkt = rte_pktmbuf_mtod(mbufs[j], uint8_t*);
		out[j] = pkt[offset] % task->n_workers;
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

union ip_port {
	struct {
		uint32_t ip;
		uint32_t port;
	};
	uint64_t ip_port;
};

struct pkt_ether_ipv4_udp {
	struct ether_hdr ether;
	struct ipv4_hdr  ipv4;
	struct udp_hdr   udp;
} __attribute__((unused));

static uint8_t handle_lb_ip_port(struct task_lb_pos *task, struct rte_mbuf *mbuf)
{
	union ip_port ip_port;
	uint8_t ret;

	struct pkt_ether_ipv4_udp *pkt = rte_pktmbuf_mtod(mbuf, void *);

	if (pkt->ether.ether_type != ETYPE_IPv4 ||
	    (pkt->ipv4.next_proto_id != IPPROTO_TCP &&
	     pkt->ipv4.next_proto_id == IPPROTO_UDP))
		return NO_PORT_AVAIL;

	if (task->byte_offset == 0) {
		ip_port.ip   = pkt->ipv4.src_addr;
		ip_port.port = pkt->udp.src_port;
	}
	else {
		ip_port.ip   = pkt->ipv4.dst_addr;
		ip_port.port = pkt->udp.dst_port;
	}

	return ip_port.ip_port % task->n_workers;
}

static void handle_lb_ip_port_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_pos *task = (struct task_lb_pos *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;
	uint64_t ip_port = 0;

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_ip_port(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_ip_port(task, mbufs[j]);
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static struct task_init task_init_lb_pos = {
	.mode_str = "lbpos",
	.init = init_task_lb_pos,
	.handle = handle_lb_pos_bulk,
	.size = sizeof(struct task_lb_pos)
};

static struct task_init task_init_lb_pos2 = {
	.mode_str = "lbpos",
	.sub_mode_str = "ip_port",
	.init = init_task_lb_pos,
	.handle = handle_lb_ip_port_bulk,
	.size = sizeof(struct task_lb_pos)
};

__attribute__((constructor)) static void reg_task_lb_pos(void)
{
	reg_task(&task_init_lb_pos);
	reg_task(&task_init_lb_pos2);
}
