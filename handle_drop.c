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

#include "task_init.h"
#include "task_base.h"
#include "stats.h"
#include "arp.h"
#include "etypes.h"
#include "quit.h"
#include "log.h"
#include "prox_port_cfg.h"

struct task_drop {
	struct task_base   base;
	struct ether_addr  src_mac;
};

static void handle_drop_bulk(__attribute__((unused)) struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	for (uint16_t j = 0; j < n_pkts; ++j) {
		rte_pktmbuf_free(mbufs[j]);
	}
	TASK_STATS_ADD_DROP(&tbase->aux->stats, n_pkts);
}

static inline void prepare_arp_reply(struct task_drop *task, struct ether_hdr_arp *packet)
{
	uint32_t ip_source = packet->arp.data.spa;
	packet->arp.data.spa = packet->arp.data.tpa;
	packet->arp.data.tpa = ip_source;
	memcpy(&packet->arp.data.tha, &packet->arp.data.sha, sizeof(struct ether_addr));
	memcpy(&packet->arp.data.sha, &task->src_mac, sizeof(struct ether_addr));
}

static void handle_drop_arp_reply_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct ether_hdr_arp *hdr;
	struct task_drop *task = (struct task_drop *)tbase;
	uint8_t out[MAX_PKT_BURST];
	for (uint16_t j = 0; j < n_pkts; ++j) {
		hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr_arp *);
		if (hdr->ether_hdr.ether_type == ETYPE_ARP) {
			prepare_arp_reply(task, hdr);
			memcpy(hdr->ether_hdr.d_addr.addr_bytes, hdr->ether_hdr.s_addr.addr_bytes, 6);
			memcpy(hdr->ether_hdr.s_addr.addr_bytes, &task->src_mac, 6);
			out[j] = 0;
			hdr->arp.oper = 0x200;
		} else
			out[j] = -1;
	}
	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_drop(struct task_base *tbase, struct task_args *targ)
{
	struct task_drop *task = (struct task_drop *)tbase;
	tbase->flags |= FLAG_NEVER_FLUSH;
}

static void init_task_drop_arp_reply(struct task_base *tbase, struct task_args *targ)
{
	struct task_drop *task = (struct task_drop *)tbase;
	PROX_PANIC(targ->nb_txports == 0, "drop mode with arp_reply must have a tx_port");
	memcpy(&task->src_mac, &prox_port_cfg[task->base.tx_params_hw.tx_port_queue[0].port].eth_addr, sizeof(struct ether_addr));
}

static struct task_init task_init_drop = {
	.mode_str = "drop",
	.init = init_task_drop,
	.handle = handle_drop_bulk,
	.flag_features = TASK_NO_TX,
	.size = sizeof(struct task_base)
};

static struct task_init task_init_drop_arp_reply = {
	.mode_str = "drop",
	.sub_mode_str = "with_arp_reply",
	.init = init_task_drop_arp_reply,
	.handle = handle_drop_arp_reply_bulk,
	.flag_features = 0,
	.size = sizeof(struct task_drop)
};

__attribute__((constructor)) static void reg_task_drop(void)
{
	reg_task(&task_init_drop);
	reg_task(&task_init_drop_arp_reply);
}
