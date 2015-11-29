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

#include "defines.h"
#include "hash_entry_types.h"
#include "mpls.h"
#include "prefetch.h"
#include "task_base.h"
#include "tx_pkt.h"
#include "task_init.h"
#include "prox_port_cfg.h"
#include "prox_cksum.h"
#include "thread_generic.h"
#include "prefetch.h"
#include "prox_assert.h"
#include "etypes.h"
#include "log.h"

struct task_unmpls {
	struct task_base base;
	uint8_t n_tags;
};

static void init_task_unmpls(__attribute__((unused)) struct task_base *tbase,
			     __attribute__((unused)) struct task_args *targ)
{
}

static inline uint8_t handle_unmpls(__attribute__((unused)) struct task_unmpls *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
        uint32_t mpls_len = sizeof(struct mpls_hdr);
        while (!(mpls->bytes & 0x00010000)) {
                mpls++;
                mpls_len += sizeof(struct mpls_hdr);
        }
		uint32_t tot_eth_addr_len = 2*sizeof(struct ether_addr);
		rte_memcpy(((uint8_t *)peth) + mpls_len, peth, tot_eth_addr_len);
        struct ipv4_hdr *ip = (struct ipv4_hdr *)(mpls + 1);
        switch (ip->version_ihl >> 4) {
        case 4:
                peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
                peth->ether_type = ETYPE_IPv4;
                return 0;
        case 6:
                peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
                peth->ether_type = ETYPE_IPv6;
                return 0;
        default:
                plog_warn("Failed Decoding MPLS Packet - neither IPv4 nor IPv6: version %u\n", ip->version_ihl);
                return NO_PORT_AVAIL;
        }
}

static void handle_unmpls_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_unmpls *task = (struct task_unmpls *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_unmpls(task, mbufs[j]);
        }
#ifdef BRAS_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_unmpls(task, mbufs[j]);
        }
#endif
        task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static struct task_init task_init_unmpls = {
	.mode_str = "unmpls",
	.init = init_task_unmpls,
	.handle = handle_unmpls_bulk,
	.thread_x = thread_generic,
	.size = sizeof(struct task_unmpls)
};

struct task_tagmpls {
	struct task_base base;
	uint8_t n_tags;
};

static void init_task_tagmpls(__attribute__((unused)) struct task_base *tbase,
			      __attribute__((unused)) struct task_args *targ)
{
}

static inline uint8_t handle_tagmpls(__attribute__((unused)) struct task_tagmpls *task, struct rte_mbuf *mbuf)
{
        struct ether_hdr *peth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, 4);
        PROX_RUNTIME_ASSERT(peth);
        rte_prefetch0(peth);
	uint32_t mpls = 0;
#ifdef HARD_CRC
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
        mbuf->l2_len += sizeof(struct mpls_hdr);
#else
        mbuf->pkt.vlan_macip.data += sizeof(struct mpls_hdr) << 9;
#endif
#endif
		uint32_t tot_eth_addr_len = 2*sizeof(struct ether_addr);
		rte_memcpy(peth, ((uint8_t *)peth) + sizeof(struct mpls_hdr), tot_eth_addr_len);
        *((uint32_t *)(peth + 1)) = mpls | 0x00010000; // Set BoS to 1
        peth->ether_type = ETYPE_MPLSU;
        return 0;
}

static void handle_tagmpls_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_tagmpls *task = (struct task_tagmpls *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_tagmpls(task, mbufs[j]);
        }
#ifdef BRAS_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_tagmpls(task, mbufs[j]);
        }
#endif
        task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static struct task_init task_init_tagmpls = {
	.mode_str = "tagmpls",
	.init = init_task_tagmpls,
	.handle = handle_tagmpls_bulk,
	.size = sizeof(struct task_tagmpls)
};

__attribute__((constructor)) static void reg_task_mplstag(void)
{
	reg_task(&task_init_unmpls);
	reg_task(&task_init_tagmpls);
}
