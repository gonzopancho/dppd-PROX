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

#include <rte_hash.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_version.h>
#include <rte_byteorder.h>

#include "etypes.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prefetch.h"
#include "prox_globals.h"
#include "defines.h"
#include "quit.h"

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

#define L3FWD_HASH_ENTRIES		1024*1024*8
#define HASH_TABLE_SIZE			1024*1024*8*4

struct task_lb_5tuple {
	struct task_base base;
	uint32_t runtime_flags;
	struct rte_hash *lookup_hash;
	uint8_t ipv4_l3fwd_out_if[HASH_TABLE_SIZE] __rte_cache_aligned;
};

struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
} __attribute__((__packed__));

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	__m128i xmm;
};

struct ipv4_l3fwd_route {
	struct ipv4_5tuple key;
	uint8_t if_out;
};

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
	uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	return (init_val);
}

static __m128i mask0;
static inline uint8_t
get_ipv4_dst_port(struct task_lb_5tuple *task, void *ipv4_hdr, uint8_t portid, struct rte_hash * ipv4_l3fwd_lookup_struct)
{
	int ret = 0;
	union ipv4_5tuple_host key;

	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);
	__m128i data = _mm_loadu_si128((__m128i*)(ipv4_hdr));
	/* Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol */
	key.xmm = _mm_and_si128(data, mask0);
	/* Find destination port */
	ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct, (const void *)&key);
	return (uint8_t)((ret < 0)? portid : task->ipv4_l3fwd_out_if[ret]);
}

static void convert_ipv4_5tuple(struct ipv4_5tuple* key1,
		union ipv4_5tuple_host* key2)
{
	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
	return;
}

static inline uint8_t handle_lb_5tuple(struct task_lb_5tuple *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	switch (eth_hdr->ether_type) {
	case ETYPE_IPv4:
		/* Handle IPv4 headers.*/
		ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
		return get_ipv4_dst_port(task, ipv4_hdr, NO_PORT_AVAIL, task->lookup_hash);
	default:
		return NO_PORT_AVAIL;
	}
}

static void handle_lb_5tuple_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_5tuple *task = (struct task_lb_5tuple *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_5tuple(task, mbufs[j]);
	}
#ifdef BRAS_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_5tuple(task, mbufs[j]);
	}
#endif

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_lb_5tuple(struct task_base *tbase, struct task_args *targ)
{
#if RTE_VERSION < RTE_VERSION_NUM(2, 1, 0, 0)
	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
        .name = NULL,
        .entries = HASH_TABLE_SIZE,
        .key_len = sizeof(union ipv4_5tuple_host),
		.bucket_entries = 4,
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    };
#else
	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
        .name = NULL,
        .entries = HASH_TABLE_SIZE,
        .key_len = sizeof(union ipv4_5tuple_host),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    };
#endif
	struct task_lb_5tuple *task = (struct task_lb_5tuple *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	uint32_t i;

	char s[64];

	/* create ipv4 hash */
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socket_id);
	ipv4_l3fwd_hash_params.name = s;
	ipv4_l3fwd_hash_params.socket_id = socket_id;
	task->lookup_hash = rte_hash_create(&ipv4_l3fwd_hash_params);
	PROX_PANIC(task->lookup_hash == NULL, "Unable to create the l3fwd hash\n");

	mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS, ALL_32_BITS, BIT_8_TO_15);
	for (i = 0; i < L3FWD_HASH_ENTRIES; i++) {
		struct ipv4_l3fwd_route entry;
		union ipv4_5tuple_host newkey;
		memset(&entry, 0, sizeof(entry));
		entry.if_out = i % 4;
		entry.key.ip_src   = i         & 0b00011111;
		entry.key.ip_dst   = (i >> 5)  & 0b00011111;
		entry.key.port_src = (i >> 10) & 0b00011111;
		entry.key.port_dst = (i >> 15) & 0b00011111;
		entry.key.proto    = (i >> 15) & 0b11100000;
		convert_ipv4_5tuple(&entry.key, &newkey);
		int32_t ret = rte_hash_add_key(task->lookup_hash, (void *) &newkey);
		PROX_PANIC(ret < 0, "Unable to add entry %u (err code %d)\n", i, ret);
		task->ipv4_l3fwd_out_if[ret] = (uint8_t) entry.if_out;
	}
	task->runtime_flags = targ->flags;
}

static struct task_init task_init_lb_5tuple = {
	.mode_str = "lb5tuple",
	.init = init_task_lb_5tuple,
	.handle = handle_lb_5tuple_bulk,
	.flag_features = TASK_NEVER_DROPS | TASK_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_lb_5tuple),
};

__attribute__((constructor)) static void reg_task_lb_5tuple(void)
{
	reg_task(&task_init_lb_5tuple);
}
