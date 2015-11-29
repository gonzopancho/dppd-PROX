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
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_version.h>
#include <rte_byteorder.h>

#include "prox_lua_types.h"
#include "prox_lua.h"

#include "prox_cksum.h"
#include "prefetch.h"
#include "etypes.h"
#include "log.h"
#include "quit.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prox_port_cfg.h"

#ifndef RTE_CACHE_LINE_SIZE
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct task_nat {
	struct task_base base;
	struct rte_hash  *hash;
	uint32_t         *entries;
	int              use_src;
};

struct pkt_eth_ipv4 {
	struct ether_hdr ether_hdr;
	struct ipv4_hdr  ipv4_hdr;
} __attribute__((packed));

static int handle_nat(struct task_nat *task, struct rte_mbuf *mbuf)
{
	uint32_t *ip_addr;
	struct pkt_eth_ipv4 *pkt = rte_pktmbuf_mtod(mbuf, struct pkt_eth_ipv4 *);
	int ret;

	/* Currently, only support eth/ipv4 packets */
	if (pkt->ether_hdr.ether_type != ETYPE_IPv4)
		return NO_PORT_AVAIL;
	if (task->use_src)
		ip_addr = &(pkt->ipv4_hdr.src_addr);
	else
		ip_addr = &(pkt->ipv4_hdr.dst_addr);

	ret = rte_hash_lookup(task->hash, ip_addr);

	/* Drop all packets for which no translation has been
	   configured. */
	if (ret < 0)
		return NO_PORT_AVAIL;

        *ip_addr = task->entries[ret];
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
#ifdef HARD_CRC
        mbuf->tx_offload = CALC_TX_OL(sizeof(struct ether_hdr), sizeof(struct ipv4_hdr));
#endif
#endif
	return 0;
}

static void handle_nat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_nat *task = (struct task_nat *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef BRAS_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_nat(task, mbufs[j]);
        }
#ifdef BRAS_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_nat(task, mbufs[j]);
        }
#endif
        task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int lua_to_hash_nat(struct lua_State *L, enum lua_place from, const char *name,
			   uint8_t socket, struct rte_hash **hash, uint32_t **entries)
{
	struct rte_hash *ret_hash;
	uint32_t *ret_entries;
	uint32_t n_entries;
	uint32_t ip_from, ip_to;
	int ret, pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	PROX_PANIC(n_entries == 0, "No entries for NAT\n");

	static char hash_name[30] = "000_hash_nat_table";

	const struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries * 4,
		.key_len = sizeof(ip_from),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};

	ret_hash = rte_hash_create(&hash_params);
	PROX_PANIC(ret_hash == NULL, "Failed to set up hash table for NAT\n");
	name++;
	ret_entries = rte_zmalloc_socket(NULL, n_entries * sizeof(ip_to), RTE_CACHE_LINE_SIZE, socket);
	PROX_PANIC(ret_entries == NULL, "Failed to allocate memory for NAT %u entries\n", n_entries);

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_ip(L, TABLE, "from", &ip_from) ||
		    lua_to_ip(L, TABLE, "to", &ip_to))
			return -1;

		ip_from = rte_bswap32(ip_from);
		ip_to = rte_bswap32(ip_to);

		ret = rte_hash_lookup(ret_hash, (const void *)&ip_from);
		PROX_PANIC(ret >= 0, "Key %x already exists in NAT hash table\n", ip_from);

		ret = rte_hash_add_key(ret_hash, (const void *)&ip_from);

		PROX_PANIC(ret < 0, "Failed to add Key %x to NAT hash table\n", ip_from);
		ret_entries[ret] = ip_to;
		lua_pop(L, 1);
	}

	lua_pop(L, pop);

	*hash = ret_hash;
	*entries = ret_entries;
	return 0;
}

static void init_task_nat(struct task_base *tbase, struct task_args *targ)
{
	struct task_nat *task = (struct task_nat *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	int ret;

	/* Use destination IP by default. */
	task->use_src = targ->use_src;

	PROX_PANIC(!strcmp(targ->nat_table, ""), "No nat table specified\n");
	ret = lua_to_hash_nat(prox_lua(), GLOBAL, targ->nat_table, socket_id, &task->hash, &task->entries);
	PROX_PANIC(ret != 0, "Failed to load NAT table from lua:\n%s\n", get_lua_to_errors());
}

/* Basic static nat. */
static struct task_init task_init_nat = {
	.mode_str = "nat",
	.init = init_task_nat,
	.handle = handle_nat_bulk,
	.flag_features = TASK_TXQ_FLAGS_NOOFFLOADS|TASK_TXQ_FLAGS_NOMULTSEGS,
	.size = sizeof(struct task_nat),
	.mbuf_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
};

__attribute__((constructor)) static void reg_task_nat(void)
{
	reg_task(&task_init_nat);
}
