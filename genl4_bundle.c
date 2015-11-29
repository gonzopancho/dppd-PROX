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
#include <rte_hash.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "defines.h"
#include "genl4_bundle.h"
#include "log.h"
#include "pkt_parser.h"
#include "prox_lua_types.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define RTE_CACHE_LINE_ROUNDUP CACHE_LINE_ROUNDUP
#endif

/* zero on success */
int bundle_ctx_pool_create(const char *name, uint32_t n_elems, struct bundle_ctx_pool *ret, int socket_id)
{
	size_t memsize;
	uint8_t *mem;

	const struct rte_hash_parameters params = {
		.name = name,
		.entries = n_elems * 8,
		//.bucket_entries = 8,
		.key_len = sizeof(struct pkt_tuple),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};

	ret->hash = rte_hash_create(&params);
	if (NULL == ret->hash)
		return -1;

	memsize = 0;
	memsize += RTE_CACHE_LINE_ROUNDUP(params.entries * sizeof(ret->hash_entries[0]));
	memsize += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->free_bundles[0]));
	memsize += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->bundles[0]));

	mem = rte_zmalloc_socket(NULL, memsize, RTE_CACHE_LINE_SIZE, socket_id);
	if (NULL == mem)
		return -1;

	ret->hash_entries = (struct bundle_ctx **) mem;
	mem += RTE_CACHE_LINE_ROUNDUP(params.entries * sizeof(ret->hash_entries[0]));
	ret->free_bundles = (struct bundle_ctx **) mem;
	mem += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->free_bundles[0]));
	ret->bundles = (struct bundle_ctx *) mem;

	for (unsigned i = 0; i < n_elems; ++i) {
		ret->free_bundles[i] = &ret->bundles[i];
	}
	ret->n_free_bundles = n_elems;
	ret->tot_bundles    = n_elems;

	return 0;
}

struct bundle_ctx *bundle_ctx_pool_get(struct bundle_ctx_pool *p)
{
	if (p->n_free_bundles > 0)
		return p->free_bundles[--p->n_free_bundles];
	return NULL;
}

void bundle_ctx_pool_put(struct bundle_ctx_pool *p, struct bundle_ctx *bundle)
{
	p->free_bundles[p->n_free_bundles++] = bundle;
}

static void bundle_cleanup(struct bundle_ctx *bundle)
{
	if (bundle->heap_ref.elem != NULL) {
		heap_del(bundle->heap, &bundle->heap_ref);

		int c = bundle->stream_idx;
		const struct stream_cfg *stream_cfg = &bundle->ctx.stream_cfg[c];
	}
}

static int bundle_iterate_streams(struct bundle_ctx *bundle, struct bundle_ctx_pool *pool, unsigned *seed, struct l4_stats *l4_stats)
{
	enum l4gen_peer peer;
	int ret = 0, old;

	while (bundle->ctx.stream_cfg->is_ended(&bundle->ctx)) {

		if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP) {
			if (bundle->ctx.retransmits == 0)
				l4_stats->tcp_finished_no_retransmit++;
			else
				l4_stats->tcp_finished_retransmit++;
		}
		else
			l4_stats->udp_finished++;

		if (bundle->stream_idx + 1 != bundle->cfg->n_stream_cfgs) {
			ret = 1;
			bundle->stream_idx++;

			peer = bundle->ctx.peer;
			memset(&bundle->ctx, 0, sizeof(bundle->ctx));
			bundle->ctx.peer = peer;

			bundle->ctx.stream_cfg = bundle->cfg->stream_cfgs[bundle->stream_idx];

			/* Update tuple */
			old = rte_hash_del_key(pool->hash, &bundle->tuple);
			if (old < 0) {
				plogx_err("Failed to delete key while trying to change tuple: %d (%s)\n",old, strerror(-old));
			}
			plogx_dbg("Moving to stream with idx %d\n", bundle->stream_idx);

			/* In case there are multiple streams, clients
			   randomized but ports fixed, it is still
			   possible to hit an infinite loop here. The
			   situations is hit if a client:port is
			   connected to a server:port in one of the
			   streams while client:port is regenerated
			   for the first stream. There is no conflict
			   yet since the server:port is
			   different. Note that this is bug since a
			   client:port can only have one open
			   connection. */
			int retries = 0;
			do {
				bundle_create_tuple(&bundle->tuple, &bundle->cfg->clients, bundle->ctx.stream_cfg, 0, seed);

				ret = rte_hash_lookup(pool->hash, (const void *)&bundle->tuple);
				if (++retries == 1000) {
					plogx_warn("Already tried 1K times\n");
					plogx_warn("Going from %d to %d\n", bundle->stream_idx -1, bundle->stream_idx);
				}
			} while (ret >= 0);

			ret = rte_hash_add_key(pool->hash, &bundle->tuple);
			if (ret < 0) {
				plogx_err("Failed to add key while moving to next stream!\n");
				return -1;
			}
			pool->hash_entries[ret] = pool->hash_entries[old];

			if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP)
				l4_stats->tcp_created++;
			else
				l4_stats->udp_created++;
		}
		else {
			int a = rte_hash_del_key(pool->hash, &bundle->tuple);
			if (a < 0) {
				plogx_err("Del failed (%d)! during finished all bundle (%d)\n", a, bundle->cfg->n_stream_cfgs);
				exit(-1);
			}
			bundle_cleanup(bundle);
			bundle_ctx_pool_put(pool, bundle);

			return -1;
		}
	}
	return ret;
}

void bundle_create_tuple(struct pkt_tuple *tp, const struct host_set *clients, const struct stream_cfg *stream_cfg, int rnd_ip, unsigned  *seed)
{
	tp->dst_port = clients->port;
	tp->dst_port &= ~clients->port_mask;
	tp->dst_port |= rand_r(seed) & clients->port_mask;

	if (rnd_ip) {
		tp->dst_addr = clients->ip;
		tp->dst_addr &= ~clients->ip_mask;
		tp->dst_addr |= rand_r(seed) & clients->ip_mask;
	}

	tp->src_addr = stream_cfg->servers.ip;
	tp->src_port = stream_cfg->servers.port;
	plogx_dbg("bundle_create_tuple() with proto = %x, %d\n", stream_cfg->proto, rnd_ip);
	tp->proto_id = stream_cfg->proto;

	tp->l2_types[0] = 0x0008;
}

void bundle_init(struct bundle_ctx *bundle, const struct bundle_cfg *cfg, struct heap *heap, enum l4gen_peer peer, unsigned *seed)
{
	bundle->heap_ref.elem = NULL;
	bundle->heap = heap;
	bundle->cfg = cfg;
	memset(&bundle->ctx, 0, sizeof(bundle->ctx));
	// TODO; assert that there is at least one stream
	bundle->stream_idx = 0;
	bundle->ctx.stream_cfg = bundle->cfg->stream_cfgs[bundle->stream_idx];
	bundle->ctx.peer = peer;

	/* Server's initial state is different from client for TCP. */
	bundle->ctx.tcp_state = PEER_CLIENT == peer? CLOSED : LISTEN;
	bundle->ctx.other_mss = 536; /* default 536 as per RFC 879 */

	bundle_create_tuple(&bundle->tuple, &cfg->clients, bundle->ctx.stream_cfg, peer == PEER_CLIENT, seed);
}

int bundle_proc_data(struct bundle_ctx *bundle, struct rte_mbuf *mbuf, struct l4_meta *l4_meta, struct bundle_ctx_pool *pool, unsigned *seed, struct l4_stats *l4_stats)
{
	int ret;
	uint64_t next_tsc;
	uint32_t retransmit = 0;

	if (bundle->heap_ref.elem != NULL) {
		heap_del(bundle->heap, &bundle->heap_ref);
	}

	if (bundle_iterate_streams(bundle, pool, seed, l4_stats) < 0)
		return -1;

	next_tsc = UINT64_MAX;
	ret = bundle->ctx.stream_cfg->proc(&bundle->ctx, mbuf, &bundle->tuple, l4_meta, &next_tsc, &retransmit);

	if (bundle->ctx.expired) {
		struct pkt_tuple *pt = &bundle->tuple;
		plogx_dbg("Client = "IPv4_BYTES_FMT":%d, Server = "IPv4_BYTES_FMT":%d\n", IPv4_BYTES(((uint8_t*)&pt->dst_addr)), rte_bswap16(pt->dst_port), IPv4_BYTES(((uint8_t*)&pt->src_addr)), rte_bswap16(pt->src_port));
		int a = rte_hash_del_key(pool->hash, bundle);
		if (a < 0) {
			plogx_err("Del failed with error %d: '%s'\n", a, strerror(-a));
			plogx_err("ended = %d\n", bundle->ctx.tcp_ended);
		}

		if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP)
			l4_stats->tcp_expired++;
		else
			l4_stats->udp_expired++;

		bundle_cleanup(bundle);
		bundle_ctx_pool_put(pool, bundle);
		return -1;
	}
	else if (next_tsc != UINT64_MAX) {
		heap_add(bundle->heap, &bundle->heap_ref, rte_rdtsc() + next_tsc);
	}
	l4_stats->tcp_retransmits += retransmit;
	bundle->ctx.retransmits += retransmit;

	if (bundle_iterate_streams(bundle, pool, seed, l4_stats) > 0) {
		if (bundle->heap_ref.elem != NULL) {
			heap_del(bundle->heap, &bundle->heap_ref);
		}
		heap_add(bundle->heap, &bundle->heap_ref, rte_rdtsc());
	}

	return ret;
}
