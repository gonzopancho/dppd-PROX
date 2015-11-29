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
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "prox_args.h"
#include "defines.h"
#include "pkt_parser.h"
#include "handle_lat.h"
#include "task_init.h"
#include "task_base.h"
#include "prox_port_cfg.h"
#include "lconf.h"
#include "log.h"
#include "quit.h"
#include "heap.h"
#include "mbuf_utils.h"
#include "genl4_bundle.h"
#include "genl4_stream_udp.h"
#include "genl4_stream_tcp.h"
#include "cdf.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct new_tuple {
	uint32_t dst_addr;
	uint8_t proto_id;
	uint16_t dst_port;
	uint16_t l2_types[4];
} __attribute__((packed));

struct task_gen_server {
	struct task_base base;
	struct l4_stats l4_stats;
	struct rte_mempool *mempool;
	struct rte_hash *listen_hash;
	/* Listening bundles contain only 1 part since the state of a
	   multi_part comm is kept mostly at the client side*/
	struct bundle_cfg     **listen_entries;
	struct bundle_ctx_pool bundle_ctx_pool;
	struct bundle_cfg *bundle_cfgs; /* Loaded configurations */
	struct heap *heap;
	uint64_t last_tsc;
	unsigned seed;
	/* Handle scheduled events */
	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint32_t n_new_mbufs;
};

struct task_gen_client {
	struct task_base base;
	struct l4_stats l4_stats;
	struct rte_mempool *mempool;
	struct bundle_ctx_pool bundle_ctx_pool;
	struct bundle_cfg *bundle_cfgs; /* Loaded configurations */
	/* Create new connections and handle scheduled events */
	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint32_t n_new_mbufs;
	uint32_t tot_imix;
	uint64_t last_tsc;
	struct cdf *cdf;
	unsigned seed;
	struct heap *heap;
};

static const struct bundle_cfg *server_accept(struct task_gen_server *task, struct new_tuple *nt)
{
	int ret = rte_hash_lookup(task->listen_hash, nt);

	if (ret < 0)
		return NULL;
	else
		return task->listen_entries[ret];
}

static void handle_gen_bulk_client(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;
	uint8_t out[MAX_PKT_BURST] = {0};
	struct bundle_ctx *conn;
	int ret;

	if (n_pkts) {
		for (int i = 0; i < n_pkts; ++i) {
			struct pkt_tuple pt;
			struct l4_meta l4_meta;

			if (parse_pkt(mbufs[i], &pt, &l4_meta)) {
				plogdx_err(mbufs[i], "Parsing failed\n");
				out[i] = NO_PORT_AVAIL;
				continue;
			}

			ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)&pt);

			if (ret < 0) {
				plogx_dbg("Client: packet RX that does not belong to connection:"
					  "Client = "IPv4_BYTES_FMT":%d, Server = "IPv4_BYTES_FMT":%d\n", IPv4_BYTES(((uint8_t*)&pt.dst_addr)), rte_bswap16(pt.dst_port), IPv4_BYTES(((uint8_t*)&pt.src_addr)), rte_bswap16(pt.src_port));
				plogdx_dbg(mbufs[i], NULL);
				// if tcp, send RST
				/* pkt_tuple_debug2(&pt); */
				out[i] = NO_PORT_AVAIL;
				continue;
			}

			conn = task->bundle_ctx_pool.hash_entries[ret];
			ret = bundle_proc_data(conn, mbufs[i], &l4_meta, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);
			out[i] = ret == 0? 0: NO_PORT_AVAIL;
		}
		task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	}

	if (task->n_new_mbufs < MAX_PKT_BURST) {
		if (rte_mempool_get_bulk(task->mempool, (void **)task->new_mbufs, MAX_PKT_BURST - task->n_new_mbufs) < 0) {
			plogx_err("4Mempool alloc failed %d\n", MAX_PKT_BURST);
			return ;
 		}

		for (uint32_t i = 0; i < MAX_PKT_BURST - task->n_new_mbufs; ++i) {
			init_mbuf_seg(task->new_mbufs[i]);
		}

		task->n_new_mbufs = MAX_PKT_BURST;
	}

	/* If there is at least one callback to handle, handle at most MAX_PKT_BURST */
	if (task->heap->n_elems && rte_rdtsc() > heap_peek_prio(task->heap)) {
		uint16_t n_called_back = 0;
		while (task->heap->n_elems && rte_rdtsc() > heap_peek_prio(task->heap) && n_called_back < MAX_PKT_BURST) {
			conn = BUNDLE_CTX_UPCAST(heap_pop(task->heap));

			/* handle packet TX (retransmit or delayed transmit) */
			ret = bundle_proc_data(conn, task->new_mbufs[n_called_back], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

			if (ret == 0) {
				out[n_called_back] = 0;
				n_called_back++;
			}
		}
		plogx_dbg("During callback, will send %d packets\n", n_called_back);

		task->base.tx_pkt(&task->base, task->new_mbufs, n_called_back, out);
		task->n_new_mbufs -= n_called_back;
	}

	int n_new = task->bundle_ctx_pool.n_free_bundles;
	n_new = n_new > MAX_PKT_BURST? MAX_PKT_BURST : n_new;

	if (n_new == 0)
		return ;

	if (task->n_new_mbufs < MAX_PKT_BURST) {
		if (rte_mempool_get_bulk(task->mempool, (void **)task->new_mbufs, MAX_PKT_BURST - task->n_new_mbufs) < 0) {
			plogx_err("4Mempool alloc failed %d\n", MAX_PKT_BURST);
			return ;
		}

		for (uint32_t i = 0; i < MAX_PKT_BURST - task->n_new_mbufs; ++i) {
			init_mbuf_seg(task->new_mbufs[i]);
		}

		task->n_new_mbufs = MAX_PKT_BURST;
	}

	for (int i = 0; i < n_new; ++i) {
		int32_t ret = cdf_sample(task->cdf, &task->seed);
		/* Select a new bundle_cfg according to imix */
		struct bundle_cfg *bundle_cfg = &task->bundle_cfgs[ret];
		struct bundle_ctx *bundle_ctx;

		bundle_ctx = bundle_ctx_pool_get(&task->bundle_ctx_pool);

		/* Should be an assert: */
		if (!bundle_ctx) {
			plogx_err("No more available bundles\n");
			exit(-1);
		}

		struct pkt_tuple *pt = &bundle_ctx->tuple;

		int n_retries = 0;
		do {
			/* Note that the actual packet sent will
			   contain swapped addresses and ports
			   (i.e. pkt.src <=> tuple.dst). The incoming
			   packet will match this struct. */
			bundle_init(bundle_ctx, bundle_cfg, task->heap, PEER_CLIENT, &task->seed);

			ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)pt);
			if (n_retries == 1000) {
				plogx_err("Already tried 1K times\n");
			}
			if (ret >= 0) {
				n_retries++;
			}
		} while (ret >= 0);

		ret = rte_hash_add_key(task->bundle_ctx_pool.hash, (const void *)pt);

		if (ret < 0) {
			plogx_err("Failed to add key ret = %d, n_free = %d\n", ret, task->bundle_ctx_pool.n_free_bundles);
			bundle_ctx_pool_put(&task->bundle_ctx_pool, bundle_ctx);

			pkt_tuple_debug2(pt);
			out[i] = NO_PORT_AVAIL;
			continue;
		}

		task->bundle_ctx_pool.hash_entries[ret] = bundle_ctx;

		if (bundle_ctx->ctx.stream_cfg->proto == IPPROTO_TCP)
			task->l4_stats.tcp_created++;
		else
			task->l4_stats.udp_created++;

		ret = bundle_proc_data(bundle_ctx, task->new_mbufs[i], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);
		out[i] = ret == 0? 0: NO_PORT_AVAIL;
	}

	task->base.tx_pkt(&task->base, task->new_mbufs, n_new, out);
	task->n_new_mbufs -= n_new;
}

static void handle_gen_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;
	struct pkt_tuple pkt_tuple[MAX_PKT_BURST];
	uint8_t out[MAX_PKT_BURST];
	struct l4_meta l4_meta[MAX_PKT_BURST];
	struct bundle_ctx *conn;
	int ret;

	for (uint16_t j = 0; j < n_pkts; ++j) {
		if (parse_pkt(mbufs[j], &pkt_tuple[j], &l4_meta[j]))
			plogdx_err(mbufs[j], "Unknown packet, parsing failed\n");
	}
	/* Main proc loop */
	for (uint16_t j = 0; j < n_pkts; ++j) {
		conn = NULL;
		ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)&pkt_tuple[j]);

		if (ret >= 0)
			conn = task->bundle_ctx_pool.hash_entries[ret];

		/* If not part of existing connection, try to create a connection */
		if (NULL == conn) {
			struct new_tuple nt;
			nt.dst_addr = pkt_tuple[j].dst_addr;
			nt.proto_id = pkt_tuple[j].proto_id;
			nt.dst_port = pkt_tuple[j].dst_port;
			rte_memcpy(nt.l2_types, pkt_tuple[j].l2_types, sizeof(nt.l2_types));

			const struct bundle_cfg *n;

			if (NULL != (n = server_accept(task, &nt))) {
				conn = bundle_ctx_pool_get(&task->bundle_ctx_pool);
				if (!conn) {
					out[j] = NO_PORT_AVAIL;
					plogx_err("No more free bundles to accept new connection\n");
					continue;
				}
				ret = rte_hash_add_key(task->bundle_ctx_pool.hash, (const void *)&pkt_tuple[j]);
				if (ret < 0) {
					out[j] = NO_PORT_AVAIL;
					bundle_ctx_pool_put(&task->bundle_ctx_pool, conn);
					plog_err("Adding key failed while trying to accept connection\n");
					continue;
				}

				task->bundle_ctx_pool.hash_entries[ret] = conn;

				bundle_init(conn, n, task->heap, PEER_SERVER, &task->seed);
				conn->tuple = pkt_tuple[j];

				if (conn->ctx.stream_cfg->proto == IPPROTO_TCP)
					task->l4_stats.tcp_created++;
				else
					task->l4_stats.udp_created++;
			}
		}

		/* bundle contains either an active connection or a
		   newly created connection. If it is NULL, then not
		   listening. */
		if (NULL != conn) {
			int ret = bundle_proc_data(conn, mbufs[j], &l4_meta[j], &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

			out[j] = ret == 0? 0: NO_PORT_AVAIL;
		}
		else {
			plog_err("Packet received for service that does not exist\n");
			pkt_tuple_debug(&pkt_tuple[j]);
			plogd_dbg(mbufs[j], NULL);
			out[j] = NO_PORT_AVAIL;
		}
	}
	conn = NULL;

	task->base.tx_pkt(&task->base, mbufs, n_pkts, out);

	if (!(task->heap->n_elems && rte_rdtsc() > heap_peek_prio(task->heap)))
		return ;

	if (task->n_new_mbufs < MAX_PKT_BURST) {
		if (rte_mempool_get_bulk(task->mempool, (void **)task->new_mbufs, MAX_PKT_BURST - task->n_new_mbufs) < 0) {
			return ;
 		}

		for (uint32_t i = 0; i < MAX_PKT_BURST - task->n_new_mbufs; ++i) {
			init_mbuf_seg(task->new_mbufs[i]);
		}

		task->n_new_mbufs = MAX_PKT_BURST;
	}

	if (task->heap->n_elems && rte_rdtsc() > heap_peek_prio(task->heap)) {
		uint16_t n_called_back = 0;
		while (task->heap->n_elems && rte_rdtsc() > heap_peek_prio(task->heap) && n_called_back < MAX_PKT_BURST) {
			conn = BUNDLE_CTX_UPCAST(heap_pop(task->heap));

			/* handle packet TX (retransmit or delayed transmit) */
			ret = bundle_proc_data(conn, task->new_mbufs[n_called_back], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

			if (ret == 0) {
				out[n_called_back] = 0;
				n_called_back++;
			}
		}

		task->base.tx_pkt(&task->base, task->new_mbufs, n_called_back, out);
		task->n_new_mbufs -= n_called_back;
	}
}

static int lua_to_host_set(struct lua_State *L, enum lua_place from, const char *name, struct host_set *h)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;
	uint32_t port, port_mask;
	if (lua_to_ip(L, TABLE, "ip", &h->ip) ||
	    lua_to_int(L, TABLE, "ip_mask", &h->ip_mask) ||
	    lua_to_int(L, TABLE, "port", &port) ||
	    lua_to_int(L, TABLE, "port_mask", &port_mask))
		return -1;

	h->port = rte_bswap16(port);
	h->port_mask = rte_bswap16(port_mask);
	h->ip = rte_bswap32(h->ip);
	h->ip_mask = rte_bswap32(h->ip_mask);

	lua_pop(L, pop);
	return 0;
}

static int lua_to_peer_data(struct lua_State *L, enum lua_place from, const char *name, uint32_t socket, struct peer_data *peer_data, size_t *cl)
{
	uint32_t hdr_len, hdr_beg, content_len, content_beg;
	char hdr_file[256], content_file[256];
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	if (lua_getfrom(L, TABLE, "header") < 0)
		return -1;
	if (lua_to_int(L, TABLE, "len", &hdr_len) < 0)
		return -1;
	if (lua_to_int(L, TABLE, "beg", &hdr_beg) < 0)
		return -1;
	if (lua_to_string(L, TABLE, "file_name", hdr_file, sizeof(hdr_file)) < 0)
		return -1;
	lua_pop(L, 1);

	if (lua_getfrom(L, TABLE, "content") < 0)
		return -1;
	if (lua_to_int(L, TABLE, "len", &content_len) < 0)
		return -1;
	if (lua_to_int(L, TABLE, "beg", &content_beg) < 0)
		return -1;
	if (lua_to_string(L, TABLE, "file_name", content_file, sizeof(content_file)) < 0)
		return -1;
	lua_pop(L, 1);

	if (hdr_len == (uint32_t)-1) {
		char file_name[PATH_MAX];
		snprintf(file_name, sizeof(file_name), "%s/%s", get_cfg_dir(), hdr_file);
		FILE *f = fopen(file_name, "r");
		long file_beg;

		if (!f)
			return -1;
		fseek(f, hdr_beg, SEEK_SET);
		file_beg = ftell(f);
		fseek(f, 0, SEEK_END);
		hdr_len = ftell(f) - file_beg;
		fclose(f);
	}

	if (content_len == (uint32_t)-1) {
		char file_name[PATH_MAX];
		snprintf(file_name, sizeof(file_name), "%s/%s", get_cfg_dir(), content_file);
		FILE *f = fopen(file_name, "r");
		long file_beg;

		if (!f)
			return -1;
		fseek(f, content_beg, SEEK_SET);
		file_beg = ftell(f);
		fseek(f, 0, SEEK_END);
		content_len = ftell(f) - file_beg;
		fclose(f);
	}
	*cl = content_len;
	peer_data->mem = rte_zmalloc_socket(NULL, hdr_len + content_len, RTE_CACHE_LINE_SIZE, socket);
	PROX_PANIC(peer_data->mem == NULL, "Failed to allocate memory (%u bytes) to hold headers and contents for peer\n", hdr_len + content_len);
	peer_data->hdr = peer_data->mem;
	peer_data->hdr_len = hdr_len;
	peer_data->content = peer_data->mem + hdr_len;

	char file_name[PATH_MAX];
	snprintf(file_name, sizeof(file_name), "%s/%s", get_cfg_dir(), hdr_file);
	FILE *f = fopen(file_name, "r");
	if (!f) {
		return -1;
	}
	fseek(f, hdr_beg, SEEK_SET);

	size_t ret;

	ret = fread(peer_data->hdr, 1, hdr_len, f);

	if ((uint32_t)ret !=  hdr_len) {
		plog_err("Failed to read hdr, %zu, %u\n", ret, hdr_len);
		return -1;
	}
	fclose(f);

	snprintf(file_name, sizeof(file_name), "%s/%s", get_cfg_dir(), content_file);
	f = fopen(file_name, "r");

	if (!f)
		return -1;
	fseek(f, content_beg, SEEK_SET);

	ret = fread(peer_data->content, 1, content_len, f);
	if ((uint32_t)ret !=  content_len) {
		plog_err("Failed to read content, %zu, %u\n", ret, content_len);
		return -1;
	}
	fclose(f);

	lua_pop(L, pop);
	return 0;
}

static int lua_to_peer_action(struct lua_State *L, enum lua_place from, const char *name, struct peer_action *action, size_t client_contents_len, size_t server_contents_len)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	uint32_t peer, beg, len;
	if (lua_to_int(L, TABLE, "peer", &peer) ||
	    lua_to_int(L, TABLE, "beg", &beg) ||
	    lua_to_int(L, TABLE, "len", &len)) {
		return -1;
	}
	size_t data_len = (peer == PEER_CLIENT? client_contents_len : server_contents_len);
	if (len == (uint32_t)-1)
		len = data_len - beg;

	PROX_PANIC(beg + len > data_len, "Accessing data past the end (starting at %u for %u bytes) while total length is %zu\n", beg, len, data_len);

	action->peer = peer;
	action->beg = beg;
	action->len = len;
	lua_pop(L, pop);
	return 0;
}

static int lua_to_stream_cfg(struct lua_State *L, enum lua_place from, const char *name, uint32_t socket, struct stream_cfg **stream_cfg)
{
	int pop;
	struct stream_cfg *ret;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (lua_getfrom(L, TABLE, "actions") < 0)
		return -1;

	lua_len(prox_lua(), -1);
	uint32_t n_actions = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);

	lua_pop(L, 1);

	size_t mem_size = 0;
	mem_size += sizeof(*ret);
	mem_size += sizeof(ret->actions[0])*n_actions;

	ret = rte_zmalloc_socket(NULL, sizeof(*ret) + mem_size, RTE_CACHE_LINE_SIZE, socket);
	ret->n_actions = n_actions;

	size_t client_contents_len, server_contents_len;
	char proto[16];
	uint32_t timeout_us, timeout_time_wait_us;

	plogx_dbg("loading stream\n");
	if (lua_to_host_set(L, TABLE, "servers", &ret->servers) ||
	    lua_to_string(L, TABLE, "l4_proto", proto, sizeof(proto)) ||
	    lua_to_peer_data(L, TABLE, "client_data", socket, &ret->data[PEER_CLIENT], &client_contents_len) ||
	    lua_to_peer_data(L, TABLE, "server_data", socket, &ret->data[PEER_SERVER], &server_contents_len)) {
		return -1;
	}

	if (lua_to_int(L, TABLE, "timeout", &timeout_us)) {
		timeout_us = 1000000;
	}

	ret->tsc_timeout = (uint64_t)timeout_us * rte_get_tsc_hz()/1000000;

	if (!strcmp(proto, "tcp")) {
		ret->proto = IPPROTO_TCP;
		ret->proc = stream_tcp_proc;
		ret->is_ended = stream_tcp_is_ended;

		if (lua_to_int(L, TABLE, "timeout_time_wait", &timeout_time_wait_us)) {
			timeout_time_wait_us = 2000000;
		}

		ret->tsc_timeout_time_wait = (uint64_t)timeout_time_wait_us * rte_get_tsc_hz()/1000000;
	}
	else if (!strcmp(proto, "udp")) {
		plogx_dbg("loading UDP\n");
		ret->proto = IPPROTO_UDP;
		ret->proc = stream_udp_proc;
		ret->is_ended = stream_udp_is_ended;
	}
	else
		return -1;

	/* get all actions */
	if (lua_getfrom(L, TABLE, "actions") < 0)
		return -1;

	uint32_t idx = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_peer_action(L, STACK, NULL, &ret->actions[idx], client_contents_len, server_contents_len))
			return -1;
		idx++;

		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	lua_pop(L, pop);
	*stream_cfg = ret;
	return 0;
}

static int lua_to_bundle_cfg(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct bundle_cfg *bundle)
{
	int pop, pop2, idx;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	if (lua_to_host_set(L, TABLE, "clients", &bundle->clients))
		return -1;

	/* Read streams array */
	if ((pop2 = lua_getfrom(L, TABLE, "streams")) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	lua_len(prox_lua(), -1);
	bundle->n_stream_cfgs = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);

	if (bundle->n_stream_cfgs >= sizeof(bundle->stream_cfgs)/sizeof(bundle->stream_cfgs[0]))
		return -1;
	plogx_dbg("loading bundle cfg with %d streams\n", bundle->n_stream_cfgs);
	idx = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_stream_cfg(L, STACK, NULL, socket, &bundle->stream_cfgs[idx]))
			return -1;

		++idx;
		lua_pop(L, 1);
	}
	lua_pop(L, pop2);

	lua_pop(L, pop);
	return 0;
}

static void init_task_gen(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	static char name[] = "server_mempool";
	name[0]++;
	task->mempool = rte_mempool_create(name,
					   targ->nb_mbuf - 1, MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   socket_id, 0);
	int pop = lua_getfrom(prox_lua(), GLOBAL, targ->streams);
	PROX_PANIC(pop < 0, "Failed to find '%s' in lua\n", targ->streams);

	lua_len(prox_lua(), -1);
	uint32_t n_listen = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);
	PROX_PANIC(n_listen == 0, "No services specified to listen on\n");

	task->bundle_cfgs = rte_zmalloc_socket(NULL, n_listen * sizeof(task->bundle_cfgs[0]), RTE_CACHE_LINE_SIZE, socket_id);

	plogx_info("n_listen = %d\n", n_listen);
	const struct rte_hash_parameters listen_table = {
		.name = name,
		.entries = n_listen * 4,
		.key_len = sizeof(struct new_tuple),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};
	name[0]++;

	task->listen_hash = rte_hash_create(&listen_table);
	task->listen_entries = rte_zmalloc_socket(NULL, listen_table.entries * sizeof(task->listen_entries[0]), RTE_CACHE_LINE_SIZE, socket_id);

	int idx = 0;
	lua_pushnil(prox_lua());
	while (lua_next(prox_lua(), -2)) {
		task->bundle_cfgs[idx].n_stream_cfgs = 1;
		int ret = lua_to_stream_cfg(prox_lua(), STACK, NULL, socket_id, &task->bundle_cfgs[idx].stream_cfgs[0]);
		PROX_PANIC(ret, "Failed to load stream cfg\n");
		struct stream_cfg *stream = task->bundle_cfgs[idx].stream_cfgs[0];

		// TODO: check mask and add to hash for each host
		struct new_tuple nt = {
			.dst_addr = stream->servers.ip,
			.proto_id = stream->proto,
			.dst_port = stream->servers.port,
			.l2_types[0] = 0x0008,
		};

		ret = rte_hash_add_key(task->listen_hash, &nt);
		PROX_PANIC(ret < 0, "Failed to add\n");

		task->listen_entries[ret] = &task->bundle_cfgs[idx];

		plogx_dbg("Server = "IPv4_BYTES_FMT":%d\n", IPv4_BYTES(((uint8_t*)&nt.dst_addr)), rte_bswap16(nt.dst_port));
		++idx;
		lua_pop(prox_lua(), 1);
	}

	static char name2[] = "task_gen_hash2";
	name2[0]++;
	PROX_PANIC(bundle_ctx_pool_create(name2, targ->n_concur_conn*2, &task->bundle_ctx_pool, socket_id), "Failed to create conn_ctx_pool");
	task->heap = heap_create(targ->n_concur_conn*2, socket_id);
	task->seed = rte_rdtsc();
}

static void init_task_gen_client(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;
	static char name[] = "gen_pool";
	const uint32_t socket = rte_lcore_to_socket_id(targ->lconf->id);
	name[0]++;
	task->mempool = rte_mempool_create(name,
					   targ->nb_mbuf - 1, MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   socket, 0);

	/* streams contains a lua table. Go through it and read each
	   stream with associated imix_fraction. */
	uint32_t imix;
	int i = 0;

	int pop = lua_getfrom(prox_lua(), GLOBAL, targ->streams);
	PROX_PANIC(pop < 0, "Failed to find '%s' in lua\n", targ->streams);

	lua_len(prox_lua(), -1);
	uint32_t n_bundle_cfgs = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);
	PROX_PANIC(n_bundle_cfgs == 0, "No configs specified\n");
	plogx_info("loading %d bundle_cfgs\n", n_bundle_cfgs);
	task->bundle_cfgs = rte_zmalloc_socket(NULL, n_bundle_cfgs * sizeof(task->bundle_cfgs[0]), RTE_CACHE_LINE_SIZE, socket);
	lua_pushnil(prox_lua());

	int total_imix = 0;
	struct cdf *cdf = cdf_create(n_bundle_cfgs, socket);

	while (lua_next(prox_lua(), -2)) {
		PROX_PANIC(lua_to_int(prox_lua(), TABLE, "imix_fraction", &imix) ||
			   lua_to_bundle_cfg(prox_lua(), TABLE, "bundle", socket, &task->bundle_cfgs[i]),
			   "Failed to load bundle cfg:\n%s\n", get_lua_to_errors());
		cdf_add(cdf, imix);
		total_imix += imix;
		++i;
		lua_pop(prox_lua(), 1);
	}
	lua_pop(prox_lua(), pop);
	cdf_setup(cdf);

	task->tot_imix = total_imix;
	task->cdf = cdf;
	static char name2[] = "task_gen_hash";
	name2[0]++;
	PROX_PANIC(bundle_ctx_pool_create(name2, targ->n_concur_conn, &task->bundle_ctx_pool, socket), "Failed to create conn_ctx_pool");
	task->heap = heap_create(targ->n_concur_conn, socket);
	task->seed = rte_rdtsc();
}

static struct task_init task_init_gen1 = {
	.mode_str = "genl4",
	.sub_mode_str = "server",
	.init = init_task_gen,
	.handle = handle_gen_bulk,
	.flag_features = TASK_ZERO_RX,
	.size = sizeof(struct task_gen_server),
	.mbuf_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
};

static struct task_init task_init_gen2 = {
	.mode_str = "genl4",
	.init = init_task_gen_client,
	.handle = handle_gen_bulk_client,
	.flag_features = TASK_ZERO_RX,
	.size = sizeof(struct task_gen_client),
	.mbuf_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
};

__attribute__((constructor)) static void reg_task_gen(void)
{
	reg_task(&task_init_gen1);
	reg_task(&task_init_gen2);
}
