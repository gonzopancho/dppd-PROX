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

#include "genl4_stream_udp.h"

int stream_udp_is_ended(struct stream_ctx *ctx)
{
	return ctx->cur_action == ctx->stream_cfg->n_actions;
}

int stream_udp_proc(struct stream_ctx *meta, struct rte_mbuf *mbuf, struct pkt_tuple *tuple, struct l4_meta *l4_meta, uint64_t *next_tsc, __attribute__((unused)) uint32_t *retransmit)
{
	/* Timeout, always require a callback to the proc function. */
	*next_tsc = meta->stream_cfg->tsc_timeout;

	if (l4_meta) {
		enum l4gen_peer peer = meta->stream_cfg->actions[meta->cur_action].peer;
		plogx_dbg("Consuming UDP data\n");
		/* data should come from the other side */
		if (peer == meta->peer) {
			plogx_err("Wrong peer\n");
			return -1;
		}
		/* Fixed length data expected */
		if (meta->stream_cfg->actions[meta->cur_action].len != l4_meta->len) {
			plogx_dbg("unexpected UDP len (expected = %u, got = %u, action = %u)\n",
				  meta->stream_cfg->actions[meta->cur_action].len,
				  l4_meta->len,
				  meta->cur_action);

			return -1;
		}
		/* With specific payload */
		if (memcmp(meta->stream_cfg->data[peer].content + meta->cur_pos[peer], l4_meta->payload, l4_meta->len) != 0) {
			plogx_dbg("Bad payload at action_id %d\n", meta->cur_action);
			return -1;
		}
		meta->cur_pos[peer] += l4_meta->len;
		meta->cur_action++;

		if (stream_udp_is_ended(meta))
			return -1;
	}

	if (meta->stream_cfg->actions[meta->cur_action].peer != meta->peer) {
		const char *other_peer_str = meta->peer != PEER_SERVER? "server" : "client";

		plogx_dbg("Expecting more UDP data from %s\n", other_peer_str);
		if (!l4_meta) {
			meta->expired = 1;
		}
		return -1;
	}

	plogx_dbg("Creating UDP packet\n");
	const struct stream_cfg *stream_cfg = meta->stream_cfg;

	uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
	const struct peer_action *act = &stream_cfg->actions[meta->cur_action];

	uint16_t pkt_len = stream_cfg->data[act->peer].hdr_len + sizeof(struct udp_hdr) + act->len;
	/* Create reply */
	rte_pktmbuf_pkt_len(mbuf) = pkt_len;
	rte_pktmbuf_data_len(mbuf) = pkt_len;
	plogx_dbg("Constructing UDP data at %s\n", act->peer == PEER_CLIENT? "client" : "server");
	/* Construct the packet. The template is used up to L4 header,
	   a gap of sizeof(l4_hdr) is skipped, followed by the payload. */
	rte_memcpy(pkt, stream_cfg->data[act->peer].hdr, stream_cfg->data[act->peer].hdr_len);
	rte_memcpy(pkt + stream_cfg->data[act->peer].hdr_len + sizeof(struct udp_hdr), stream_cfg->data[act->peer].content + act->beg, act->len);

	struct ipv4_hdr *l3_hdr = (struct ipv4_hdr*)&pkt[stream_cfg->data[act->peer].hdr_len - sizeof(struct ipv4_hdr)];
	struct udp_hdr *l4_hdr = (struct udp_hdr*)&pkt[stream_cfg->data[act->peer].hdr_len];

	l3_hdr->src_addr = tuple->dst_addr;
	l3_hdr->dst_addr = tuple->src_addr;
	l3_hdr->next_proto_id = IPPROTO_UDP;
	l4_hdr->src_port = tuple->dst_port;
	l4_hdr->dst_port = tuple->src_port;
	l4_hdr->dgram_len = rte_bswap16(sizeof(struct udp_hdr) + act->len);
	/* TODO: UDP checksum calculation */
	l3_hdr->total_length = rte_bswap16(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + act->len);
	meta->cur_pos[meta->peer] += act->len;
	meta->cur_action++;

	/* Send next packet as soon as possible */
	if (meta->stream_cfg->actions[meta->cur_action].peer == meta->peer)
		*next_tsc = 0;

	return 0;
}
