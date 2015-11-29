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

#ifndef _GENL4_STREAM_H_
#define _GENL4_STREAM_H_

#include "prox_lua_types.h"
#include "pkt_parser.h"

enum tcp_state {
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECEIVED,
	ESTABLISHED,
	CLOSE_WAIT,
	LAST_ACK,
	FIN_WAIT,
	TIME_WAIT
};

static const char *tcp_state_to_str(const enum tcp_state s)
{
	switch(s) {
	case CLOSED:
		return "CLOSED";
	case LISTEN:
		return "LISTEN";
	case SYN_SENT:
		return "SYN_SENT";
	case SYN_RECEIVED:
		return "SYN_RECEIVED";
	case ESTABLISHED:
		return "ESTABLISHED";
	case CLOSE_WAIT:
		return "CLOSE_WAIT";
	case LAST_ACK:
		return "LAST_ACK";
	case FIN_WAIT:
		return "FIN_WAIT";
	case TIME_WAIT:
		return "TIME_WAIT";
	default:
		return "INVALID_STATE";
	}
}

/* Run-time structure to management state information associated with current stream_cfg. */
struct stream_ctx {
	enum l4gen_peer         peer;
	uint32_t                cur_action;
	uint32_t                cur_pos[2];
	enum tcp_state          tcp_state;
	uint32_t                expired;
	uint32_t                same_state;
	uint32_t                next_seq;
	uint32_t                ackd_seq;
	uint32_t                recv_seq;
	uint32_t                needs_ack;
	uint32_t                ackable_data_seq;
	uint32_t                seq_first_byte;       /* seq number - seq_first_byte gives offset within content. */
	uint32_t                other_seq_first_byte; /* seq number - seq_first_byte gives offset within content. */
	uint32_t                other_mss;
	uint64_t                last_tsc;
	uint64_t                last_data_tsc;
	uint64_t                last_tsc_data_sent;
	int                     tcp_ended;
	uint32_t                more_data;
	uint32_t                retransmits;
	const struct stream_cfg *stream_cfg;          /* Current active steam_cfg */
};

struct host_set {
	uint32_t ip;
	uint32_t ip_mask;
	uint16_t port;
	uint16_t port_mask;
};

struct stream_cfg {
	struct peer_data   data[2];
	struct host_set    servers; // Current implementation only allows mask == 0. (i.e. single server)
	uint16_t           proto;
	uint64_t           tsc_timeout;
	uint64_t           tsc_timeout_time_wait;
	uint32_t           n_actions;
	int                (*proc)(struct stream_ctx *meta, struct rte_mbuf *mbuf, struct pkt_tuple *tuple, struct l4_meta *l4_meta, uint64_t *next_tsc, uint32_t *retransmit);
	int                (*is_ended)(struct stream_ctx *meta);
	struct peer_action actions[0];
};

#endif /* _GENL4_STREAM_H_ */
