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

#include <rte_cycles.h>

#include "log.h"
#include "genl4_stream_tcp.h"

struct tcp_option {
	uint8_t kind;
	uint8_t len;
} __attribute__((packed));

static void create_tcp_pkt(struct stream_ctx *ctx, struct rte_mbuf *mbuf, struct pkt_tuple *tuple,
			   int put_syn, int put_fin, int put_ack, int put_rst, int data_beg, int data_len)
{
	uint8_t *pkt;

	const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];
	const struct stream_cfg *stream_cfg = ctx->stream_cfg;

	pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
	rte_memcpy(pkt, stream_cfg->data[act->peer].hdr, stream_cfg->data[act->peer].hdr_len);

	struct ipv4_hdr *l3_hdr = (struct ipv4_hdr*)&pkt[stream_cfg->data[act->peer].hdr_len - sizeof(struct ipv4_hdr)];
	struct tcp_hdr *l4_hdr = (struct tcp_hdr *)&pkt[stream_cfg->data[act->peer].hdr_len];

	l3_hdr->src_addr = tuple->dst_addr;
	l3_hdr->dst_addr = tuple->src_addr;
	l3_hdr->next_proto_id = IPPROTO_TCP;

	l4_hdr->src_port = tuple->dst_port;
	l4_hdr->dst_port = tuple->src_port;

	uint32_t tcp_len = sizeof(struct tcp_hdr);
	uint32_t tcp_payload_len = 0;
	uint32_t seq_len = 0;
	struct tcp_option *tcp_op;

	uint8_t tcp_flags = 0;
	if (put_rst) {
		tcp_flags |= 0x04;
		seq_len = 1;
	}
	else if (put_syn) {
		tcp_flags |= 0x02;
		/* Window scaling */

		/* TODO: make options come from the stream. */
		tcp_op = (struct tcp_option *)(l4_hdr + 1);

		tcp_op->kind = 2;
		tcp_op->len = 4;
		*(uint16_t *)(tcp_op + 1) = rte_bswap16(1460);

		tcp_len += 4;
		seq_len = 1;

		ctx->seq_first_byte = ctx->ackd_seq + 1;
	}
	else if (put_fin) {
		tcp_flags |= 0x01;
		seq_len = 1;
	}
	if (put_ack) {
		l4_hdr->recv_ack = rte_bswap32(ctx->recv_seq);
		tcp_flags |= 0x10;
	}
	else
		l4_hdr->recv_ack = 0;

	uint16_t l4_payload_offset = stream_cfg->data[act->peer].hdr_len + tcp_len;

	if (data_len) {
		seq_len = data_len;
		plogx_dbg("l4 payload offset = %d\n", l4_payload_offset);
		rte_memcpy(pkt + l4_payload_offset, stream_cfg->data[act->peer].content + data_beg, data_len);
	}

	l4_hdr->sent_seq = rte_bswap32(ctx->next_seq);
	l4_hdr->tcp_flags = tcp_flags; /* SYN */
	l4_hdr->rx_win = rte_bswap16(0x3890); // TODO: make this come from stream (config)
	//l4_hdr->cksum = ...;
	l4_hdr->tcp_urp = 0;
	l4_hdr->data_off = ((tcp_len / 4) << 4); /* Highest 4 bits are TCP header len in units of 32 bit words */

	/* ctx->next_seq = ctx->ackd_seq + seq_len; */
	ctx->next_seq += seq_len;

	/* No payload after TCP header. */
	rte_pktmbuf_pkt_len(mbuf)  = l4_payload_offset + data_len;
	rte_pktmbuf_data_len(mbuf) = l4_payload_offset + data_len;

	l3_hdr->total_length = rte_bswap16(sizeof(struct ipv4_hdr) + tcp_len + data_len);
	plogdx_dbg(mbuf, NULL);

	plogx_dbg("put tcp packet with flags: %s%s%s, (len = %d, seq = %d, ack =%d)\n", put_syn? "SYN ":"", put_ack? "ACK ":"", put_fin? "FIN " : "", data_len, rte_bswap32(l4_hdr->sent_seq), rte_bswap32(l4_hdr->recv_ack));
}

/* Return: zero: packet in mbuf is the reply, non-zero: data consumed,
   nothing to send. The latter case might mean that the connection has
   ended, or that a future event has been scheduled. in_pkt =>
   mbuf contains packet to be processed. */
int stream_tcp_proc(struct stream_ctx *ctx, struct rte_mbuf *mbuf, struct pkt_tuple *tuple, struct l4_meta *l4_meta, uint64_t *next_tsc, uint32_t *retransmit)
{
	int got_syn = 0;
	int got_ack = 0;
	int got_fin = 0;
	int got_rst = 0;
	int got_data_len = 0;

	int put_ack = 0;
	int put_syn = 0;
	int put_fin = 0;
	int put_rst = 0;

	int data_len = 0;
	int data_beg = 0;

	int no_pkt = 0; /* set to 1 if answer is delayed. */
	struct tcp_hdr *tcp = NULL;

	if (l4_meta) {
		tcp = (struct tcp_hdr *)l4_meta->l4_hdr;

		got_syn = tcp->tcp_flags & 0x02;
		got_ack = tcp->tcp_flags & 0x10;
		got_fin = tcp->tcp_flags & 0x01;
		got_rst = tcp->tcp_flags & 0x04;
		plogx_dbg("TCP, flags: %s%s%s, (len = %d, seq = %d, ack =%d)\n", got_syn? "SYN ":"", got_ack? "ACK ":"", got_fin? "FIN " : "", l4_meta->len, rte_bswap32(tcp->sent_seq), rte_bswap32(tcp->recv_ack));

		int progress_ack = 0, progress_seq = 0;

		/* RST => other side wants to terminate due to
		   inconsitent state (example: delay of retransmit of
		   last ACK while other side already closed the
		   connection. The other side will accept the packet
		   as a beginning of a new connection but there will
		   be no SYN. ) */
		if (got_rst) {
			plogx_dbg("got rst\n");
			ctx->tcp_ended = 1;
			return -1;
		}

		if (got_ack) {
			uint32_t ackd_seq = rte_bswap32(tcp->recv_ack);

			if (ackd_seq > ctx->ackd_seq) {
				plogx_dbg("Got ACK for outstanding data, from %d to %d\n", ctx->ackd_seq, ackd_seq);
				ctx->ackd_seq = ackd_seq;
				plogx_dbg("ackable data = %d\n", ctx->ackable_data_seq);
				/* Ackable_data_seq set to byte after
				   current action. */
				if (ctx->ackable_data_seq == ctx->ackd_seq) {
					ctx->ackable_data_seq = 0;
					const struct stream_cfg *stream_cfg = ctx->stream_cfg;
					const struct peer_action *act = &stream_cfg->actions[ctx->cur_action];

					ctx->cur_pos[act->peer] += act->len;
					ctx->cur_action++;
					plogx_dbg("Moving to next action\n");
				}
				progress_ack = 1;
			}
			else {
				plogx_dbg("Old data acked: acked = %d, ackable =%d\n", ackd_seq, ctx->ackd_seq);
			}
		}

		uint32_t seq = rte_bswap32(tcp->sent_seq);

		/* update recv_seq. */
		if (got_syn) {
			/* When a syn is received, immediately reset recv_seq based on seq from packet. */
			ctx->recv_seq = seq + 1;
			/* Syn packets have length 1, so the first real data will start after that. */
			ctx->other_seq_first_byte = seq + 1;
			progress_seq = 1;
		}
		else if (got_fin) {
			if (ctx->recv_seq == seq) {
				plogx_dbg("Got fin with correct seq\n");
				ctx->recv_seq = seq + 1;
				progress_seq = 1;
			}
			else {
				plogx_dbg("Got fin but incorrect seq\n");
			}
		}
		else {
			/* Only expect in-order packets. */
			if (ctx->recv_seq == seq) {
				plogx_dbg("Got data with seq %d (as expected), with len %d\n", seq, l4_meta->len);
				ctx->last_data_tsc = rte_rdtsc();

				if (l4_meta->len) {
					const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];
					enum l4gen_peer peer = act->peer;
					/* Since we have received the expected sequence number, the start address will not exceed the cfg memory buffer. */
					uint8_t *content = ctx->stream_cfg->data[peer].content;
					uint32_t seq_beg = seq - ctx->other_seq_first_byte;
					uint32_t end = ctx->stream_cfg->actions[ctx->cur_action].beg + ctx->stream_cfg->actions[ctx->cur_action].len;
					uint32_t remaining = end - seq_beg;

					if (l4_meta->len > remaining) {
						plogx_err("Provided data is too long:\n");
						plogx_err("action.beg = %d, action.len = %d", act->beg, act->len);
						plogx_err("tcp seq points at %d in action, l4_meta->len = %d\n", seq_beg, l4_meta->len);
					}
					else {
						if (memcmp(content + seq_beg, l4_meta->payload, l4_meta->len) == 0) {
							plogx_dbg("Good payload in %d\n", ctx->cur_action);
							ctx->recv_seq = seq + l4_meta->len;
							ctx->cur_pos[peer] += l4_meta->len;
							/* Move forward only when this was the last piece of data within current action (i.e. end of received data == end of action data). */
							if (seq_beg + l4_meta->len == act->beg + act->len) {
								plogx_dbg("Got last piece in action %d\n", ctx->cur_action);
								ctx->cur_action++;
							}
							else {
								plogx_dbg("Got data from %d with len %d, but waiting for more (tot len = %d)!\n", seq_beg, l4_meta->len, act->len);
							}
							progress_seq = 1;
							put_ack = 1;
						}
						else {
							plogx_err("Bad payload at action_id %d, %d\n", ctx->cur_action, ctx->other_seq_first_byte);
							plogx_err("   pkt payload len = %d, action len = %d\n", l4_meta->len, act->len);
							plogx_err("   Payload starts %zu bytes after beginning of l4_hdr\n", l4_meta->payload - l4_meta->l4_hdr);
							plogx_err("   cur_pos = %d, payload[0-1] = %02x %02x\n", seq_beg, l4_meta->payload[0], l4_meta->payload[1]);
							plogx_err("Not ACK'ing\n");
							plogdx_err(mbuf, NULL);
						}
					}
				}
			}
			else if (ctx->recv_seq < seq) {
				plogx_dbg("Future data received (got = %d, expected = %d), missing data! (data ignored)\n", seq, ctx->recv_seq);
			}
			else {
				plogx_dbg("Old data received again (state = %s)\n", tcp_state_to_str(ctx->tcp_state));
				plogx_dbg("expecting seq %d, got seq %d, len = %d\n",ctx->recv_seq, seq, l4_meta->len);
				plogx_dbg("ackd_seq = %d, next_seq = %d, action = %d\n", ctx->ackd_seq, ctx->next_seq, ctx->cur_action);
			}
		}

		/* parse options */
		if (((tcp->data_off >> 4)*4) > sizeof(struct tcp_hdr)) {
			struct tcp_option *tcp_op = (struct tcp_option *)(tcp + 1);
			uint8_t *payload = (uint8_t *)tcp + ((tcp->data_off >> 4)*4);

			do {
				if (tcp_op->kind == 2 && tcp_op->len == 4) {
					uint16_t mss = rte_bswap16(*(uint16_t *)(tcp_op + 1));
					ctx->other_mss = mss;
				}

				tcp_op = (struct tcp_option *)(((uint8_t*)tcp_op) + tcp_op->len);
			} while (((uint8_t*)tcp_op) < payload);
		}

		if (progress_ack || progress_seq) {
			ctx->same_state = 0;
		}
	}


	/* Consume data (move ack forward). Set ack
	   needed... which will be set in the next packet. */
	switch (ctx->tcp_state) {
	case CLOSED: /* Client initial state */
		if (l4_meta) {
			plogx_err("Invalid state\n");
			/* This state is impossible (i.e. receive a
			   packet while not having sent any
			   packet, since the client immediately goes
			   out of CLOSED by sending a SYN. It never
			   receives data before that as it is the initiator. */
		}
		else {
			/* create SYN packet in mbuf, return 0. goto SYN_SENT, ++same_state, set timeout */
			put_syn = 1;
			ctx->same_state = 0;
			ctx->tcp_state = SYN_SENT;

			/* Initialize: */
			ctx->next_seq = 99;
			ctx->ackd_seq = 99;
		}
		break;
	case LISTEN: /* Server starts in this state. */
		if (l4_meta) {
			/* if syn received _now_, send ack + syn. goto SYN_RECEIVED. */
			plogx_dbg("Got packet while listen\n");
			if (!got_syn) {
				// TODO: keep connection around at end to catch retransmits from client
				plogx_dbg("Got packet while listening without SYN (will send RST)\n");
				pkt_tuple_debug(tuple);

				put_rst = 1;
				ctx->tcp_ended = 1;

				break;
			}

			ctx->next_seq = 200;
			ctx->ackd_seq = 200;

			put_syn = 1;
			put_ack = 1;

			ctx->tcp_state = SYN_RECEIVED;
		}
		else {
			plogx_err("Impossible state: timeout while LISTEN\n");
			/* This is impossible since the tcp state at
			   the server side is created when the first
			   packet is received. */
		}
		break;
	case SYN_SENT:
		if (l4_meta) {
			plogx_dbg("SYN_SENT and got packet\n");
			/* if not acked, send syn again */
			if (ctx->ackd_seq < ctx->next_seq) {
				plogx_info("resend syn!, %d\n", got_syn);
				/* Resend SYN */
				put_syn = 1;
				++ctx->same_state;
				*retransmit = 1;
				/* Initialize: */
				ctx->next_seq = 99;
				ctx->ackd_seq = 99;

				break;
			}
			plogx_dbg("ackd_seq = %d, next_seq = %d\n", ctx->ackd_seq, ctx->next_seq);
			/* else, if syn received _now_, send ack. reset same_state, set timeout, goto ESTABLISHED, if first to send, schedule immediately. */
			if (got_syn) {
				put_ack = 1;
				ctx->same_state = 0;
				ctx->tcp_state = ESTABLISHED;

				if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
					*next_tsc = 0;
					plogx_dbg("immediately resched (%d)\n", ctx->cur_action);
				}
			}
		}
		else {
			plogx_dbg("Retransmit SYN, %"PRIu64"\n", rte_rdtsc() - ctx->last_data_tsc);
			/* Did not get packet, send syn again and keep state (waiting for ACK). */
			put_syn = 1;
			++ctx->same_state;
			*retransmit = 1;

			/* Initialize: */
			ctx->next_seq = 99;
			ctx->ackd_seq = 99;
		}
		break;
	case SYN_RECEIVED:
		if (l4_meta) {
			if (ctx->ackd_seq == ctx->next_seq) {
				ctx->same_state = 0;
				ctx->tcp_state = ESTABLISHED;

				/* Possible from server side with
				   ctx->cur_action == 1 if the
				   current packet received had ACK for
				   syn from server to client and also
				   data completing the first
				   action. */
				if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
					*next_tsc = 0;
					if (!put_ack) {
						plogx_warn("no ack\n");
					}

					plogx_dbg("immediately resched (%d)\n", ctx->cur_action);
				}
				else
					no_pkt = 1;
				plogx_dbg("Going from SYN_RECEIVED to ESTABLISHED\n");
			}
			else {
				plogx_dbg("Retransmit SYN/ACK (got data, ackd_seq = %d, next_seq = %d\n", ctx->ackd_seq, ctx->next_seq);
				put_syn = 1;
				put_ack = 1;
				*retransmit = 1;
				++ctx->same_state;
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		else {
			if (ctx->ackd_seq == ctx->next_seq) {
				ctx->same_state = 0;
				ctx->tcp_state = ESTABLISHED;
				no_pkt = 1;

				if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
					*next_tsc = 0;
					plogx_dbg("immediately resched (%d)\n", ctx->cur_action);
				}
				plogx_dbg("Going from SYN_RECEIVED to ESTABLISHED\n");
			}
			else {
				plogx_dbg("Retransmit SYN/ACK %"PRIu64"\n", ctx->last_data_tsc);
				put_syn = 1;
				put_ack = 1;
				++ctx->same_state;
				*retransmit = 1;
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		break;
	case ESTABLISHED:
		if (l4_meta) {
			plogx_dbg("ESTABLISHED and got pkt!\n");
			if (got_fin) {
				plogx_dbg("Got fin!\n");

				/* Current implementation does not use CLOSE_WAIT*/
				if (1) {
					put_ack = 1;
					put_fin = 1;
					ctx->tcp_state = LAST_ACK;
				}
				else {
					put_fin = 1;
					ctx->tcp_state = CLOSE_WAIT;
					*next_tsc = 0;
				}
				break;
			}
			else {
				put_ack = 1;
			}
		}

		const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];

		if (act->peer == ctx->peer) {
			plogx_dbg("This peer to send!\n");
			uint32_t outstanding_bytes = ctx->next_seq - ctx->ackd_seq;

			data_beg = ctx->next_seq - ctx->seq_first_byte;
			uint32_t remaining_len2 = act->len - (data_beg - act->beg);

			/* remaining_len2 will be zero, while in case
			   of act->len == 0, the connection can be
			   closed immediately. */
			if (act->len == 0) {
				plogx_dbg("Closing connection\n");
				put_ack = 1;
				put_fin = 1;
				/* This would be an ACK
				   combined with FIN. To send
				   a separate ack. keep the state in established, put_ack and expire immediately*/
				plogx_dbg("Moving to FIN_WAIT\n");
				ctx->tcp_state = FIN_WAIT;
				ctx->same_state = 0;
				break;
			}


			/* If still data to be sent and allowed by outstanding amount*/
			if (outstanding_bytes ==0 /* < 30000 */ && remaining_len2) {
				plogx_dbg("Outstanding bytes = %d, and remaining_len = %d, next_seq = %d\n", outstanding_bytes, remaining_len2, ctx->next_seq);
				if (ctx->ackable_data_seq == 0)
					ctx->ackable_data_seq = ctx->next_seq + act->len;
				else
					plogx_dbg("This will not be the first part of the data within an action\n");

			}
			/* still data yet to be acked || still data to be sent */
			else {
				/* If got packet, ignore it */
				if (l4_meta) {
					no_pkt = 1;

					uint64_t now = rte_rdtsc();
					/* Schedule remaining time (or schedule immediately if already passed) */
					if (ctx->last_tsc + ctx->stream_cfg->tsc_timeout < now) {
						*next_tsc = 0;
					}
					else
						*next_tsc = ctx->last_tsc + ctx->stream_cfg->tsc_timeout - now;
					break;
				}
				else {
					if ( !ctx->more_data) {
						ctx->same_state++;
						*retransmit = 1;
						/* This possibly means that now retransmit is resumed half-way in the action. */
						plogx_dbg("Retransmit: outstanding = %d\n", outstanding_bytes);
						plogx_dbg("Assuming %d->%d lost\n", ctx->ackd_seq, ctx->next_seq);
						ctx->next_seq = ctx->ackd_seq;
						plogx_dbg("ack = %d, next = %d, %"PRIu64", last = %"PRIu64"\n",
							  ctx->ackd_seq, ctx->next_seq,
							  (rte_rdtsc() - ctx->last_tsc_data_sent)*1000000/rte_get_tsc_hz(),
							  (rte_rdtsc() - ctx->last_tsc)*1000000/rte_get_tsc_hz());
						plogx_dbg("highest seq from other side = %d\n", ctx->recv_seq);
					}
					/* this is hit when called without data and too many outstanding bytes.*/
					else {
						ctx->more_data = 0;
						/* Don't send any packet. */
						no_pkt = 1;
						break;
					}
				}
				/* When ctx->more_data is set, real
				   timeouts can't occur. If this is
				   needed, timeouts need to carry
				   additional information. */
			}


			if (act->len == 0) {
				plogx_dbg("Closing connection\n");
				put_ack = 1;
				put_fin = 1;
				/* This would be an ACK
				   combined with FIN. To send
				   a separate ack. keep the state in established, put_ack and expire immediately*/
				plogx_dbg("Moving to FIN_WAIT\n");
				ctx->tcp_state = FIN_WAIT;
				ctx->same_state = 0;
			}
			else {
				/* The following code will retransmit the same data if next_seq is not moved forward. */
				data_beg = ctx->next_seq - ctx->seq_first_byte;
				uint32_t remaining_len = act->len - (data_beg - act->beg);
				data_len = remaining_len > ctx->other_mss? ctx->other_mss: remaining_len;
				if (data_len == 0)
					plogx_warn("data_len == 0\n");

				ctx->more_data = remaining_len > ctx->other_mss;
				if (ctx->more_data)
					*next_tsc = 0;
				ctx->last_tsc_data_sent = rte_rdtsc();
				put_ack = 1;
			}
		}
		/* Currently listening to incoming data (cur action is
		   from other peer), just resend ACK */
		else if (!l4_meta) {
			put_ack = 1;
			ctx->same_state++;
			*retransmit = 1;
			plogx_dbg("state++ (ack = %d), %"PRIu64", %"PRIu64"\n",
				  ctx->recv_seq, rte_rdtsc() - ctx->last_tsc,
				  rte_rdtsc() - ctx->last_data_tsc);
		}
		break;
	case CLOSE_WAIT:
		if (l4_meta) {
			put_ack = 1;
			put_fin = 1;
			ctx->tcp_state = LAST_ACK;
		}
		else {
			put_ack = 1;
			put_fin = 1;
			ctx->tcp_state = LAST_ACK;
			ctx->next_seq = ctx->ackd_seq;
		}
		break;
	case LAST_ACK:
		if (l4_meta) {
			if (ctx->ackd_seq == ctx->next_seq) {
				plogx_dbg("Last ACK received\n");
				ctx->tcp_ended = 1;
				no_pkt = 1;
			}
			else {
				put_fin = 1;
				put_ack = 1;
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		else {
			if (ctx->ackd_seq == ctx->next_seq) {
				ctx->tcp_ended = 1;
				plogx_info("Last ACK from expire\n");
				no_pkt = 1;
			}
			else {
				put_fin = 1;
				put_ack = 1;
				ctx->same_state++;
				*retransmit = 1;
				plogx_dbg("Retransmit!\n");
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		break;
	case FIN_WAIT:
		if (l4_meta) {
			if (ctx->ackd_seq == ctx->next_seq) {
				if (got_fin) {
					put_ack = 1;
					ctx->same_state = 0;
					*next_tsc = ctx->stream_cfg->tsc_timeout_time_wait;
					ctx->tcp_state = TIME_WAIT;
					plogx_dbg("from FIN_WAIT to TIME_WAIT (timeout = %"PRIu64")\n", ctx->stream_cfg->tsc_timeout_time_wait);
				}
				else {
					plogx_dbg("Same state++\n");
					put_ack = 1;
					ctx->same_state++;
					*retransmit = 1;
				}
			}
			else {
				put_fin = 1;
				put_ack = 1;
				ctx->same_state++;
				*retransmit = 1;
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		else {
			if (ctx->ackd_seq == ctx->next_seq) {
				put_ack = 1;
				ctx->same_state = 0;
				ctx->tcp_state = TIME_WAIT;
				*next_tsc = ctx->stream_cfg->tsc_timeout_time_wait;
				plogx_dbg("Moving from FIN_WAIT to TIME_WAIT timeout = %"PRIu64"\n", ctx->stream_cfg->tsc_timeout_time_wait);
			}
			else {
				put_fin = 1;
				put_ack = 1;
				ctx->same_state++;
				*retransmit = 1;
				plogx_dbg("Retransmit!\n");
				ctx->next_seq = ctx->ackd_seq;
			}
		}
		break;
	case TIME_WAIT:
		if (l4_meta) {
			/* Ignore packet (although still parse ACK). no_pkt = 1 */
			plogx_dbg("Got packet while in TIME_WAIT (pkt ignored)\n");
			*next_tsc = ctx->stream_cfg->tsc_timeout_time_wait;
			put_ack = 1; /* Got packet, send ACK to move other side forward. */
		}
		else {
			plogx_dbg("TIME_WAIT expired! for %#x\n", tuple->dst_addr);
			ctx->tcp_ended = 1;
			no_pkt = 1;
		}
		break;
	}

	if (*next_tsc == UINT64_MAX && !ctx->tcp_ended) {
		*next_tsc = ctx->stream_cfg->tsc_timeout;
	}
	ctx->last_tsc = rte_rdtsc();

	if (no_pkt)
		return -1;

	if (ctx->same_state == 10) {
		ctx->expired = 1;
		return -1;
	}

	create_tcp_pkt(ctx, mbuf, tuple, put_syn, put_fin, put_ack, put_rst, data_beg, data_len);
	return 0;
}

int stream_tcp_is_ended(struct stream_ctx *ctx)
{
	return ctx->tcp_ended;
}
