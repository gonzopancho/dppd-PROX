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
#include <rte_byteorder.h>

#include "handle_gen.h"
#include "handle_lat.h"
#include "task_init.h"
#include "task_base.h"
#include "prox_port_cfg.h"
#include "lconf.h"
#include "log.h"
#include "quit.h"
#include "prox_cfg.h"
#include "mbuf_utils.h"
#include "qinq.h"
#include "prox_cksum.h"
#include "etypes.h"


#ifndef RTE_CACHE_LINE_SIZE
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

static inline uint8_t init_ipv4_csum(struct ipv4_hdr *ip, uint8_t *pkt, uint8_t l2_len)
{
	uint8_t l3_len = sizeof(struct ipv4_hdr);
	if (unlikely(ip->version_ihl >> 4 != 4)) {
		plog_warn("IPv4 ether_type but IP version = %d != 4", ip->version_ihl >> 4);
		return 0;
	}
	if (unlikely((ip->version_ihl & 0xF) != 5)) {
		l3_len = (ip->version_ihl & 0xF) * 4;
	}
	// Initialize IP header Csum
	ip->hdr_checksum = 0;

	// L4 offloads requires L4 CSUM to be prefilled with CSUM of pseudo header...
	// L4 Offload makes most sense for big packet sizes...
	if (ip->next_proto_id == IPPROTO_UDP) {
		prox_write_udp_cksum_pseudo_hdr(pkt, l2_len, l3_len);
	} else 	if (ip->next_proto_id == IPPROTO_TCP) {
		prox_write_tcp_cksum_pseudo_hdr(pkt, l2_len, l3_len);
	}
	return l3_len;
}

static void handle_gen_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen *task = (struct task_gen *)tbase;
	struct rte_mbuf **new_pkts = task->new_pkts;
	uint64_t* pkt_tsc_offsets = task->pkt_tsc_offsets; /* bulk extrapolation */
	uint32_t** pkt_tsc_pointer = task->pkt_tsc_pointer;
	uint32_t ret, ret_tmp;
	uint32_t send_bulk = 0;
	uint64_t bytes_since_first_pkt = 0;
	uint64_t bytes_diff;

	/* next 2 values are passed empty by thread_call */
	(void)mbufs;
	(void)n_pkts;

	if (task->start_tsc == 0) {
		task->start_tsc = rte_rdtsc();
		task->bytes_now = 0;
		task->bytes_start_tsc = 0;
		task->sent_bytes = 0;
		return;
	}
	if (task->rate_bps != task->new_rate_bps) {
		task->start_tsc = rte_rdtsc();
		task->bytes_now = 0;
		task->bytes_start_tsc = 0;
		task->sent_bytes = 0;
		task->rate_bps = task->new_rate_bps;
	}

	uint64_t bps = task->rate_bps;

	if (!bps) {
		task->start_tsc = 0;
		return ;
	}

	if (rte_rdtsc() - task->start_tsc > rte_get_tsc_hz()) {
		task->start_tsc+=task->bytes_start_tsc*rte_get_tsc_hz()/bps;
		task->bytes_start_tsc = 0;
		if (rte_rdtsc() - task->start_tsc > rte_get_tsc_hz()) {
			// This should only happen if thread was stopped for some time (more than one sec)
			// We should probably reset start_tsc when stopping the core
			// Best is to reset...
			// If the thread stopped for less than one sec, then we might xmit too fast : bug
			plog_info("Thread was stopped ...\n");
			task->start_tsc = rte_rdtsc();
			task->bytes_now = 0;
			task->sent_bytes = 0;
			return;
		}
	}
	bytes_diff = (rte_rdtsc() - task->start_tsc)*bps/rte_get_tsc_hz() - task->bytes_start_tsc;

	task->bytes_now += bytes_diff;
	task->bytes_start_tsc += bytes_diff;
	uint64_t can_send_bytes = task->bytes_now - task->sent_bytes;

	uint64_t will_send_bytes = 0;

	/* The biggest bulk we allow to send is 64 packets. At the
	   same time, we are rate limiting based on the specified
	   speed (in bytes per second). */

	uint32_t would_send_bytes = 0;
	uint32_t pkt_idx_tmp = task->pkt_idx;
	for (uint16_t j = 0; j < 64; ++j) {
		uint32_t pkt_size = task->pkt_size? task->pkt_size : task->proto_len[pkt_idx_tmp];
		uint32_t pkt_len = (pkt_size < 60? 60 : pkt_size) + 20 + 4;
		if (pkt_len + would_send_bytes > can_send_bytes) {
			break;
		}

		pkt_idx_tmp++;
		if (pkt_idx_tmp >= task->n_pkts) {
			pkt_idx_tmp = 0;
		}

		send_bulk++;
		would_send_bytes += pkt_len;
	}

	/* Loop was too fast. */
	if (send_bulk == 0)
		return ;

	if (task->pkt_count == 0) {
		/* packets are being sent from count, but all of them
		   have already been sent. In this case, throw away
		   all tokens to avoid accumulation of tokens. If
		   tokens would not be thrown away, transmit rate
		   after resume would be line-rate. */
		task->sent_bytes += can_send_bytes;
		return ;
	}

	if (task->pkt_count != (uint32_t)-1) {
		if (task->pkt_count > send_bulk) {
			task->pkt_count -= send_bulk;
		}
		else {
			send_bulk = task->pkt_count;
			task->pkt_count = 0;
		}
	}

	if (rte_mempool_get_bulk(task->mempool, (void **)new_pkts, send_bulk) < 0) {
		return ;
	}
	for (uint16_t j = 0; j < send_bulk; ++j) {
		uint32_t pkt_size = task->pkt_size? task->pkt_size : task->proto_len[task->pkt_idx];
		uint32_t pkt_len = (pkt_size < 60? 60 : pkt_size) + 20 + 4;
		struct rte_mbuf *next_pkt = new_pkts[j];

		rte_pktmbuf_pkt_len(next_pkt) = pkt_size;
		rte_pktmbuf_data_len(next_pkt) = pkt_size;

		init_mbuf_seg(next_pkt);

		struct ether_hdr *hdr = rte_pktmbuf_mtod(next_pkt, struct ether_hdr *);
		rte_memcpy(rte_pktmbuf_mtod(next_pkt, void *), task->proto[task->pkt_idx].buf, task->proto_len[task->pkt_idx]);
		uint8_t *pret_tmp = (uint8_t*)&ret_tmp;

		/* apply all randoms */
		for (uint16_t i = 0; i < task->n_rands; ++i) {
			ret = rand_r(&task->seeds[i]);
			ret_tmp = (ret & task->rand_mask[i]) | task->fixed_bits[i];

			ret_tmp = rte_bswap32(ret_tmp);
			/* At this point, the lower order bytes (BE)
			   contain the generated value. The address
			   where the values of interest starts is at
			   ret_tmp + 4 - rand_len. */
			rte_memcpy(rte_pktmbuf_mtod(next_pkt, uint8_t *) + task->rand_offset[i], pret_tmp + 4 - task->rand_len[i], task->rand_len[i]);
		}
		/* apply all fixed values */
		for (uint16_t i = 0; i < task->n_values; ++i) {
			rte_memcpy(rte_pktmbuf_mtod(next_pkt, uint8_t *) + task->offset[i], &task->value[i], task->value_len[i]);
		}
		pkt_tsc_offsets[j] = rte_get_tsc_hz()*will_send_bytes/1250000000;
		pkt_tsc_pointer[j] = (uint32_t *)(rte_pktmbuf_mtod(new_pkts[j], uint8_t *) + task->lat_pos);
		will_send_bytes += pkt_len;

		task->pkt_idx++;
		if (task->pkt_idx >= task->n_pkts) {
			task->pkt_idx = 0;
		}

		uint8_t l2_len = sizeof(struct ether_hdr), l3_len = 0;
		struct ipv4_hdr *ip;
		uint8_t *pkt = (uint8_t *)hdr;

		switch (hdr->ether_type) {
			case ETYPE_IPv6:
				// No L3 cksum offload, but TODO L4 offload
				l2_len = 0;
				break;
			case ETYPE_MPLSU:
			case ETYPE_MPLSM:
				l2_len +=4;
			case ETYPE_IPv4:
				// Initialize l3_len and l3 header csum for IP CSUM offload.
				ip = (struct ipv4_hdr *)(pkt + l2_len);
				l3_len = init_ipv4_csum(ip, pkt, l2_len);
				break;
			case ETYPE_EoGRE:
				// Not implemented yet
				break;
			case ETYPE_8021ad:
			case ETYPE_VLAN:
				l2_len +=4;
				struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)hdr;
				struct qinq_hdr *qinq_hdr = (struct qinq_hdr *)hdr;
				switch (qinq_hdr->cvlan.eth_proto) {
				case ETYPE_IPv6:
					l2_len = 0;
					break;
				case ETYPE_VLAN:
					l2_len +=4;
					if (qinq_hdr->ether_type == ETYPE_IPv4) {
						// Update l3_len for IP CSUM offload in case IP header contains optional fields.
						ip = (struct ipv4_hdr *)(qinq_hdr + 1);
						l3_len = init_ipv4_csum(ip, pkt, l2_len);
					} else if (qinq_hdr->ether_type == ETYPE_ARP) {
						l2_len = 0;
					} else {
						l2_len = 0;
					}
					break;
				case ETYPE_IPv4:
					// Update l3_len for IP CSUM offload in case IP header contains optional fields.
					ip = (struct ipv4_hdr *)(vlan_hdr + 1);
					l3_len = init_ipv4_csum(ip, pkt, l2_len);
					break;
				case ETYPE_ARP:
					l2_len = 0;
					break;
				default:
					l2_len = 0;
					plog_warn("Unsupported packet type %x - CRC might be wrong\n", qinq_hdr->cvlan.eth_proto);
					break;
				}
				break;
			case ETYPE_ARP:
				l2_len = 0;
				break;
			default:
				l2_len = 0;
				plog_warn("Unsupported packet type %x - CRC might be wrong\n", hdr->ether_type);
				break;
		}
		if (l2_len) {
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
                	prox_ip_cksum_hw(next_pkt, (l2_len << 9) | l3_len);
#else
                	next_pkt->tx_offload = CALC_TX_OL(l2_len, l3_len);
                	next_pkt->ol_flags |= PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM;
#endif
		}
	}

	/* If max burst has been sent, we can't keep up so just assume
	   that we can (leaving a "gap" in the packet stream on the
	   wire) */
	if (send_bulk == 64) {
		task->sent_bytes += can_send_bytes;
	}
	else
		task->sent_bytes += will_send_bytes;

	/* Just before sending the packets, apply the time stamp
	   relative to when the first packet will be sent. The first
	   packet will be sent now. The time is read for each packet
	   to reduce the error towards the actual time the packet will
	   be sent. */

	if (task->lat_enabled) {
		// t
		uint64_t now = rte_rdtsc() + 400; /* assume writing tsc will take 400 cycles. */
		for (uint16_t j = 0; j < send_bulk; ++j) {
			*(pkt_tsc_pointer[j]) = (now + pkt_tsc_offsets[j]) >> LATENCY_ACCURACY;
		}

		/* Make sure it takes at least 400 cycles */
		while(rte_rdtsc() < now);
	}

	// t + 400
	task->base.tx_pkt(&task->base, new_pkts, send_bulk, NULL);
	// t+ 4400
}

static void init_task_gen(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen *task = (struct task_gen *)tbase;
	static char name[] = "gen_pool";

	name[0]++;
	task->mempool = rte_mempool_create(name,
					   targ->nb_mbuf - 1, MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   rte_lcore_to_socket_id(targ->lconf->id), 0);
	task->lat_pos = targ->lat_pos;
	task->new_rate_bps = targ->rate_bps;
	/* init all seeds */
	for (size_t i = 0; i < sizeof(task->seeds)/sizeof(task->seeds[0]); ++i) {
		task->seeds[i] = rte_rdtsc();
	}

	for (uint32_t i = 0; i < targ->n_rand_str; ++i) {
		PROX_PANIC(strlen(targ->rand_str[i]) > 32, "Maximum random length is 32\n");
		PROX_PANIC(strlen(targ->rand_str[i]) % 8 || !strlen(targ->rand_str[i]),
			   "Random should be multiple of 8 long and at least 1 byte\n");
		task->rand_len[i] = strlen(targ->rand_str[i])/8;
		task->rand_offset[i] = targ->rand_offset[i];

		/* for each random, X0010101XXX... syntax is used:
		   X = rand bit
		   0, 1 = fixed bit. */
		uint32_t rnd_len_bits = task->rand_len[i] * 8;
		for (uint32_t j = 0; j < rnd_len_bits; ++j) {
			/* Store in the lower bits the value of the
			   rand string (note that these are the higher
			   bits in LE). */
			if (targ->rand_str[i][j] == 'X') {
				task->rand_mask[i] |= 1 << (rnd_len_bits - 1 - j);
			}
			else if (targ->rand_str[i][j] == '1') {
				task->fixed_bits[i] |= 1 << (rnd_len_bits - 1 - j);
			}
			else {
				PROX_PANIC(targ->rand_str[i][j] != '0', "Unexpected %c\n", targ->rand_str[i][j]);
			}
		}
		PROX_PANIC((task->rand_mask[i] & RAND_MAX) != task->rand_mask[i],
			   "Using rand() as random generator which has generates values in [0, %u]"
			   " while the mask specified was %u. Suggesting to use 2 random fields instead",
			   RAND_MAX, task->rand_mask[i]);
	}

	task->pkt_count = -1;
	task->n_rands = targ->n_rand_str;
	task->lat_enabled = targ->lat_enabled;
	task->pkt_size = targ->pkt_size;

	if (*targ->pcap_file == 0) {
		plog_info("Using inline definition of a packet\n");
		task->n_pkts = 1;
		PROX_PANIC(task->pkt_size == 0, "Invalid packet size length (no packet defined?)\n");
		task->pkt_size = targ->pkt_size;
		task->proto = rte_zmalloc_socket(NULL, task->n_pkts * sizeof(gen_proto), RTE_CACHE_LINE_SIZE, rte_lcore_to_socket_id(targ->lconf->id));
		rte_memcpy(task->proto[0].buf, targ->pkt_inline, RTE_MIN(targ->pkt_size, sizeof(task->proto[0].buf)));
		if ((targ->flags & DSF_KEEP_SRC_MAC) == 0)
			rte_memcpy(&task->proto[0].buf[6], prox_port_cfg[tbase->tx_params_hw.tx_port_queue->port].eth_addr.addr_bytes, 6);
		task->proto_len = rte_zmalloc_socket(NULL, task->n_pkts*sizeof(*task->proto_len), RTE_CACHE_LINE_SIZE, rte_lcore_to_socket_id(targ->lconf->id));
		task->proto_len[0] = targ->pkt_size;
		return ;
	}

	plog_info("Loading from pcap %s\n", targ->pcap_file);

	char err[PCAP_ERRBUF_SIZE];
 	pcap_t *handle = pcap_open_offline(targ->pcap_file, err);
	PROX_PANIC(handle == NULL, "Failed to open PCAP file: %s\n", err);
	long pkt1_fpos = ftell(pcap_file(handle));

	struct pcap_pkthdr header;

	// First, just count the packets
	task->n_pkts = 0;
	const uint8_t *buf;
	while ((buf = pcap_next(handle, &header))) {
		task->n_pkts++;
	}

	// Now load the packets
	int ret = fseek(pcap_file(handle), pkt1_fpos, SEEK_SET);
	PROX_PANIC(ret != 0, "Failed to reset reading pcap file\n");

	plogx_info("Loading %d packets from pcap\n", task->n_pkts);
	task->proto_len = rte_zmalloc_socket(NULL, task->n_pkts*sizeof(*task->proto_len),
					     RTE_CACHE_LINE_SIZE, rte_lcore_to_socket_id(targ->lconf->id));
	task->proto = rte_zmalloc_socket(NULL, task->n_pkts * sizeof(gen_proto),
					 RTE_CACHE_LINE_SIZE, rte_lcore_to_socket_id(targ->lconf->id));
	PROX_PANIC(task->proto == NULL, "Failed to allocate memory (in huge pages) for pcap file (%lu bytes needed)\n", task->n_pkts * sizeof(gen_proto));
	for (uint32_t i=0; i < task->n_pkts; ++i) {
		buf = pcap_next(handle, &header);
		PROX_PANIC(buf == NULL, "Failed to read packet %d from pcap %s\n", i, targ->pcap_file);
		task->proto_len[i] = header.len;
		rte_memcpy(task->proto[i].buf, buf, RTE_MIN(header.len, sizeof(task->proto[i].buf)));
		if ((targ->flags & DSF_KEEP_SRC_MAC) == 0)
			rte_memcpy(&task->proto[i].buf[6], prox_port_cfg[tbase->tx_params_hw.tx_port_queue->port].eth_addr.addr_bytes, 6);
	}
	pcap_close(handle);

	task->pkt_idx = 0;
}

static struct task_init task_init_gen = {
	.mode_str = "gen",
	.init = init_task_gen,
	.handle = handle_gen_bulk,
	.flag_features = TASK_NEVER_DROPS | TASK_NO_RX,
	.size = sizeof(struct task_gen)
};

__attribute__((constructor)) static void reg_task_gen(void)
{
	reg_task(&task_init_gen);
}
