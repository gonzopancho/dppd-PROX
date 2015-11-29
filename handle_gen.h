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

#ifndef _HANDLE_GEN_H_
#define _HANDLE_GEN_H_

#include <rte_ether.h>
#include "task_base.h"

typedef struct _gen_proto {
	uint8_t buf[ETHER_MAX_LEN];
} gen_proto;

struct task_gen {
	struct task_base base;
	struct rte_mempool* mempool;
	uint8_t src_dst_mac[64];
	gen_proto* proto; /* packet templates (from pcap) */
	uint16_t* proto_len; /* length of packet templates */
	uint32_t n_pkts; /* number of packets in pcap */
	uint32_t pkt_idx; /* current packet from pcap */
	uint8_t n_rands; /* number of randoms */
	uint8_t n_values; /* number of fixed values */
	uint32_t seeds[64];
	uint32_t rand_offset[64]; /* each random has an offset*/
	uint32_t rand_mask[64]; /* since the random vals are uniform, masks don't introduce bias  */
	uint32_t rand_len[64]; /* # bytes to take from random (no bias introduced) */
	uint32_t fixed_bits[64]; /* length of each random (max len = 4) */
	uint16_t offset[64]; /* offset of bytes with fixed value */
	uint32_t value[64]; /* value of fixed byte */
	uint16_t value_len[64]; /* length of fixed byte */
	uint64_t start_tsc;
	uint64_t sent_bytes;
	uint64_t bytes_start_tsc;
	uint64_t bytes_now;
	uint64_t new_rate_bps;
	uint64_t rate_bps;
	uint16_t lat_pos;
	uint32_t lat_enabled;
	uint32_t pkt_size;
	struct rte_mbuf *new_pkts[64];
	uint64_t pkt_tsc_offsets[64];
	uint32_t* pkt_tsc_pointer[64];
	uint32_t pkt_count; /* how many pakets to generate */
};

#endif /* _HANDLE_GEN_H_ */
