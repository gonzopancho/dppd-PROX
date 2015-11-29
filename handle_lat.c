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
#include <math.h>

#include "handle_lat.h"
#include "log.h"
#include "task_init.h"
#include "task_base.h"
#include "stats.h"

static void handle_lat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lat *task = (struct task_lat *)tbase;
	struct lat_test *lat_test;
	uint64_t now = rte_rdtsc();

	if (task->use_lt != task->using_lt)
		task->using_lt = task->use_lt;

	lat_test = &task->lt[task->using_lt];


	uint32_t tsc_32bit;
	uint64_t bytes_since_last_pkt = 0;
	uint64_t cur_lat = 0;
	for (uint16_t j = 0; j < n_pkts; ++j) {
		struct rte_mbuf *cur = mbufs[n_pkts - 1 - j];
		uint32_t pkt_time = *(uint32_t *)(rte_pktmbuf_mtod(cur, uint8_t *) +
						  task->lat_pos);
		tsc_32bit = (now - rte_get_tsc_hz()*bytes_since_last_pkt/1250000000) >> LATENCY_ACCURACY;

		if (tsc_32bit < pkt_time) {
			cur_lat = ((uint32_t)-1) - (pkt_time - tsc_32bit - 1);
		}
		else
			cur_lat = tsc_32bit - pkt_time;

		lat_test->tot_lat += cur_lat;
#ifndef NO_LATENCY_PER_PACKET
		lat_test->lat[lat_test->cur_pkt++] = cur_lat;
		if (lat_test->cur_pkt == MAX_PACKETS_FOR_LATENCY)
			lat_test->cur_pkt = 0;
#endif
		lat_test->tot_pkts++;
#ifndef NO_LATENCY_DETAILS
		uint64_t bucket_id = (cur_lat >> task->bucket_size);
		bucket_id = bucket_id < 127? bucket_id : 127;
		lat_test->buckets[bucket_id]++;
#endif
		if (cur_lat > lat_test->max_lat)
			lat_test->max_lat = cur_lat;
		if (cur_lat < lat_test->min_lat)
			lat_test->min_lat = cur_lat;
#ifndef NO_LATENCY_DETAILS
		lat_test->var_lat += cur_lat*cur_lat;
#endif

		if (rte_pktmbuf_pkt_len(cur) < 60)
			rte_pktmbuf_pkt_len(cur) = 60;
		bytes_since_last_pkt += rte_pktmbuf_pkt_len(cur) + 4 + 20;
	}

	for (uint16_t j = 0; j < n_pkts; ++j) {
		rte_pktmbuf_free(mbufs[j]);
	}
	TASK_STATS_ADD_DROP(&tbase->aux->stats, n_pkts);
}

static void init_task_lat(struct task_base *tbase, __attribute__((unused)) struct task_args *targ)
{
	tbase->flags |= FLAG_NEVER_FLUSH;
	struct task_lat *task = (struct task_lat *)tbase;
	task->lat_pos = targ->lat_pos;
	if (targ->bucket_size < LATENCY_ACCURACY) {
		// Latency data is already shifted by LATENCY_ACCURACY
		task->bucket_size = DEFAULT_BUCKET_SIZE - LATENCY_ACCURACY; // each bucket will hold 1024 cycles by default
	} else {
		task->bucket_size = targ->bucket_size - LATENCY_ACCURACY;
	}
}

static struct task_init task_init_lat = {
	.mode_str = "lat",
	.init = init_task_lat,
	.handle = handle_lat_bulk,
	.flag_features = TASK_NO_TX,
	.size = sizeof(struct task_lat)
};

__attribute__((constructor)) static void reg_task_lat(void)
{
	reg_task(&task_init_lat);
}
