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

#ifndef _STATS_H_
#define _STATS_H_

#include <rte_atomic.h>
#include "clock.h"

#ifdef BRAS_STATS

/* A task struct is read/write from the task itself and read-only from
   the core that collects the task. Since only the task executing the
   actual work ever modify the stats, no locking is required. Both a
   read and a write are atomic (assuming the correct alignment). From
   this, it followed that the statistics can be incremented
   directly. In cases where these assumptions do not hold, a possible
   solution (although slightly less accurate) would be to keep data
   that is being written to by the task separately and periodically
   copying the statistics trough atomic primitives, for example
   through rte_atomic32_set() to memory accessed by a statistics
   core. The accuracy would be determined by the frequency in which
   the statistics are exposed to the statistics core. */

struct task_stats {
	uint32_t	rx_pkt_count;
	uint32_t	tx_pkt_count;
	uint32_t	tx_pkt_drop;
	uint32_t	empty_cycles;
} __attribute__((packed)) __rte_cache_aligned;

#define TASK_STATS_ADD_IDLE(stats, cycles) do {				\
		(stats)->empty_cycles += (cycles) + rdtsc_overhead_stats; \
	} while(0)							\

#define TASK_STATS_ADD_TX(stats, ntx) do {	\
		(stats)->tx_pkt_count += ntx;	\
	} while(0)				\

#define TASK_STATS_ADD_DROP(stats, ntx) do {	\
		(stats)->tx_pkt_drop += ntx;	\
	} while(0)				\

#define TASK_STATS_ADD_RX(stats, ntx) do {	\
		(stats)->rx_pkt_count += ntx;	\
	} while (0)				\

#define START_EMPTY_MEASSURE() uint64_t cur_tsc = rte_rdtsc();

struct eth_stats {
	uint64_t tsc[2];
	uint64_t no_mbufs[2];
	uint64_t ierrors[2];
	uint64_t oerrors[2];
	uint64_t rx_tot[2];
	uint64_t tx_tot[2];
	uint64_t rx_bytes[2];
	uint64_t tx_bytes[2];
};

#ifdef PROX_HW_DIRECT_STATS
extern void ixgbe_read_stats(uint8_t port_id, struct eth_stats* stats, int last_stat);
#endif

#else
#define TASK_STATS_ADD_IDLE(stats, cycles) {}
#define TASK_STATS_ADD_TX(stats, ntx) {}
#define TASK_STATS_ADD_DROP(stats, ntx) {}
#define TASK_STATS_ADD_RX(stats, ntx) {}
#endif

#endif /* _STATS_H_ */
