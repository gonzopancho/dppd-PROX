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

#ifndef _HANDLE_LAT_H_
#define _HANDLE_LAT_H_

#include "task_base.h"
#define MAX_PACKETS_FOR_LATENCY 64
#define LATENCY_ACCURACY	1
#define DEFAULT_BUCKET_SIZE	10

struct lat_test {
	uint64_t max_lat;
	uint64_t min_lat;
	uint64_t tot_lat;
	uint64_t var_lat; /* variance*/
	uint64_t tot_pkts;
	uint64_t buckets[128];
#ifndef NO_LATENCY_PER_PACKET
	uint32_t cur_pkt;
	uint64_t lat[MAX_PACKETS_FOR_LATENCY];
#endif
};

struct task_lat {
	struct task_base base;
	uint16_t lat_pos;
	uint32_t bucket_size;
	volatile uint16_t use_lt; /* which lt to use, */
	volatile uint16_t using_lt; /* 0 or 1 depending on which of the 2 result records are used */
	struct lat_test lt[2];
};

#endif /* _HANDLE_LAT_H_ */
