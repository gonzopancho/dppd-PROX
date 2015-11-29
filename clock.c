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

#include "clock.h"

#include <stdio.h>

#include <rte_cycles.h>

/* Calibrate TSC overhead by reading NB_READ times and take the smallest value.
   Bigger values are caused by external influence and can be discarded. The best
   estimate is the smallest read value. */
#define NB_READ 10000

uint32_t rdtsc_overhead;
uint32_t rdtsc_overhead_stats;

/* calculate how much overhead is involved with calling rdtsc. This value has
   to be taken into account where the time spent running a small piece of code
   is measured */
void prox_init_tsc_overhead(void)
{
	volatile uint32_t min_without_overhead = 0xffffffff;
	volatile uint32_t min_with_overhead = 0xffffffff;
	volatile uint32_t min_stats_overhead = 0xffffffff;
	volatile uint64_t start1, end1;
	volatile uint64_t start2, end2;

	for (uint32_t i = 0; i < NB_READ; ++i) {
		start1 = rte_rdtsc();
		end1   = rte_rdtsc();

		start2 = rte_rdtsc();
		end2   = rte_rdtsc();
		end2   = rte_rdtsc();

		if (min_without_overhead > end1 - start1) {
			min_without_overhead = end1 - start1;
		}

		if (min_with_overhead > end2 - start2) {
			min_with_overhead = end2 - start2;
		}
	}

	rdtsc_overhead = min_with_overhead - min_without_overhead;


	start1 = rte_rdtsc();
	end1   = rte_rdtsc();
	/* forbid the compiler to optimize this dummy variable */
	volatile int dummy = 0;
	for (uint32_t i = 0; i < NB_READ; ++i) {
		start1 = rte_rdtsc();
		dummy += 32;
		end1   = rte_rdtsc();

		if (min_stats_overhead > end2 - start2) {
			min_stats_overhead = end1 - start1;
		}
	}

	rdtsc_overhead_stats = rdtsc_overhead + min_stats_overhead - min_without_overhead;
}
