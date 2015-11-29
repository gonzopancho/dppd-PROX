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

#ifndef _DISPLAY_H_
#define _DISPLAY_H_

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

void display_init(unsigned avg_start, unsigned duration);
void display_end(void);
void display_stats(void);
void display_refresh(void);
void display_print(const char *str);
void display_cmd(const char *cmd, int cmd_len, int cursor_pos);
void display_screen(int screen_id);
void display_page_up(void);
void display_page_down(void);

int display_getch(void);

void stats_reset(void);
void stats_init(void);
void stats_update(void);

uint64_t global_total_tx(void);
uint64_t global_total_rx(void);
uint64_t global_pps_tx(void);
uint64_t global_pps_rx(void);
uint64_t global_avg_tx(void);
uint64_t global_avg_rx(void);
uint64_t global_last_tsc(void);

uint64_t tot_ierrors_per_sec(void);
uint64_t tot_ierrors_tot(void);

void display_print_page(void);

uint64_t *buckets_core_lat(uint8_t lcore_id, uint8_t task_id);
#ifndef NO_LATENCY_PER_PACKET
void stats_core_lat(uint8_t lcore_id, uint8_t task_id, unsigned int *npackets, uint64_t *lat);
#endif
uint64_t stats_core_task_lat_min(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_lat_max(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_lat_avg(uint8_t lcore_id, uint8_t task_id);

uint64_t stats_core_task_tot_rx(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_tx(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_drop(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_last_tsc(uint8_t lcore_id, uint8_t task_id);

struct get_port_stats {
	uint64_t no_mbufs_diff;
	uint64_t ierrors_diff;
	uint64_t rx_bytes_diff;
	uint64_t tx_bytes_diff;
	uint64_t rx_pkts_diff;
	uint64_t tx_pkts_diff;
	uint64_t rx_tot;
	uint64_t tx_tot;
	uint64_t no_mbufs_tot;
	uint64_t ierrors_tot;
	uint64_t last_tsc;
	uint64_t prev_tsc;
};

int stats_port(uint8_t port_id, struct get_port_stats *ps);

#endif /* _DISPLAY_H_ */
