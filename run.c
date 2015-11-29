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

#include <inttypes.h>
#include <string.h>

#include <rte_launch.h>
#include <rte_cycles.h>

#include "run.h"
#include "prox_cfg.h"
#include "prox_port_cfg.h"
#include "quit.h"
#include "commands.h"
#include "main.h"
#include "log.h"
#include "display.h"

#include "input.h"
#include "input_curses.h"
#include "input_conn.h"

static int needs_refresh;
static int update_interval = 1000;
static int stop_prox = 0; /* set to 1 to stop prox */

void set_update_interval(uint32_t msec)
{
	update_interval = msec;
}

void req_refresh(void)
{
	needs_refresh = 1;
}

void quit(void)
{
	plog_info("Leaving...\n");
	stop_core_all(-1);
	stop_prox = 1;
}

static void update_link_states(void)
{
	struct prox_port_cfg *port_cfg;
	struct rte_eth_link link;

	for (uint8_t portid = 0; portid < PROX_MAX_PORTS; ++portid) {
		if (!prox_port_cfg[portid].active) {
			continue;
		}

		port_cfg  = &prox_port_cfg[portid];
		rte_eth_link_get_nowait(portid, &link);
		port_cfg->link_up = link.link_status;
		port_cfg->link_speed = link.link_speed;
	}
}

/* start main loop */
void __attribute__((noreturn)) run(uint32_t flags)
{
	if (flags & DSF_LISTEN_TCP)
		PROX_PANIC(reg_input_tcp(), "Failed to start listening on TCP port 8474: %s\n", strerror(errno));
	if (flags & DSF_LISTEN_UDS)
		PROX_PANIC(reg_input_uds(), "Failed to start listening on UDS /tmp/prox.sock: %s\n", strerror(errno));

	reg_input_curses();

	stats_init();
	display_init(prox_cfg.start_time, prox_cfg.duration_time);

	cmd_rx_tx_info();

	if (get_n_warnings() == -1) {
		plog_info("Warnings disabled\n");
	}
	else if (get_n_warnings() > 0) {
		int n_print = get_n_warnings() < 5? get_n_warnings(): 5;
		plog_info("Started with %d warnings, last %d warnings: \n", get_n_warnings(), n_print);
		for (int i = -n_print + 1; i <= 0; ++i) {
			plog_info("%s", get_warning(i));
		}
	}
	else {
		plog_info("Started without warnings\n");
	}

	/* start all tasks on worker cores */
	if (flags & DSF_AUTOSTART)
		start_core_all(-1);
	else
		stop_core_all(-1);
	display_refresh();

#ifndef BRAS_STATS
	while(1) {sleep(1000000);}
#endif

	uint64_t cur_tsc = rte_rdtsc();
	uint64_t next_update = cur_tsc + rte_get_tsc_hz();
	uint64_t stop_tsc = 0;
	int32_t lsc_local;

	if (prox_cfg.duration_time != 0) {
		stop_tsc = cur_tsc + prox_cfg.start_time*rte_get_tsc_hz() + prox_cfg.duration_time*rte_get_tsc_hz();
	}

	/* Multiplex input handling with statistics gathering/display. */
	while (stop_prox == 0) {
		input_proc_until(next_update);

		next_update += rte_get_tsc_hz() * update_interval / 1000;

		if (needs_refresh) {
			needs_refresh = 0;
			display_refresh();
		}

		lsc_local = rte_atomic32_read(&lsc);

		if (lsc_local) {
			rte_atomic32_dec(&lsc);
			update_link_states();
			display_refresh();
		}

		stats_update();

		display_stats();

		if (stop_tsc && cur_tsc >= stop_tsc) {
			stop_prox = 1;
		}
	}

	plog_info("total RX: %"PRIu64", total TX: %"PRIu64", average RX: %"PRIu64" pps, average TX: %"PRIu64" pps\n",
		  global_total_rx(),
		  global_total_tx(),
		  global_avg_rx(),
		  global_avg_tx());

	if (prox_cfg.flags & DSF_WAIT_ON_QUIT) {
		stop_core_all(-1);
	}

	display_end();
	exit(EXIT_SUCCESS);
}
