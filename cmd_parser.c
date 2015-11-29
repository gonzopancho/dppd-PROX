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

#include <stdio.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "cmd_parser.h"
#include "commands.h"
#include "run.h"
#include "display.h"
#include "log.h"
#include "prox_cfg.h"
#include "prox_port_cfg.h"
#include "prox_args.h"
#include "task_base.h"
#include "main.h"
#include "parse_utils.h"

#include "handle_routing.h"
#include "handle_qinq_decap4.h"
#include "handle_lat.h"
#include "handle_gen.h"
#include "handle_acl.h"
#include "defines.h"
#include "prox_cfg.h"
#include "version.h"

static int core_task_is_valid(int lcore_id, int task_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		plog_err("Invalid core id %u (lcore ID above %d)\n", lcore_id, RTE_MAX_LCORE);
		return 0;
	}
	else if (!prox_core_active(lcore_id, 0)) {
		plog_err("Invalid core id %u (lcore is not active)\n", lcore_id);
		return 0;
	}
	else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
		plog_err("Invalid task id (valid task IDs for core %u are below %u)\n",
			 lcore_id, lcore_cfg[lcore_id].n_tasks_all);
		return 0;
	}
	return 1;
}

static int parse_cmd_quit(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	quit();
	return 0;
}

static int parse_cmd_reset_stats(const char *str, __attribute__((unused)) int fd,
				 __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	stats_reset();
	return 0;
}

static int parse_cmd_trace(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, nb_packets;

	if (sscanf(str, "%u %u %u", &lcore_id, &task_id, &nb_packets) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id))
		cmd_trace(lcore_id, task_id, nb_packets);
	return 0;
}

static int parse_cmd_dump_rx(const char *str, __attribute__((unused)) int fd,
			     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, nb_packets;

	if (sscanf(str, "%u %u %u", &lcore_id, &task_id, &nb_packets) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id))
		cmd_dump(lcore_id, task_id, nb_packets, fd, cb, 1, 0);
	return 0;
}

static int parse_cmd_dump_tx(const char *str, __attribute__((unused)) int fd,
			     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, nb_packets;

	if (sscanf(str, "%u %u %u", &lcore_id, &task_id, &nb_packets) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id))
		cmd_dump(lcore_id, task_id, nb_packets, fd, cb, 0, 1);
	return 0;
}


static int parse_cmd_rate(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned queue, port, rate;

	if (sscanf(str, "%u %u %u", &queue, &port, &rate) != 3) {
		return -1;
	}

	if (port > PROX_MAX_PORTS) {
		plog_err("Max port id allowed is %u (specified %u)\n", PROX_MAX_PORTS, port);
	}
	else if (!prox_port_cfg[port].active) {
		plog_err("Port %u not active\n", port);
	}
	else if (queue >= prox_port_cfg[port].n_txq) {
		plog_err("Number of active queues is %u\n",
			 prox_port_cfg[port].n_txq);
	}
	else if (rate > prox_port_cfg[port].link_speed) {
		plog_err("Max rate allowed on port %u queue %u is %u Mbps\n",
			 port, queue, prox_port_cfg[port].link_speed);
	}
	else {
		if (rate == 0) {
			plog_info("Disabling rate limiting on port %u queue %u\n",
				  port, queue);
		}
		else {
			plog_info("Setting rate limiting to %u Mbps on port %u queue %u\n",
				  rate, port, queue);
		}
		rte_eth_set_queue_rate_limit(port, queue, rate);
	}
	return 0;
}

static int parse_cmd_count(const char *str, __attribute__((unused)) int fd,
			   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, count;

	if (sscanf(str, "%u %u %u", &lcore_id, &task_id, &count) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
			plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
		}
		else {
			((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id])->pkt_count = count;
			if (count == (unsigned)-1)
				plog_info("Core %u task %u will keep sending packets\n", lcore_id, task_id);
			else if (count == 0)
				plog_info("Core %u task %u waits for next count command\n", lcore_id, task_id);
			else
				plog_info("Core %u task %u stopping after %u packets\n", lcore_id, task_id, count);
		}
	}
	return 0;
}

static int parse_cmd_pkt_size(const char *str, __attribute__((unused)) int fd,
			      __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, pkt_size;

	if (sscanf(str, "%u %u %d", &lcore_id, &task_id, &pkt_size) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
			plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
		}
		else if (pkt_size > 1514 || pkt_size < 34) {    // 34 for 14 + 20 (MAC, EtherType and IP)
			plog_err("pkt_size out of range (must be betweeen 34 and 1514)\n");
		}
		else {
			((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id])->pkt_size = pkt_size;
			plog_info("Setting pkt_size to %u \n", pkt_size);
		}
	}
	return 0;
}

static int parse_cmd_speed(const char *str, __attribute__((unused)) int fd,
			   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;
	float speed;

	if (sscanf(str, "%u %u %f", &lcore_id, &task_id, &speed) != 3) {
		return -1;
	}

	if (!core_task_is_valid(lcore_id, task_id)) {
		return 0;
	}

	if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
		plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
	}
	else if (speed > 100.0f || speed < 0.0f) {
		plog_err("Speed out of range (must be betweeen 0%% and 100%%)\n");
	}
	else {
		uint64_t bps = speed * 12500000;

		((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id])->new_rate_bps = bps;
		plog_info("Setting rate to %"PRIu64" Bps\n", bps);
	}
	return 0;
}

static int parse_cmd_speed_byte(const char *str, __attribute__((unused)) int fd,
				__attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, value;
	if (sscanf(str, "%u %u %u", &lcore_id, &task_id, &value) != 3) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
			plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
		}
		else if (value > 1250000000) {
			plog_err("Speed out of range (must be <= 1250000000)\n");
		}
		else {
			((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id])->rate_bps = value;
			plog_info("Setting rate to %"PRIu32" Bps\n", value);
		}
	}
	return 0;
}

static int parse_cmd_reset_values_all(const char *str, __attribute__((unused)) int fd,
				      __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	unsigned task_id, lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0) {
		for (task_id = 0; task_id < lcore_cfg[lcore_id].n_tasks_all; task_id++) {
			if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen") == 0) {
				struct task_gen *task = ((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id]);
				plog_info("Resetting values on core %d task %d from %d values\n", lcore_id, task_id, task->n_values);
				task->n_values = 0;
			}
		}
	}
	return 0;
}

static int parse_cmd_reset_values(const char *str, __attribute__((unused)) int fd,
				  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
			plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
		}
		else {
			struct task_gen *task = ((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id]);
			plog_info("Resetting values on core %d task %d from %d values\n", lcore_id, task_id, task->n_values);
			task->n_values = 0;
		}
	}
	return 0;
}

static int parse_cmd_set_value(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, value;
	unsigned short offset;
	uint8_t value_len;

	if (sscanf(str, "%u %u %hu %u %hhu", &lcore_id, &task_id, &offset, &value, &value_len) != 5) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "gen")) {
			plog_err("Core %u task %u is not generating packets\n", lcore_id, task_id);
		}
		else if (offset > ETHER_MAX_LEN) {
			plog_err("Offset out of range (must be less then %u)\n", ETHER_MAX_LEN);
		}
		else if (value_len > 4) {
			plog_err("Length out of range (must be less then 4)\n");
		}
		else {
			struct task_gen *task = ((struct task_gen *)lcore_cfg[lcore_id].tasks_all[task_id]);
			if (task->n_values >= 64) {
				plog_info("Unable to set Byte %"PRIu16" to %"PRIu8" - too many value set\n", offset, value);
			}
			else {
				task->value[task->n_values] = rte_cpu_to_be_32(value) >> ((4 - value_len) * 8);
				task->offset[task->n_values] = offset;
				task->value_len[task->n_values] = value_len;
				task->n_values++;
				plog_info("Setting Byte %"PRIu16" to %"PRIu32"\n", offset, value);
			}
		}
	}
	return 0;
}

static int parse_cmd_thread_info(const char *str, __attribute__((unused)) int fd,
				 __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}
	cmd_thread_info(lcore_id, task_id);
	return 0;
}

static int parse_cmd_verbose(const char *str, __attribute__((unused)) int fd,
			     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned id;

	if (sscanf(str, "%u", &id) != 1) {
		return -1;
	}

	if (plog_set_lvl(id) != 0) {
		plog_err("Cannot set log level to %u\n", id);
	}
	return 0;
}

static int parse_cmd_arp_add(const char *str, __attribute__((unused)) int fd,
			     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	struct arp_msg amsg;
	struct arp_msg *pmsg = &amsg;
	unsigned lcore_id, task_id;
	struct rte_ring *ring;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}
	if (str_to_arp_msg(&amsg, str) == 0) {
		ring = ctrl_rings[lcore_id*MAX_TASKS_PER_CORE + task_id];
		if (lcore_id >= RTE_MAX_LCORE || !lcore_cfg[lcore_id].n_tasks_all) {
			plog_err("Failed to add route because core %u not active\n", lcore_id);
		}
		else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
			plog_err("Task %u is not active on core %u\n", task_id, lcore_id);
		}
		else if (!ring) {
			plog_err("No ring for control messages to core %u task %u\n", lcore_id, task_id);
		}
		else {
			while (rte_ring_sp_enqueue_bulk(ring, (void *const *)&pmsg, 1));
			while (!rte_ring_empty(ring));
		}
		return 0;
	}
	return -1;
}

static int parse_cmd_rule_add(const char *str, __attribute__((unused)) int fd,
			      __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	struct rte_ring *ring;
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}
	char *fields[9];
	char str_cpy[255];
	strncpy(str_cpy, str, 255);
	// example add rule command: rule add 15 0 1&0x0fff 1&0x0fff 0&0 128.0.0.0/1 128.0.0.0/1 5000-5000 5000-5000 allow
	int ret = rte_strsplit(str_cpy, 255, fields, 9, ' ');
	if (ret != 8) {
		return -1;
	}

	struct acl4_rule rule;
	struct acl4_rule *prule = &rule;
	if (str_to_rule(&rule, fields, -1, 1) == 0) {
		ring = ctrl_rings[lcore_id*MAX_TASKS_PER_CORE + task_id];
		if (lcore_id >= RTE_MAX_LCORE || !lcore_cfg[lcore_id].n_tasks_all) {
			plog_err("Adding rule failed: Core %u not active\n", lcore_id);
		}
		else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
			plog_err("Adding rule failed: Task %u is not active on core %u\n", task_id, lcore_id);
		}
		else if (!ring) {
			plog_err("No ring for control messages to core %u task %u\n", lcore_id, task_id);
		}
		else {
			while (rte_ring_sp_enqueue_bulk(ring, (void *const *)&prule, 1));
			while (!rte_ring_empty(ring));
		}
		return 0;
	}
	return -1;
}

static int parse_cmd_route_add(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id, prefix, next_hop_idx, ip[4];

	if (sscanf(str, "%u %u %u.%u.%u.%u/%u %u", &lcore_id, &task_id, ip, ip + 1, ip + 2, ip + 3,
		   &prefix, &next_hop_idx) != 8) {
		return -1;
	}
	struct rte_ring *ring;

	ring = ctrl_rings[lcore_id*MAX_TASKS_PER_CORE + task_id];
	if (lcore_id >= RTE_MAX_LCORE || !lcore_cfg[lcore_id].n_tasks_all) {
		plog_err("Adding route failed: Core %u not active\n", lcore_id);
	}
	else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
		plog_err("Adding route failed: Task %u is not active on core %u\n", task_id, lcore_id);
	}
	else if (!ring) {
		plog_err("No ring for control messages to core %u task %u\n", lcore_id, task_id);
	}
	else {
		struct route_msg rmsg;
		struct route_msg *pmsg = &rmsg;

		rmsg.ip_bytes[0] = ip[0];
		rmsg.ip_bytes[1] = ip[1];
		rmsg.ip_bytes[2] = ip[2];
		rmsg.ip_bytes[3] = ip[3];
		rmsg.prefix = prefix;
		rmsg.nh = next_hop_idx;
		while (rte_ring_sp_enqueue_bulk(ring, (void *const *)&pmsg, 1));
		while (!rte_ring_empty(ring));
	}
	return 0;
}

static int parse_cmd_start(const char *str, __attribute__((unused)) int fd,
			   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	int task_id = -1;

	if (strncmp(str, "all", 3) == 0) {
		str += 3;
		sscanf(str, "%d", &task_id);

		start_core_all(task_id);
		req_refresh();
		return 0;
	}

	uint32_t cores[32] = {0};
	int ret;
	ret = parse_list_set(cores, str, 32);
	if (ret < 0) {
		return -1;
	}
	str = strchr(str, ' ');

	if (str) {
		sscanf(str, "%d", &task_id);
	}
	start_cores(cores, ret, task_id);
	req_refresh();
	return 0;
}

static int parse_cmd_stop(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	int task_id = -1;

	if (strncmp(str, "all", 3) == 0) {
		str += 3;
		sscanf(str, "%d", &task_id);
		stop_core_all(task_id);
		req_refresh();
		return 0;
	}

	uint32_t cores[32] = {0};
	int ret;
	ret = parse_list_set(cores, str, 32);
	if (ret < 0) {
		return -1;
	}
	str = strchr(str, ' ');

	if (str) {
		sscanf(str, "%d", &task_id);
	}
	stop_cores(cores, ret, task_id);
	req_refresh();

	return 0;
}

static int parse_cmd_rx_distr_start(const char *str, __attribute__((unused)) int fd,
				    __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id[1];

	int ret;

	ret = parse_list_set(lcore_id, str, sizeof(lcore_id)/sizeof(lcore_id[0]));

	if (ret == 0) {
		return -1;
	}

	for (size_t i = 0; i < sizeof(lcore_id)/sizeof(lcore_id[0]); ++i)
		cmd_rx_distr_start(lcore_id[i]);
	return 0;
}

static int parse_cmd_rx_distr_stop(const char *str, __attribute__((unused)) int fd,
				   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id[1];

	int ret;

	ret = parse_list_set(lcore_id, str, sizeof(lcore_id)/sizeof(lcore_id[0]));

	if (ret == 0) {
		return -1;
	}

	for (size_t i = 0; i < sizeof(lcore_id)/sizeof(lcore_id[0]); ++i)
		cmd_rx_distr_stop(lcore_id[i]);
	return 0;
}

static int parse_cmd_rx_distr_reset(const char *str, __attribute__((unused)) int fd,
				    __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id[1];

	int ret;

	ret = parse_list_set(lcore_id, str, sizeof(lcore_id)/sizeof(lcore_id[0]));

	if (ret == 0) {
		return -1;
	}

	for (size_t i = 0; i < sizeof(lcore_id)/sizeof(lcore_id[0]); ++i)
		cmd_rx_distr_rst(lcore_id[i]);
	return 0;
}

static int parse_cmd_rx_distr_show(const char *str, __attribute__((unused)) int fd,
				   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id[1];

	int ret;

	ret = parse_list_set(lcore_id, str, sizeof(lcore_id)/sizeof(lcore_id[0]));

	if (ret == 0) {
		return -1;
	}

	for (size_t i = 0; i < sizeof(lcore_id)/sizeof(lcore_id[0]); ++i)
		cmd_rx_distr_show(lcore_id[i]);
	return 0;
}

static int parse_cmd_tot_stats(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp("", str) != 0) {
		return -1;
	}

	uint64_t tot_rx = global_total_rx();
	uint64_t tot_tx = global_total_tx();
	uint64_t last_tsc = global_last_tsc();
	if (fd != -1) {
		char buf[128];
		snprintf(buf, sizeof(buf), "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",
			 tot_rx, tot_tx, last_tsc, rte_get_tsc_hz());
		cb(fd, buf, strlen(buf));
	}
	else {
		plog_info("RX: %"PRIu64", TX: %"PRIu64"\n", tot_rx, tot_tx);
	}
	return 0;
}

static int parse_cmd_update_interval(const char *str, __attribute__((unused)) int fd,
				     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned val;

	if (sscanf(str, "%u", &val) != 1) {
		return -1;
	}

	if (val < 10) {
		plog_err("Minimum update interval is 10 ms\n");
	}
	else {
		plog_info("Setting update interval to %d ms\n", val);
		set_update_interval(val);
	}
	return 0;
}

static int parse_cmd_mem_info(const char *str, __attribute__((unused)) int fd,
			      __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp("", str) != 0) {
		return -1;
	}

	plog_info("Memory layout:\n");
	cmd_mem_layout();
	return 0;
}

static int parse_cmd_tot_ierrors_per_sec(const char *str, __attribute__((unused)) int fd,
					 __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	uint64_t tot = tot_ierrors_per_sec();
	uint64_t last_tsc = global_last_tsc();

	if (fd != -1) {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "%"PRIu64",%"PRIu64",%"PRIu64"\n",
			 tot, last_tsc, rte_get_tsc_hz());
		cb(fd, buf, strlen(buf));
	}
	else {
		plog_info("ierrors: %"PRIu64"\n", tot);
	}
	return 0;
}

static int parse_cmd_tot_ierrors_tot(const char *str, __attribute__((unused)) int fd,
				     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}
	uint64_t tot = tot_ierrors_tot();
	uint64_t last_tsc = global_last_tsc();

	if (fd != -1) {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "%"PRIu64",%"PRIu64",%"PRIu64"\n",
			 tot, last_tsc, rte_get_tsc_hz());
		cb(fd, buf, strlen(buf));
	}
	else {
		plog_info("ierrors: %"PRIu64"\n", tot);
	}
	return 0;
}

static int parse_cmd_ring_info_all(const char *str, __attribute__((unused)) int fd,
				   __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}
	cmd_ringinfo_all();
	return 0;
}

static int parse_cmd_port_up(const char *str, __attribute__((unused)) int fd,
			     __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned val;

	if (sscanf(str, "%u", &val) != 1) {
		return -1;
	}

	cmd_port_up(val);
	return 0;
}

static int parse_cmd_port_down(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned val;

	if (sscanf(str, "%u", &val) != 1) {
		return -1;
	}

	cmd_port_down(val);
	return 0;
}

static int parse_cmd_xstats(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned val;

	if (sscanf(str, "%u", &val) != 1) {
		return -1;
	}

	cmd_xstats(val);
	return 0;
}

static int parse_cmd_port_info(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	int val;

	if (strcmp(str, "all") == 0) {
		val = -1;
	}
	else if (sscanf(str, "%d", &val) != 1) {
		return -1;
	}

	if (fd != -1 && val != -1) {
		struct prox_port_cfg* port_cfg = &prox_port_cfg[val];
		/* TODO: check if port ID is valid */
		char buf[128];
		snprintf(buf, sizeof(buf),
			 ""MAC_BYTES_FMT",%d\n", MAC_BYTES(port_cfg->eth_addr.addr_bytes), port_cfg->socket);
		cb(fd, buf, strlen(buf));
	}
	else {
		cmd_portinfo(val);
	}
	return 0;
}

static int parse_cmd_ring_info(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}

	cmd_ringinfo(lcore_id, task_id);
	return 0;
}

static int parse_cmd_port_stats(const char *str, __attribute__((unused)) int fd,
				__attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned val;

	if (sscanf(str, "%u", &val) != 1) {
		return -1;
	}

	struct get_port_stats s;
	if (stats_port(val, &s)) {
		plog_err("Invalid port %u\n", val);
		return 0;
	}
	char buf[256];
	snprintf(buf, sizeof(buf),
		 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64","
		 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64","
		 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",
		 s.no_mbufs_diff, s.ierrors_diff,
		 s.rx_bytes_diff, s.tx_bytes_diff,
		 s.rx_pkts_diff, s.tx_pkts_diff,
		 s.rx_tot, s.tx_tot,
		 s.no_mbufs_tot, s.ierrors_tot,
		 s.last_tsc, s.prev_tsc);
	plog_info("%s", buf);
	if (fd != -1) {
		cb(fd, buf, strlen(buf));
	}
	return 0;
}

static int parse_cmd_core_stats(const char *str, __attribute__((unused)) int fd,
				__attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		uint64_t tot_rx = stats_core_task_tot_rx(lcore_id, task_id);
		uint64_t tot_tx = stats_core_task_tot_tx(lcore_id, task_id);
		uint64_t tot_drop = stats_core_task_tot_drop(lcore_id, task_id);
		uint64_t last_tsc = stats_core_task_last_tsc(lcore_id, task_id);

		if (fd != -1) {
			char buf[128];
			snprintf(buf, sizeof(buf),
				 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",
				 tot_rx, tot_tx, tot_drop, last_tsc, rte_get_tsc_hz());
			cb(fd, buf, strlen(buf));
		}
		else {
			plog_info("RX: %"PRIu64", TX: %"PRIu64", DROP: %"PRIu64"\n",
				  tot_rx, tot_tx, tot_drop);
		}
	}
	return 0;
}

static int parse_cmd_lat_stats(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "lat")) {
			plog_err("Core %u task %u is not measuring latency\n", lcore_id, task_id);
		}
		else {
			uint64_t lat_min, lat_max, lat_avg, last_tsc;

			lat_min = stats_core_task_lat_min(lcore_id, task_id);
			lat_max = stats_core_task_lat_max(lcore_id, task_id);
			lat_avg = stats_core_task_lat_avg(lcore_id, task_id);
			last_tsc = stats_core_task_last_tsc(lcore_id, task_id);

			if (fd != -1) {
				char buf[128];
				snprintf(buf, sizeof(buf),
					 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",
					 lat_min, lat_max, lat_avg, last_tsc, rte_get_tsc_hz());
				cb(fd, buf, strlen(buf));
			}
			else {
				plog_info("min: %"PRIu64", max: %"PRIu64", avg: %"PRIu64"\n",
					  lat_min, lat_max, lat_avg);
			}
		}
	}
	return 0;
}

static int parse_cmd_lat_packets(const char *str, __attribute__((unused)) int fd,
				 __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	unsigned lcore_id, task_id;

	if (sscanf(str, "%u %u", &lcore_id, &task_id) != 2) {
		return -1;
	}

	if (core_task_is_valid(lcore_id, task_id)) {
		if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "lat")) {
			plog_err("Core %u task %u is not measuring latency\n", lcore_id, task_id);
		}
		else {
			unsigned int i;
#ifndef NO_LATENCY_PER_PACKET
			unsigned int npackets;
			uint64_t lat[MAX_PACKETS_FOR_LATENCY];

			stats_core_lat(lcore_id, task_id, &npackets, lat);

			if (fd != -1) {
				char buf[4096] = {0};
				for (i=0;i<npackets;i++)
					sprintf(buf+strlen(buf), "[%d]: %"PRIu64"\n", i, lat[i]);
				cb(fd, buf, strlen(buf));
			}
			else {
				for (i=0;i<npackets;i++)
					plog_info("[%d]: %"PRIu64"\n", i, lat[i]);
			}
#else
			plog_info("NO_LATENCY_PER_PACKET enabled\n");
#endif
#ifndef NO_LATENCY_DETAILS
			uint64_t *buckets = buckets_core_lat(lcore_id, task_id);
			if (buckets == NULL)
				return 0;

			if (fd != -1) {
				char buf[4096] = {0};
				for (i=0;i<128;i++)
					sprintf(buf+strlen(buf), "Bucket [%d]: %"PRIu64"\n", i, buckets[i]);
				cb(fd, buf, strlen(buf));
			}
			else {
				for (i=0;i<128;i++)
					if (buckets[i])
						plog_info("Bucket [%d]: %"PRIu64"\n", i, buckets[i]);
			}
#else
			plog_info("NO_LATENCY_DETAILS enabled\n");
#endif
		}
	}
	return 0;
}

static int parse_cmd_pps_stats(const char *str, __attribute__((unused)) int fd,
			       __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	uint64_t tot_rx = global_pps_rx();
	uint64_t tot_tx = global_pps_tx();
	uint64_t last_tsc = global_last_tsc();
	if (fd != -1) {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",
			 tot_rx, tot_tx, last_tsc, rte_get_tsc_hz());
		cb(fd, buf, strlen(buf));
	}
	else {
		plog_info("RX: %"PRIu64", TX: %"PRIu64"\n", tot_rx, tot_tx);
	}
	return 0;
}

static int parse_cmd_rx_tx_info(const char *str, __attribute__((unused)) int fd,
				__attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	cmd_rx_tx_info();
	return 0;
}

static int parse_cmd_version(const char *str, int fd, void (*cb)(int fd, const char *data, size_t len))
{
	if (strcmp(str, "") != 0) {
		return -1;
	}

	if (fd != -1) {
		uint64_t version =
			((uint64_t)VERSION_MAJOR) << 32 |
			((uint64_t)VERSION_MINOR) << 16 |
			((uint64_t)VERSION_REV) << 8;

		char buf[128];
		snprintf(buf, sizeof(buf), "%"PRIu64",%"PRIu64"\n", version, (uint64_t)RTE_VERSION);
		cb(fd, buf, strlen(buf));
	}
	else {
		plog_info("prox version: %d.%d, DPDK version: %d.%d.%d\n",
			  VERSION_MAJOR, VERSION_MINOR,
			  RTE_VER_MAJOR, RTE_VER_MINOR, RTE_VER_PATCH_LEVEL);
	}
	return 0;
}

struct cmd_str {
	const char *cmd;
	const char *args;
	const char *help;
	int (*parse)(const char *args, int fd, void (*cb)(int fd, const char *data, size_t len));
};

static int parse_cmd_help(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len));

static struct cmd_str cmd_strings[] = {
	{"quit", "", "Stop all cores and quit", parse_cmd_quit},
	{"help", "<substr>", "Show list of commands that have <substr> as a substring. If no substring is provided, all commands are shown.", parse_cmd_help},
	{"verbose", "<level>", "Set verbosity level", parse_cmd_verbose},
	{"thread info", "<core_id> <task_id>", "", parse_cmd_thread_info},
	{"mem info", "", "Show information about system memory (number of huge pages and addresses of these huge pages)", parse_cmd_mem_info},
	{"update interval", "<value>", "Update statistics refresh rate, in msec (must be >=10). Default is 1 second", parse_cmd_update_interval},
	{"rx tx info", "", "Print connections between tasks on all cores", parse_cmd_rx_tx_info},
	{"start", "<core list>|all <task_id>", "Start core <core_id> or all cores", parse_cmd_start},
	{"stop", "<core list>|all <task_id>", "Stop core <core id> or all cores", parse_cmd_stop},

	{"dump", "<core id> <task id> <nb packets>", "Create a hex dump of <nb_packets> from <task_id> on <core_id> showing how packets have changed between RX and TX.", parse_cmd_trace},
	{"dump_rx", "<core id> <task id> <nb packets>", "Create a hex dump of <nb_packets> from <task_id> on <core_id> at RX", parse_cmd_dump_rx},
	{"dump_tx", "<core id> <task id> <nb packets>", "Create a hex dump of <nb_packets> from <task_id> on <core_id> at TX", parse_cmd_dump_tx},
	{"rx distr start", "", "Start gathering statistical distribution of received packets", parse_cmd_rx_distr_start},
	{"rx distr stop", "", "Stop gathering statistical distribution of received packets", parse_cmd_rx_distr_stop},
	{"rx distr reset", "", "Reset gathered statistical distribution of received packets", parse_cmd_rx_distr_reset},
	{"rx distr show", "", "Display gathered statistical distribution of received packets", parse_cmd_rx_distr_show},

	{"rate", "<port id> <queue id> <rate>", "rate does not include preamble, SFD and IFG", parse_cmd_rate},
	{"count","<core id> <task id> <count>", "Generate <count> packets", parse_cmd_count},
	{"pkt_size", "<core_id> <task_id> <pkt_size>", "Set the packet size to <pkt_size>", parse_cmd_pkt_size},
	{"speed", "<core_id> <task_id> <speed percentage>", "Change the speed to <speed percentage> at which packets are being generated on core <core_id> in task <task_id>.", parse_cmd_speed},
	{"speed_byte", "<core_id> <task_id> <speed>", "Change speed to <speed>. The speed is specified in units of bytes per second.", parse_cmd_speed_byte},
	{"set value", "<core_id> <task_id> <offset> <value> <value_len>", "Set <value_len> bytes to <value> at offset <offset> in packets generated on <core_id> <task_id>", parse_cmd_set_value},
	{"reset values all", "", "Undo all \"set value\" commands on all cores/tasks", parse_cmd_reset_values_all},
	{"reset values", "<core id> <task id>", "Undo all \"set value\" commands on specified core/task", parse_cmd_reset_values},

	{"arp add", "<core id> <task id> <port id> <gre id> <svlan> <cvlan> <ip addr> <mac addr> <user>", "Add a single ARP entry into a CPE table on <core id>/<task id>.", parse_cmd_arp_add},
	{"rule add", "<core id> <task id> svlan_id&mask cvlan_id&mask ip_proto&mask source_ip/prefix destination_ip/prefix range dport_range action", "Add a rule to the ACL table on <core id>/<task id>", parse_cmd_rule_add},
	{"route add", "<core id> <task id> <ip/prefix> <next hop id>", "Add a route to the routing table on core <core id> <task id>. Example: route add 10.0.16.0/24 9", parse_cmd_route_add},

	{"reset stats", "", "Reset all statistics", parse_cmd_reset_stats},
	{"tot stats", "", "Print total RX and TX packets", parse_cmd_tot_stats},
	{"tot ierrors per sec", "", "Print total number of ierrors per second", parse_cmd_tot_ierrors_per_sec},
	{"tot ierrors tot", "", "Print total number of ierrors since reset", parse_cmd_tot_ierrors_tot},
	{"pps stats", "", "Print RX and TX packet rate in unit of packet per second", parse_cmd_pps_stats},
	{"lat stats", "<core id> <task id>", "Print min,max,avg latency as measured during last sampling interval", parse_cmd_lat_stats},
	{"lat packets", "<core id> <task id>", "Print the latency for each of the last set of packets", parse_cmd_lat_packets},
	{"core stats", "<core id> <task id>", "Print rx/tx/drop for task <task id> running on core <core id>", parse_cmd_core_stats},
	{"port_stats", "<port id>", "Print rate for no_mbufs, ierrors, rx_bytes, tx_bytes, rx_pkts, tx_pkts and totals for RX, TX, no_mbufs ierrors for port <port id>", parse_cmd_port_stats},

	{"ring info all", "", "Get information about ring, such as ring size and number of elements in the ring", parse_cmd_ring_info_all},
	{"ring info", "<core id> <task id>", "Get information about ring on core <core id> in task <task id>, such as ring size and number of elements in the ring", parse_cmd_ring_info},
	{"port info", "<port id> [brief?]", "Get port related information, such as MAC address, socket, number of descriptors..., . Adding \"brief\" after command prints short version of output.", parse_cmd_port_info},
	{"port up", "<port id>", "Set the port up", parse_cmd_port_up},
	{"port down", "<port id>", "Set the port down", parse_cmd_port_down},
	{"port xstats", "<port id>", "Get extra statistics for the port", parse_cmd_xstats},
	{"version", "", "Show version", parse_cmd_version},
	{0,0,0,0},
};

static int parse_cmd_help(const char *str, __attribute__((unused)) int fd,
			  __attribute__((unused)) void (*cb)(int fd, const char *data, size_t len))
{
	/* str contains the arguments, all commands that have str as a
	   substring will be shown. */
	size_t len, len2, longest_cmd = 0;
	for (size_t i = 0; i < cmd_parser_n_cmd(); ++i) {
		if (longest_cmd <strlen(cmd_strings[i].cmd))
			longest_cmd = strlen(cmd_strings[i].cmd);
	}
	/* A single call to log will be executed after the help string
	   has been built. The reason for this is to make use of the
	   built-in pager. */
	char buf[32768] = {0};

	for (size_t i = 0; i < cmd_parser_n_cmd(); ++i) {
		int is_substr = 0;
		const size_t cmd_len = strlen(cmd_strings[i].cmd);
		for (size_t j = 0; j < cmd_len; ++j) {
			is_substr = 1;
			for (size_t k = 0; k < strlen(str); ++k) {
				if (str[k] != (cmd_strings[i].cmd + j)[k]) {
					is_substr = 0;
					break;
				}
			}
			if (is_substr)
				break;
		}
		if (!is_substr)
			continue;

		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s", cmd_strings[i].cmd);
		len = strlen(cmd_strings[i].cmd);
		while (len < longest_cmd) {
			len++;
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " ");
		}

		if (strlen(cmd_strings[i].args)) {
			char tmp[256] = {0};
			strncpy(tmp, cmd_strings[i].args, 128);
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "Arguments: %s\n", tmp);
			len2 = len;
			if (strlen(cmd_strings[i].help)) {
				while (len2) {
					len2--;
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " ");
				}
			}
		}

		if (strlen(cmd_strings[i].help)) {
			int add = 0;
			const char *h = cmd_strings[i].help;
			do {
				if (add) {
					len2 = len;
					while (len2) {
						len2--;
						snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " ");
					}
				}
				char tmp[128] = {0};
				const size_t max_len = strlen(h) > 80? 80 : strlen(h);
				size_t len3 = max_len;
				if (len3 == 80) {
					while (len3 && h[len3] != ' ')
						len3--;
					if (len3 == 0)
						len3 = max_len;
				}

				strncpy(tmp, h, len3);
				h += len3;
				while (h[0] == ' ' && strlen(h))
					h++;

				snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s\n", tmp);
				add = 1;
			} while(strlen(h));
		}
		if (strlen(cmd_strings[i].help) == 0&& strlen(cmd_strings[i].args) == 0) {
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "\n");
		}
	}
	plog_info("%s", buf);

	return 0;
}

const char *cmd_parser_cmd(size_t i)
{
	i = i < cmd_parser_n_cmd()? i: cmd_parser_n_cmd();
	return cmd_strings[i].cmd;
}

size_t cmd_parser_n_cmd(void)
{
	return sizeof(cmd_strings)/sizeof(cmd_strings[0]) - 1;
}

void cmd_parser_parse(const char *str, int fd, void (*cb)(int fd, const char *data, size_t len))
{
	static unsigned lcore_id, task_id, nb_packets, val, id,
		port, queue, rate, prefix, next_hop_idx,
		interface, gre_id, svlan, cvlan, mac[6], user;
	uint32_t pkt_size;
	static char mode[20];
	size_t skip;

	for (size_t i = 0; i < cmd_parser_n_cmd(); ++i) {
		skip = strlen(cmd_strings[i].cmd);
		if (strncmp(cmd_strings[i].cmd, str, skip) == 0 &&
		    (str[skip] == ' ' || str[skip] == 0)) {
			while (str[skip] == ' ')
				skip++;

			if (cmd_strings[i].parse(str + skip, fd, cb) != 0) {
				plog_warn("Invalid syntax for command '%s': %s %s\n",
					  cmd_strings[i].cmd, cmd_strings[i].cmd, cmd_strings[i].help);
			}
			return ;
		}
	}

	plog_err("Unknown command: '%s'\n", str);
}
