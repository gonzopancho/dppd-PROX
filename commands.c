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

#include <string.h>
#include <rte_table_hash.h>
#include <rte_malloc.h>
#include <rte_version.h>

#include "display.h"
#include "commands.h"
#include "log.h"
#include "run.h"
#include "tx_worker.h"
#include "prox_args.h"
#include "hash_utils.h"
#include "prox_cfg.h"
#include "prox_port_cfg.h"
#include "defines.h"
#include "handle_qos.h"
#include "handle_qinq_encap4.h"
#include "quit.h"

void start_core_all(int task_id)
{
	uint32_t cores[RTE_MAX_LCORE];
	uint32_t lcore_id;
	char tmp[256];
	int cnt = 0;

	prox_core_to_str(tmp, sizeof(tmp), 0);
	plog_info("Starting cores: %s\n", tmp);

	lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0) {
		cores[cnt++] = lcore_id;
	}
	start_cores(cores, cnt, task_id);
}

void stop_core_all(int task_id)
{
	uint32_t cores[RTE_MAX_LCORE];
	uint32_t lcore_id;
	char tmp[256];
	int cnt = 0;

	prox_core_to_str(tmp, sizeof(tmp), 0);
	plog_info("Stopping cores: %s\n", tmp);

	lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0) {
		cores[cnt++] = lcore_id;
	}

	stop_cores(cores, cnt, task_id);
}

void start_cores(uint32_t *cores, int count, int task_id)
{
	int n_started_cores = 0;
	uint32_t started_cores[RTE_MAX_LCORE];

	for (int i = 0; i < count; ++i) {
		if (!prox_core_active(cores[i], 0)) {
			plog_warn("Can't start core %u: core is not active\n", cores[i]);
			continue;
		}

		struct lcore_cfg *lconf = &lcore_cfg[cores[i]];

		if (lconf->n_tasks_run != lconf->n_tasks_all) {

			lconf->msg.type = LCONF_MSG_START;
			lconf->msg.task_id = task_id;
			lconf_set_req(lconf);
			if (task_id == -1)
				plog_info("Starting core %u (all tasks)\n", cores[i]);
			else
				plog_info("Starting core %u task %u\n", cores[i], task_id);
			started_cores[n_started_cores++] = cores[i];
			lconf->flags |= PCFG_RUNNING;
			rte_eal_remote_launch(prox_work_thread, NULL, cores[i]);
		}
		else {
			plog_warn("Core %u is already running all its tasks\n", cores[i]);
		}
	}

	/* This function is blocking, so detect when each core has
	   consumed the message. */
	for (int i = 0; i < n_started_cores; ++i) {
		struct lcore_cfg *lconf = &lcore_cfg[started_cores[i]];
		plog_info("Waiting for core %u to start...", started_cores[i]);
		while (lconf_is_req(lconf)) ;
		plog_info(" OK\n");
	}
}

void stop_cores(uint32_t *cores, int count, int task_id)
{
	int n_stopped_cores = 0;
	uint32_t stopped_cores[RTE_MAX_LCORE];
	uint32_t c;

	for (int i = 0; i < count; ++i) {
		if (!prox_core_active(cores[i], 0)) {
			plog_warn("Can't stop core %u: core is not active\n", cores[i]);
			continue;
		}

		struct lcore_cfg *lconf = &lcore_cfg[cores[i]];
		if (lconf->n_tasks_run) {
			while (lconf_is_req(lconf));

			lconf->msg.type = LCONF_MSG_STOP;
			lconf->msg.task_id = task_id;
			lconf_set_req(lconf);
			stopped_cores[n_stopped_cores++] = cores[i];
		}
	}

	for (int i = 0; i < n_stopped_cores; ++i) {
		c = stopped_cores[i];
		struct lcore_cfg *lconf = &lcore_cfg[c];
		while (lconf_is_req(lconf));

		if (lconf->n_tasks_run == 0) {
			plog_info("All tasks stopped on core %u, waiting for core to stop...", c);
			rte_eal_wait_lcore(c);
			plog_info(" OK\n");
			lconf->flags &= ~PCFG_RUNNING;
		}
		else {
			plog_info("Stopped task %u on core %u\n", task_id, c);
		}
	}
}

void cmd_mem_layout(void)
{
	const struct rte_memseg* memseg = rte_eal_get_physmem_layout();

	for (uint32_t i = 0; i < RTE_MAX_MEMSEG; i++) {
		if (memseg[i].addr == NULL)
			break;

		const char *sz_str;
		switch (memseg[i].hugepage_sz >> 20) {
		case 2:
			sz_str = "2MB";
			break;
		case 1024:
			sz_str = "1GB";
			break;
		default:
			sz_str = "??";
		}

		plog_info("Segment %u: [%#lx-%#lx] at %p using %zu pages of %s\n",
			  i,
			  memseg[i].phys_addr,
			  memseg[i].phys_addr + memseg[i].len,
			  memseg[i].addr,
			  memseg[i].len/memseg[i].hugepage_sz, sz_str);
	}
}

void cmd_dump(uint8_t lcore_id, uint8_t task_id, uint32_t nb_packets,
	      int fd, void (*cb)(int fd, const char *data, size_t len), int rx, int tx)
{
	plog_info("dump %u %u %u\n", lcore_id, task_id, nb_packets);
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	}
	else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
		plog_warn("task_id too high, should be in [0, %u]\n", lcore_cfg[lcore_id].n_tasks_all - 1);
	}
	else {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		lconf->tasks_all[task_id]->aux->task_dump.fd = fd;
		lconf->tasks_all[task_id]->aux->task_dump.cb = cb;

		while (lconf_is_req(lconf));
		if (rx && tx)
			lconf->msg.type = LCONF_MSG_DUMP;
		else if (rx)
			lconf->msg.type = LCONF_MSG_DUMP_RX;
		else if (tx)
			lconf->msg.type = LCONF_MSG_DUMP_TX;

		if (rx || tx) {
			lconf->msg.task_id = task_id;
			lconf->msg.val  = nb_packets;
			lconf_set_req(lconf);
		}

		if (lconf->n_tasks_run == 0) {
			lconf_do_flags(lconf);
		}
	}
}

void cmd_trace(uint8_t lcore_id, uint8_t task_id, uint32_t nb_packets)
{
	plog_info("trace %u %u %u\n", lcore_id, task_id, nb_packets);
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	}
	else if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
		plog_warn("task_id too high, should be in [0, %u]\n", lcore_cfg[lcore_id].n_tasks_all - 1);
	}
	else {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		while (lconf_is_req(lconf));

		lconf->msg.type = LCONF_MSG_TRACE;
		lconf->msg.task_id = task_id;
		lconf->msg.val  = nb_packets;
		lconf_set_req(lconf);

		if (lconf->n_tasks_run == 0) {
			lconf_do_flags(lconf);
		}
	}
}

void cmd_rx_distr_start(uint32_t lcore_id)
{
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	} else if (lcore_cfg[lcore_id].flags & PCFG_RX_DISTR_ACTIVE) {
		plog_warn("rx distribution already xrunning on core %u\n", lcore_id);
	} else {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		while (lconf_is_req(lconf));
		lconf->msg.type = LCONF_MSG_RX_DISTR_START;
		lconf_set_req(lconf);

		if (lconf->n_tasks_run == 0) {
			lconf_do_flags(lconf);
		}
	}
}

void cmd_rx_distr_stop(uint32_t lcore_id)
{
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	} else if ((lcore_cfg[lcore_id].flags & PCFG_RX_DISTR_ACTIVE) == 0) {
		plog_warn("rx distribution not running on core %u\n", lcore_id);
	} else {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		while (lconf_is_req(lconf));
		lconf->msg.type = LCONF_MSG_RX_DISTR_STOP;
		lconf_set_req(lconf);

		if (lconf->n_tasks_run == 0) {
			lconf_do_flags(lconf);
		}
	}
}

void cmd_rx_distr_rst(uint32_t lcore_id)
{
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	} else {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		while (lconf_is_req(lconf));
		lconf->msg.type = LCONF_MSG_RX_DISTR_RESET;
		lconf_set_req(lconf);

		if (lconf->n_tasks_run == 0) {
			lconf_do_flags(lconf);
		}
	}
}

void cmd_rx_distr_show(uint32_t lcore_id)
{
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	} else {
		for (uint32_t i = 0; i < lcore_cfg[lcore_id].n_tasks_all; ++i) {
			struct task_base *t = lcore_cfg[lcore_id].tasks_all[i];
			plog_info("t[%u]: ", i);
			for (uint32_t j = 0; j < sizeof(t->aux->rx_bucket)/sizeof(t->aux->rx_bucket[0]); ++j) {
				plog_info("%u ", t->aux->rx_bucket[j]);
			}
			plog_info("\n");
		}
	}
}

void cmd_ringinfo_all(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			cmd_ringinfo(lcore_id, task_id);
		}
	}
}

void cmd_ringinfo(uint8_t lcore_id, uint8_t task_id)
{
	struct lcore_cfg *lconf;
	struct rte_ring *ring;
	struct task_args* targ;
	uint32_t count;

	if (!prox_core_active(lcore_id, 0)) {
		plog_info("lcore %u is not active\n", lcore_id);
		return;
	}
	lconf = &lcore_cfg[lcore_id];
	if (task_id >= lconf->n_tasks_all) {
		plog_warn("Invalid task index %u: lcore %u has %u tasks\n", task_id, lcore_id, lconf->n_tasks_all);
		return;
	}

	targ = &lconf->targs[task_id];
	plog_info("Core %u task %u: %u rings\n", lcore_id, task_id, targ->nb_rxrings);
	for (uint8_t i = 0; i < targ->nb_rxrings; ++i) {
		ring = targ->rx_rings[i];
		count = ring->prod.mask + 1;
		plog_info("\tRing %u:\n", i);
		plog_info("\t\tFlags: %s,%s\n", ring->flags & RING_F_SP_ENQ? "sp":"mp", ring->flags & RING_F_SC_DEQ? "sc":"mc");
		plog_info("\t\tMemory size: %zu bytes\n", rte_ring_get_memsize(count));
		plog_info("\t\tOccupied: %u/%u\n", rte_ring_count(ring), count);
	}
}

static int port_is_valid(uint8_t port_id)
{
	if (port_id > PROX_MAX_PORTS) {
		plog_info("requested port is higher than highest supported port ID (%u)\n", PROX_MAX_PORTS);
		return 0;
	}

	struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];
	if (!port_cfg->active) {
		plog_info("Port %u is not active\n", port_id);
		return 0;
	}
	return 1;
}

void cmd_port_up(uint8_t port_id)
{
	int err;

	if (!port_is_valid(port_id)) {
		return ;
	}

	if ((err = rte_eth_dev_set_link_up(port_id)) == 0) {
		plog_info("Bringing port %d up\n", port_id);
	}
	else {
		plog_warn("Failed to bring port %d up with error %d\n", port_id, err);
	}
}

void cmd_port_down(uint8_t port_id)
{
	int err;

	if (!port_is_valid(port_id)) {
		return ;
	}

	if ((err = rte_eth_dev_set_link_down(port_id)) == 0) {
		plog_info("Bringing port %d down\n", port_id);
	}
	else {
		plog_warn("Failed to bring port %d down with error %d\n", port_id, err);
	}
}

void cmd_xstats(uint8_t port_id)
{
#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0)
	int n_xstats;
	struct rte_eth_xstats *eth_xstats;
	struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];
	int rc;

	n_xstats = rte_eth_xstats_get(port_id, NULL, 0);
	eth_xstats = rte_zmalloc_socket(NULL, n_xstats*sizeof(struct rte_eth_xstats), RTE_CACHE_LINE_SIZE, port_cfg->socket);
	PROX_ASSERT(eth_xstats);
	rc = rte_eth_xstats_get(port_id, eth_xstats, n_xstats);
	if ((rc < 0) || (rc > n_xstats)) {
		if (rc < 0) {
			plog_warn("Failed to get xstats on port %d with error %d\n", port_id, rc);
		} else if (rc > n_xstats) {
			plog_warn("Failed to get xstats on port %d: too many xstats (%d)\n", port_id, rc);
		}
	} else {
		for (int i=0;i<rc;i++) {
			plog_info("%s: %ld\n", eth_xstats[i].name, eth_xstats[i].value);
		}
	}
#else
	plog_warn("Failed to get xstats, xstats are not supported in this version of dpdk\n");
#endif
}

void cmd_portinfo(int port_id)
{
	if (port_id == -1) {
		uint8_t max_port_idx = prox_last_port_active() + 1;

		for (uint8_t port_id = 0; port_id < max_port_idx; ++port_id) {
			if (!prox_port_cfg[port_id].active) {
				continue;
			}
			struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];

			plog_info("%2d:%10s, "MAC_BYTES_FMT", %s\n", port_id, port_cfg->name, MAC_BYTES(port_cfg->eth_addr.addr_bytes), port_cfg->pci_addr);
		}
		return;
	}

	if (!port_is_valid(port_id)) {
		return ;
	}

	struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];

	plog_info("Port info for port %u\n", port_id);
	plog_info("\tName: %s\n", port_cfg->name);
	plog_info("\tDriver: %s\n", port_cfg->driver_name);
	plog_info("\tMac address: "MAC_BYTES_FMT"\n", MAC_BYTES(port_cfg->eth_addr.addr_bytes));
	plog_info("\tLink speed: %u Mbps\n", port_cfg->link_speed);
	plog_info("\tLink status: %s\n", port_cfg->link_up? "up" : "down");
	plog_info("\tSocket: %u\n", port_cfg->socket);
	plog_info("\tPCI address: %s\n", port_cfg->pci_addr);
	plog_info("\tPromiscuous: %s\n", port_cfg->promiscuous? "yes" : "no");
	plog_info("\tNumber of RX/TX descriptors: %u/%u\n", port_cfg->n_rxd, port_cfg->n_txd);
	plog_info("\tNumber of RX/TX queues: %u/%u (max: %u/%u)\n", port_cfg->n_rxq, port_cfg->n_txq, port_cfg->max_rxq, port_cfg->max_txq);
	plog_info("\tMemory pools:\n");
	for (uint8_t i = 0; i < 32; ++i) {
		if (port_cfg->pool[i]) {
			plog_info("\t\tname: %s (%p)\n", port_cfg->pool[i]->name, port_cfg->pool[i]);
		}
	}
}

void cmd_thread_info(uint8_t lcore_id, uint8_t task_id)
{
	plog_info("thread_info %u %u \n", lcore_id, task_id);
	if (lcore_id > RTE_MAX_LCORE) {
		plog_warn("core_id too high, maximum allowed is: %u\n", RTE_MAX_LCORE);
	}
	if (!prox_core_active(lcore_id, 0)) {
		plog_warn("lcore %u is not active\n", lcore_id);
		return;
	}
	if (task_id >= lcore_cfg[lcore_id].n_tasks_all) {
		plog_warn("task_id too high, should be in [0, %u]\n", lcore_cfg[lcore_id].n_tasks_all - 1);
		return;
	}
	if (strcmp(lcore_cfg[lcore_id].targs[task_id].task_init->mode_str, "qos") == 0) {
		struct task_base *task;

		task = lcore_cfg[lcore_id].tasks_all[task_id];
		plog_info("core %d, task %d: %d mbufs stored in QoS\n", lcore_id, task_id,
			  task_qos_n_pkts_buffered(task));

#ifdef ENABLE_EXTRA_USER_STATISTICS
	}
	else if (lcore_cfg[lcore_id].targs[task_id].mode == QINQ_ENCAP4) {
		struct task_qinq_encap4 *task;
		task = (struct task_qinq_encap4 *)(lcore_cfg[lcore_id].tasks_all[task_id]);
		for (int i=0;i<task->n_users;i++) {
			if (task->stats_per_user[i])
				plog_info("User %d: %d packets\n", i, task->stats_per_user[i]);
		}
#endif
	}
	else {
		// Only QoS thread info so far
		plog_err("core %d, task %d: not a qos core (%p)\n", lcore_id, task_id, lcore_cfg[lcore_id].thread_x);
	}
}

void cmd_rx_tx_info(void)
{
	uint32_t lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		for (uint8_t task_id = 0; task_id < lcore_cfg[lcore_id].n_tasks_all; ++task_id) {
			struct task_args *targ = &lcore_cfg[lcore_id].targs[task_id];

			plog_info("Core %u:", lcore_id);
			if (targ->rx_ports[0] != NO_PORT_AVAIL) {
				for (int i = 0; i < targ->nb_rxports; i++) {
					plog_info(" RX port %u (queue %u)", targ->rx_ports[i], targ->rx_queues[i]);
				}
			}
			else {
				for (uint8_t j = 0; j < targ->nb_rxrings; ++j) {
					plog_info(" RX ring[%u,%u] %p", task_id, j, targ->rx_rings[j]);
				}
			}
			plog_info(" ==>");
			for (uint8_t j = 0; j < targ->nb_txports; ++j) {
				plog_info(" TX port %u (queue %u)", targ->tx_port_queue[j].port,
					  targ->tx_port_queue[j].queue);
			}

			for (uint8_t j = 0; j < targ->nb_txrings; ++j) {
				plog_info(" TX ring %p", targ->tx_rings[j]);
			}

			plog_info("\n");
		}
	}
}
