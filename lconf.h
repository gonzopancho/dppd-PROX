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

#ifndef _LCONF_H_
#define _LCONF_H_

#include "task_init.h"
#include "stats.h"

enum lconf_msg_type {
	LCONF_MSG_STOP,
	LCONF_MSG_START,
	LCONF_MSG_DUMP,
	LCONF_MSG_TRACE,
	LCONF_MSG_DUMP_RX,
	LCONF_MSG_DUMP_TX,
	LCONF_MSG_RX_DISTR_START,
	LCONF_MSG_RX_DISTR_STOP,
	LCONF_MSG_RX_DISTR_RESET
};

struct lconf_msg {
	uint32_t            req; /* Set by master core (if not set), unset by worker after consumption. */
	enum lconf_msg_type type;
	int                 task_id;
	int                 val;
};

struct lcore_cfg {
	/* All tasks running at the moment. This is empty when the core is stopped. */
	struct task_base	*tasks_run[MAX_TASKS_PER_CORE];
	uint8_t			n_tasks_run;

	void (*flush_queues[MAX_TASKS_PER_CORE])(struct task_base *tbase);

	void (*period_func)(void* data);
	void*                   period_data;
	uint64_t                period_timeout;       // call periodic_func after periodic_timeout cycles

	uint64_t                ctrl_timeout;
	void (*ctrl_func_m[MAX_TASKS_PER_CORE])(struct task_base *tbase, void **data, uint16_t n_msgs);
	struct rte_ring         *ctrl_rings_m[MAX_TASKS_PER_CORE];

	void (*ctrl_func_p[MAX_TASKS_PER_CORE])(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
	struct rte_ring         *ctrl_rings_p[MAX_TASKS_PER_CORE];

	struct lconf_msg        msg __attribute__((aligned(4)));
	struct task_base	*tasks_all[MAX_TASKS_PER_CORE];
	int                     task_is_running[MAX_TASKS_PER_CORE];
	uint8_t			n_tasks_all;

	// Following variables are not accessed in main loop
	uint32_t		flags;			// PCFG_* flags below
	uint8_t			active_task;
	uint8_t			id;
	char			name[MAX_NAME_SIZE];
	struct task_args        targs[MAX_TASKS_PER_CORE];
	int (*thread_x)(struct lcore_cfg* lconf);
} __rte_cache_aligned;

/* This function is only run on low load (when no bulk was sent within
   last drain_timeout (16kpps if DRAIN_TIMEOUT = 2 ms) */
static inline void lconf_flush_all_queues(struct lcore_cfg *lconf)
{
	struct task_base *task;

	for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
		task = lconf->tasks_all[task_id];
		if (!(task->flags & FLAG_TX_FLUSH) || (task->flags & FLAG_NEVER_FLUSH)) {
			task->flags |= FLAG_TX_FLUSH;
			continue;
		}
		lconf->flush_queues[task_id](task);
	}
}

/* flags for lcore_cfg */
#define PCFG_RX_DISTR_ACTIVE 0x00000001
#define PCFG_RUNNING         0x00000002

static inline void lconf_set_req(struct lcore_cfg *lconf)
{
	(*(volatile uint32_t *)&lconf->msg.req) = 1;
}

static inline void lconf_unset_req(struct lcore_cfg *lconf)
{
	(*(volatile uint32_t *)&lconf->msg.req) = 0;
}

static inline int lconf_is_req(struct lcore_cfg *lconf)
{
	return (*(volatile uint32_t *)&lconf->msg.req);
}

/* Returns non-zero when terminate has been requested */
int lconf_do_flags(struct lcore_cfg *lconf);

int lconf_get_task_id(const struct lcore_cfg *lconf, const struct task_base *task);
int lconf_task_is_running(const struct lcore_cfg *lconf, uint8_t task_id);

#endif /* _LCONF_H_ */
