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

#ifndef _TASK_INIT_H_
#define _TASK_INIT_H_

#include <sys/queue.h>

#include <rte_common.h>
#include <rte_sched.h>
#include <rte_ether.h>
#include "task_base.h"
#include "prox_globals.h"
#include "ip6_addr.h"
#include "flow_iter.h"

struct rte_mbuf;
struct lcore_cfg;

#if MAX_RINGS_PER_TASK < PROX_MAX_PORTS
#error MAX_RINGS_PER_TASK < PROX_MAX_PORTS
#endif

#define TASK_ARG_DROP           0x01
#define TASK_ARG_RX_RING        0x02
#define TASK_ARG_INET_SIDE      0x04
#define TASK_ARG_RTE_TABLE      0x08
#define TASK_ARG_LOCAL_LPM      0x10
#define TASK_ARG_QINQ_ACL       0x20
#define TASK_ARG_CTRL_RINGS_P   0x40
#define TASK_ARG_DST_MAC_SET	0x80
#define TASK_ARG_SRC_MAC_SET	0x100
#define	TASK_ARG_DO_NOT_SET_SRC_MAC 0x200
#define	TASK_ARG_DO_NOT_SET_DST_MAC 0x400


enum protocols {IPV4, ARP, IPV6};

struct qos_cfg {
	struct rte_sched_port_params port_params;
	struct rte_sched_subport_params subport_params[1];
	struct rte_sched_pipe_params pipe_params[1];
};

enum ctrl_type {CTRL_TYPE_DP, CTRL_TYPE_MSG, CTRL_TYPE_PKT};

struct thread_list_cfg {
	uint32_t    thread_id[MAX_WT_PER_LB];
	uint8_t     active;
	uint8_t     nb_threads;
	uint8_t     dest_task;
	struct task_args *targ_dst[MAX_WT_PER_LB];
	enum ctrl_type type;
};

enum task_mode {NOT_SET, MASTER, QINQ_DECAP4, QINQ_DECAP6,
		LB_QINQ, LB_NET, QINQ_ENCAP4, QINQ_ENCAP6,
		GRE_DECAP, GRE_ENCAP,
                IPV6_DECAP, IPV6_ENCAP,
};

struct task_args;

struct task_init {
	enum task_mode mode;
	char mode_str[32];
	char sub_mode_str[32];
	void (*early_init)(struct task_args *targ);
	void (*init)(struct task_base *tbase, struct task_args *targ);
	void (*handle)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts);
	int (*thread_x)(struct lcore_cfg* lconf);
	struct flow_iter flow_iter;
	size_t size;
	uint16_t     flag_req_data; /* flags from prox_shared.h */
	uint16_t     flag_features;
	uint32_t mbuf_size;
	LIST_ENTRY(task_init) entries;
};

enum police_action {
        ACT_GREEN = e_RTE_METER_GREEN,
        ACT_YELLOW = e_RTE_METER_YELLOW,
        ACT_RED = e_RTE_METER_RED,
        ACT_DROP = 3,
	ACT_INVALID = 4
};

/* Configuration for task that is only used during startup. */
struct task_args {
	struct task_base       *tbase;
	struct task_init*       task_init;
	struct rte_mempool     *pool;
	char		       pool_name[MAX_NAME_SIZE];
	struct lcore_cfg       *lconf;
	uint32_t               nb_mbuf;
	uint32_t               mbuf_size;
	uint8_t    	       mbuf_size_set_explicitely;
	uint32_t               nb_cache_mbuf;
	uint8_t                nb_slave_threads;
	uint8_t		       nb_worker_threads;
	uint8_t		       worker_thread_id;
	uint8_t		       task;
	struct thread_list_cfg thread_list[MAX_PROTOCOLS];
	struct task_args       *prev_tasks[MAX_RINGS_PER_TASK];
	uint32_t               n_prev_tasks;
	uint32_t               ring_size; /* default is RX_RING_SIZE */
	struct qos_cfg         qos_conf;
	uint32_t               flags;
	uint32_t               runtime_flags;
	uint8_t                nb_txports;
	uint8_t                nb_txrings;
	uint8_t                nb_rxrings;
	uint8_t                tot_rxrings;
	uint8_t                nb_rxports;
	uint8_t                rx_ports[PROX_MAX_PORTS];
	uint32_t               byte_offset;
	uint32_t               local_ipv4;
	struct ipv6_addr       local_ipv6;    /* For IPv6 Tunnel, it's the local tunnel endpoint address */
	struct rte_ring        *rx_rings[MAX_RINGS_PER_TASK];
	struct rte_ring        *tx_rings[MAX_RINGS_PER_TASK];
	struct ether_addr      edaddr;
	struct ether_addr      esaddr;
	struct port_queue      tx_port_queue[PROX_MAX_PORTS];
	uint8_t                rx_queues[PROX_MAX_PORTS];
	/* Used to set up actual task at initialization time. */
	enum task_mode         mode;
	/* Destination output position in hw or sw when using mac learned dest port. */
	uint8_t                mapping[PROX_MAX_PORTS];
	struct rte_table_hash  *cpe_table;
	struct rte_table_hash  *qinq_gre_table;
	struct rte_hash        *cpe_gre_hash;
	struct rte_hash        *qinq_gre_hash;
	struct cpe_data        *cpe_data;
	struct cpe_gre_data    *cpe_gre_data;
	struct qinq_gre_data   *qinq_gre_data;
	uint8_t                tx_opt_ring;
	struct task_args       *tx_opt_ring_task;
	uint32_t               qinq_tag;
#ifdef ENABLE_EXTRA_USER_STATISTICS
	uint32_t               n_users;	// Number of users in user table.
#endif
	uint32_t               n_flows;	// Number of flows used in policing
	uint32_t               cir;
	uint32_t               cbs;
	uint32_t               ebs;
	uint32_t               pir;
	uint32_t               pbs;
	uint32_t               overhead;
	enum police_action     police_act[3][3];
	uint32_t               marking[4];
	uint32_t               n_max_rules;
	uint32_t               delay_ms;
	uint32_t               cpe_table_timeout_ms;
	uint32_t               etype;
#ifdef GRE_TP
	uint32_t tb_rate;                /**< Pipe token bucket rate (measured in bytes per second) */
	uint32_t tb_size;                /**< Pipe token bucket size (measured in credits) */
#endif
	uint8_t                tunnel_hop_limit;  /* IPv6 Tunnel - Hop limit */
        uint16_t               lookup_port_mask;  /* Ipv6 Tunnel - Mask applied to UDP/TCP port before lookup */
	uint32_t               ctrl_freq;
	uint8_t                lb_friend_core;
	uint8_t                lb_friend_task;
	/* gen related*/
	uint32_t               rate_bps;
	uint32_t               n_rand_str;
	char                   rand_str[64][64];
	uint32_t               rand_offset[64];
	char                   pcap_file[256];
	uint32_t               lat_pos;
	uint32_t               bucket_size;
	uint32_t               lat_enabled;
	uint32_t               pkt_size;
	uint8_t                pkt_inline[ETHER_MAX_LEN];
	uint32_t               probability;
	char                   nat_table[256];
	uint32_t               use_src;
	char                   route_table[256];
	char                   rules[256];
	char                   dscp[256];
	char                   tun_bindings[256];
	char                   cpe_table_name[256];
	char                   user_table[256];
	uint32_t               n_concur_conn;
	char                   streams[256];
};

struct task_base *init_task_struct(struct task_args *targ);
struct task_init *to_task_init(const char *mode_str, const char *sub_mode_str);
void tasks_list(void);

void reg_task(struct task_init* t);

#endif /* _TASK_INIT_H_ */
