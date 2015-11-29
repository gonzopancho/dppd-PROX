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

#ifdef BRAS_STATS
#include <curses.h>
#endif

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <signal.h>

#include "handle_lat.h"
#include "cqm.h"
#include "msr.h"
#include "display.h"
#include "log.h"
#include "commands.h"
#include "main.h"
#include "stats.h"
#include "prox_args.h"
#include "prox_cfg.h"
#include "prox_assert.h"
#include "version.h"
#include "quit.h"
#include "prox_port_cfg.h"
#include "genl4_bundle.h"

struct screen_state {
	char chosen_screen;
	int chosen_page;
};

struct screen_state screen_state;
static void stats_display_layout(uint8_t in_place);

/* Set up the display mutex  as recursive. This enables threads to use
   display_[un]lock() to lock  the display when multiple  calls to for
   instance plog_info() need to be made. */

static pthread_mutex_t disp_mtx = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static void display_lock(void)
{
	pthread_mutex_lock(&disp_mtx);
}

static void display_unlock(void)
{
	pthread_mutex_unlock(&disp_mtx);
}

#ifdef BRAS_STATS

struct cqm_related {
	struct cqm_features	features;
	uint8_t			supported;
	uint32_t		last_rmid;
};

struct cqm_related cqm;

struct global_stats {
	uint64_t tx_pps;
	uint64_t rx_pps;
	uint64_t tx_tot;
	uint64_t rx_tot;
	uint64_t rx_tot_beg;
	uint64_t tx_tot_beg;
	uint64_t avg_start;
	uint8_t  started_avg;
	uint64_t rx_avg;
	uint64_t tx_avg;
	uint64_t nic_rx_tot_beg;
	uint64_t nic_tx_tot_beg;
	uint64_t nic_ierrors_tot_beg;
	uint64_t last_tsc;
};

struct port_stats {
	uint64_t tot_tx_pkt_count;
	uint64_t tot_tx_pkt_drop;
	uint64_t tot_rx_pkt_count;

	uint64_t tsc[2];
	uint32_t tx_pkt_count[2];
	uint32_t tx_pkt_drop[2];
	uint32_t rx_pkt_count[2];
	uint32_t empty_cycles[2];
};

struct core_port {
	struct task_stats *stats;
	struct port_stats *port_stats;
	uint8_t lcore_id;
	uint8_t port_id;
	/* flags set if total RX/TX values need to be reported set at
	   initialization time, only need to access stats values in port */
	uint8_t flags;
};

struct lcore_stats {
	struct port_stats port_stats[MAX_TASKS_PER_CORE];
	uint32_t rmid;
	uint64_t cqm_data;
	uint64_t cqm_bytes;
	uint64_t cqm_fraction;
	uint64_t afreq[2];
	uint64_t mfreq[2];
};

struct ring_stats {
	struct rte_ring	*ring;
	uint32_t	 nb_ports;
	struct prox_port_cfg *port[PROX_MAX_PORTS];
	uint32_t	 free;
	uint32_t	 size;
};

#define MAX_RING_STATS 128
/* Advanced text output */
static WINDOW *scr = NULL, *win_txt, *win_general, *win_cmd, *win_stat, *win_title, *win_tabs, *win_help;
static int win_txt_height = 1;
static int title_len;

#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0) && RTE_VER_PATCH_RELEASE >= 1
static struct rte_eth_xstats *eth_xstats = NULL;
static int xstat_tpr_offset = -1, xstat_tor_offset = -1;
#endif
static int num_ixgbe_xstats = 0;

/* Stores all readed values from the cores, displaying is done afterwards because
   displaying introduces overhead. If displaying was done right after the values
   are read, inaccuracy is introduced for later cores */
int last_stat; /* 0 or 1 to track latest 2 measurements */
static struct lcore_stats  lcore_stats[RTE_MAX_LCORE];
static struct core_port    core_ports[RTE_MAX_LCORE *MAX_TASKS_PER_CORE];
static struct core_port    *core_port_ordered[RTE_MAX_LCORE*MAX_TASKS_PER_CORE];
static struct global_stats global_stats;
static struct eth_stats    eth_stats[PROX_MAX_PORTS];
static uint8_t nb_tasks_tot;
static uint8_t nb_interface;
static uint8_t nb_active_interfaces;
static uint16_t core_port_height;
static uint64_t start_tsc;
static uint64_t beg_tsc, end_tsc;
static int msr_support;
static int col_offset;
static uint16_t n_rings;
static uint16_t rings_height;
struct ring_stats ring_stats[MAX_RING_STATS];
static uint64_t tsc_hz;

static uint16_t n_mempools;
static uint16_t n_latency;
static uint16_t n_l4gen;

struct task_lat_stats {
	struct task_lat *task;
	uint8_t lcore_id;
	uint8_t task_id;
	uint8_t rx_port; /* Currently only one */
};

struct task_lat_stats task_lats[64];
struct lat_test lat_stats[64]; /* copy of stats when running update stats. */
static int cmd_cursor_pos;
static const char *cmd_cmd;
static int cmd_len;

struct mempool_stats {
	struct rte_mempool *pool;
	uint16_t port;
	uint16_t queue;
	size_t free;
	size_t size;
};

struct mempool_stats mempool_stats[64];

/* only used in struct task_l4_stats */
struct task_l4gen {
	struct task_base base;
	struct l4_stats l4_stats;
};

struct task_l4_stats {
	struct task_l4gen *task;
	struct l4_stats l4_stats[2];
	uint64_t tsc[2];
	uint8_t lcore_id;
	uint8_t task_id;
};

struct task_l4_stats task_l4_stats[64];

/* Colors used in the interface */
enum colors {
	INVALID_COLOR,
	NO_COLOR,
	RED_ON_BLACK,
	BLACK_ON_CYAN,
	BLACK_ON_GREEN,
	BLACK_ON_WHITE,
	BLACK_ON_YELLOW,
	YELLOW_ON_BLACK,
	WHITE_ON_RED,
	YELLOW_ON_NOTHING,
	GREEN_ON_NOTHING,
	RED_ON_NOTHING,
	BLUE_ON_NOTHING,
	CYAN_ON_NOTHING,
	MAGENTA_ON_NOTHING,
	WHITE_ON_NOTHING,
};

int display_getch(void)
{
	int ret;

	display_lock();
	ret = wgetch(scr);
	display_unlock();

	return ret;
}

void display_cmd(const char *cmd, int cl, int cursor_pos)
{
	cmd_len = cl;
	if (cursor_pos == -1 || cursor_pos > cmd_len)
		cursor_pos = cmd_len;
	cmd_cursor_pos = cursor_pos;
	cmd_cmd = cmd;

	display_lock();
	werase(win_cmd);
	if (cursor_pos < cmd_len) {
		waddnstr(win_cmd, cmd, cursor_pos);
		wbkgdset(win_cmd, COLOR_PAIR(YELLOW_ON_BLACK));
		waddnstr(win_cmd, cmd + cursor_pos, 1);
		wbkgdset(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
		waddnstr(win_cmd, cmd + cursor_pos + 1, cmd_len - (cursor_pos + 1));
	}
	else {
		waddnstr(win_cmd, cmd, cmd_len);
		wmove(win_cmd, cursor_pos, 0);
		wbkgdset(win_cmd, COLOR_PAIR(YELLOW_ON_BLACK));
		waddstr(win_cmd, " ");
		wbkgdset(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
	}

	wattroff(win_stat, A_UNDERLINE);
	wrefresh(win_cmd);
	display_unlock();
}

static void refresh_cmd_win(void)
{
	display_cmd(cmd_cmd, cmd_len, cmd_cursor_pos);
}

static WINDOW *create_subwindow(int height, int width, int y_pos, int x_pos)
{
	WINDOW *win = subwin(scr, height, width, y_pos, x_pos);
	touchwin(scr);
	return win;
}

/* Format string capable [mv]waddstr() wrappers */
__attribute__((format(printf, 4, 5))) static inline int mvwaddstrf(WINDOW* win, int y, int x, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	wmove(win, y, x);
	if (x > COLS - 1) {
		return 0;
	}

	/* to prevent strings from wrapping and */
	if (strlen(buf) > (uint32_t)COLS - x) {
		buf[COLS - 1 - x] = 0;
	}
	waddstr(win, buf);
	return ret;
}

uint64_t stats_core_task_tot_rx(uint8_t lcore_id, uint8_t task_id)
{
	return lcore_stats[lcore_id].port_stats[task_id].tot_rx_pkt_count;
}

uint64_t stats_core_task_tot_tx(uint8_t lcore_id, uint8_t task_id)
{
	return lcore_stats[lcore_id].port_stats[task_id].tot_tx_pkt_count;
}

uint64_t stats_core_task_tot_drop(uint8_t lcore_id, uint8_t task_id)
{
	return lcore_stats[lcore_id].port_stats[task_id].tot_tx_pkt_drop;
}

uint64_t stats_core_task_last_tsc(uint8_t lcore_id, uint8_t task_id)
{
	return lcore_stats[lcore_id].port_stats[task_id].tsc[last_stat];
}

#define PORT_STATS_RX 0x01
#define PORT_STATS_TX 0x02

// Red: link down; Green: link up
static short link_color(const uint8_t if_port)
{
	return COLOR_PAIR(prox_port_cfg[if_port].link_up? GREEN_ON_NOTHING : RED_ON_NOTHING);
}

static void init_core_port(struct core_port *core_port, uint8_t lcore_id, uint8_t port_id, struct task_stats *stats, uint8_t flags)
{
	core_port->lcore_id = lcore_id;
	core_port->port_id = port_id;
	core_port->stats = stats;

	core_port->port_stats = &lcore_stats[lcore_id].port_stats[port_id];
	core_port->flags |= flags;

	if (cqm.supported && lcore_stats[lcore_id].rmid == 0) {
		++cqm.last_rmid; // 0 not used (by default all cores are 0)
		plog_info("setting up rmid: %d\n", cqm.last_rmid);
		lcore_stats[lcore_id].rmid = cqm.last_rmid;
	}
}

static struct core_port *set_line_no(const uint8_t lcore_id, const uint8_t port_id)
{
	for (uint8_t active_core_port = 0; active_core_port < nb_tasks_tot; ++active_core_port) {
		struct core_port *core_port = &core_ports[active_core_port];
		if (lcore_id == core_port->lcore_id && port_id == core_port->port_id) {
			return core_port;
		}
	}
	return NULL;
}

static void init_active_eth_ports(void)
{
	nb_interface = rte_eth_dev_count();
	nb_active_interfaces = 0;

	for (uint8_t i = 0; i < nb_interface; ++i) {
		if (prox_port_cfg[i].active) {
			nb_active_interfaces++;
		}
	}
}

static void init_mempools(void)
{
	uint32_t n_max_mempools = sizeof(prox_port_cfg[0].pool)/sizeof(prox_port_cfg[0].pool[0]);
	n_mempools = 0;

	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (prox_port_cfg[i].active && n_mempools < 64) {
			for (uint8_t j = 0; j < n_max_mempools; ++j) {
				if (prox_port_cfg[i].pool[j] && prox_port_cfg[i].pool_size[j]) {
					mempool_stats[n_mempools].pool = prox_port_cfg[i].pool[j];
					mempool_stats[n_mempools].port = i;
					mempool_stats[n_mempools].queue = j;
					mempool_stats[n_mempools].size = prox_port_cfg[i].pool_size[j];
					n_mempools++;
				}
			}
		}
	}
}

static void init_latency(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	n_latency = 0;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			/* TODO: make this work with multiple ports
			   and with rings. Currently, only showing lat
			   tasks which have 1 RX port. */
			if (!strcmp(targ->task_init->mode_str, "lat") && targ->nb_rxports == 1) {
				task_lats[n_latency].task = (struct task_lat *)lconf->tasks_all[task_id];
				task_lats[n_latency].lcore_id = lcore_id;
				task_lats[n_latency].task_id = task_id;
				task_lats[n_latency].rx_port = targ->rx_ports[0];
				if (++n_latency == 64)
					return ;
			}
		}
	}
}

static void init_l4gen(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	n_l4gen = 0;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			if (!strcmp(targ->task_init->mode_str, "genl4")) {
				task_l4_stats[n_l4gen].task = (struct task_l4gen *)lconf->tasks_all[task_id];
				task_l4_stats[n_l4gen].lcore_id = lcore_id;
				task_l4_stats[n_l4gen].task_id = task_id;
				if (++n_l4gen == 64)
					return ;
			}
		}
	}
}

static struct ring_stats* init_rings_add(struct rte_ring* ring)
{
	for (uint16_t i = 0; i < n_rings; ++i) {
		if (strcmp(ring->name, ring_stats[i].ring->name) == 0)
			return &ring_stats[i];
	}

	ring_stats[n_rings].ring = ring;
	n_rings++;
	PROX_PANIC(n_rings >= MAX_RING_STATS, "Maximum number of ring_stats reached - recompile be increasing MAX_RING_STATS");

	rings_height++;

	return &ring_stats[n_rings-1];
}

static void init_rings(void)
{
	uint32_t lcore_id = -1;
	struct lcore_cfg *lconf;
	struct task_args *targ;

	n_rings = 0;
	rings_height = 0;

	while(prox_core_next(&lcore_id, 1) == 0) {
		lconf = &lcore_cfg[lcore_id];

		for(uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			targ = &lconf->targs[task_id];

			for(uint32_t rxring_id = 0; rxring_id < targ->nb_rxrings; ++rxring_id) {
				if (!targ->tx_opt_ring_task)
					init_rings_add(targ->rx_rings[rxring_id]);
			}

			for (uint32_t txring_id = 0; txring_id < targ->nb_txrings; ++txring_id) {
				if (!targ->tx_opt_ring)
					init_rings_add(targ->tx_rings[txring_id]);
			}
		}
	}

	struct rte_eth_dev_info dev_info;
	uint8_t nb_ports = rte_eth_dev_count();
	struct ring_stats* stats = NULL;

	if (nb_ports > PROX_MAX_PORTS) {
		plog_warn("\tWarning: I can deal with at most %u ports."
			" Please update PROX_MAX_PORTS and recompile.\n", PROX_MAX_PORTS);

		nb_ports = PROX_MAX_PORTS;
	}

	for (uint8_t port_id = 0; port_id < nb_ports; ++port_id) {
		if (!prox_port_cfg[port_id].active) {
			continue;
		}

		if (prox_port_cfg[port_id].rx_ring[0] != '\0') {
			stats = init_rings_add(rte_ring_lookup(prox_port_cfg[port_id].rx_ring));
			stats->port[stats->nb_ports++] = &prox_port_cfg[port_id];
			if (stats->nb_ports > 1)
				rings_height++;
		}

		if (prox_port_cfg[port_id].tx_ring[0] != '\0') {
			stats = init_rings_add(rte_ring_lookup(prox_port_cfg[port_id].tx_ring));
			stats->port[stats->nb_ports++] = &prox_port_cfg[port_id];
			if (stats->nb_ports > 1)
				rings_height++;
		}
	}

	for (uint16_t ring_id = 0; ring_id < n_rings; ++ring_id) {
		ring_stats[ring_id].size = ring_stats[ring_id].ring->prod.size;
	}
}

/* Populate active_core_ports for stats reporting, the order of the cores matters
   for reporting the most accurate results. TX cores should updated first (to prevent
   negative Loss stats). This will also calculate the number of core ports used by
   other display functions. */
static void init_active_core_ports(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id;

	/* add cores that are receiving from and sending to physical ports first */
	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			struct task_stats *stats = &lconf->tasks_all[task_id]->aux->stats;
			if (targ->nb_rxrings == 0 && targ->nb_txrings == 0) {
				init_core_port(&core_ports[nb_tasks_tot], lcore_id, task_id, stats, PORT_STATS_RX | PORT_STATS_TX);
				++nb_tasks_tot;
			}
		}
	}

	/* add cores that are sending to physical ports second */
	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			struct task_stats *stats = &lconf->tasks_all[task_id]->aux->stats;
			if (targ->nb_rxrings != 0 && targ->nb_txrings == 0) {
				init_core_port(&core_ports[nb_tasks_tot], lcore_id, task_id, stats, PORT_STATS_TX);
				++nb_tasks_tot;
			}
		}
	}

	/* add cores that are receiving from physical ports third */
	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			struct task_stats *stats = &lconf->tasks_all[task_id]->aux->stats;
			if (targ->nb_rxrings == 0 && targ->nb_txrings != 0) {
				init_core_port(&core_ports[nb_tasks_tot], lcore_id, task_id, stats, PORT_STATS_RX);
				++nb_tasks_tot;
			}
		}
	}

	/* add cores that are working internally (no physical ports attached) */
	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			struct task_stats *stats = &lconf->tasks_all[task_id]->aux->stats;
			if (targ->nb_rxrings != 0 && targ->nb_txrings != 0) {
				init_core_port(&core_ports[nb_tasks_tot], lcore_id, task_id, stats, 0);
				++nb_tasks_tot;
			}
		}
	}
}

static void (*ncurses_sigwinch)(int);

static void sigwinch(int in)
{
	if (ncurses_sigwinch)
		ncurses_sigwinch(in);
	refresh();
	stats_display_layout(0);
}

static void set_signal_handler(void)
{
	struct sigaction old;

	sigaction(SIGWINCH, NULL, &old);
	ncurses_sigwinch = old.sa_handler;

	signal(SIGWINCH, sigwinch);
}

void display_init(unsigned avg_start, unsigned duration)
{
	scr = initscr();
	start_color();
	/* Assign default foreground/background colors to color number -1 */
	use_default_colors();
	tsc_hz = rte_get_tsc_hz();

	init_pair(NO_COLOR,   -1,  -1);
	init_pair(RED_ON_BLACK,     COLOR_RED,  COLOR_BLACK);
	init_pair(BLACK_ON_CYAN,   COLOR_BLACK,  COLOR_CYAN);
	init_pair(BLACK_ON_GREEN,  COLOR_BLACK,  COLOR_GREEN);
	init_pair(BLACK_ON_WHITE,  COLOR_BLACK,  COLOR_WHITE);
	init_pair(BLACK_ON_YELLOW, COLOR_BLACK,  COLOR_YELLOW);
	init_pair(YELLOW_ON_BLACK, COLOR_YELLOW,  COLOR_BLACK);
	init_pair(WHITE_ON_RED,    COLOR_WHITE,  COLOR_RED);
	init_pair(YELLOW_ON_NOTHING,   COLOR_YELLOW,  -1);
	init_pair(GREEN_ON_NOTHING,   COLOR_GREEN,  -1);
	init_pair(RED_ON_NOTHING,   COLOR_RED,  -1);
	init_pair(BLUE_ON_NOTHING,  COLOR_BLUE, -1);
	init_pair(CYAN_ON_NOTHING,  COLOR_CYAN, -1);
	init_pair(MAGENTA_ON_NOTHING,  COLOR_MAGENTA, -1);
	init_pair(WHITE_ON_NOTHING,  COLOR_WHITE, -1);
	/* nodelay(scr, TRUE); */
	noecho();
	curs_set(0);
	/* Create fullscreen log window. When stats are displayed
	   later, it is recreated with appropriate dimensions. */
	win_txt = create_subwindow(0, 0, 0, 0);
	wbkgd(win_txt, COLOR_PAIR(0));

	idlok(win_txt, FALSE);
	/* Get scrolling */
	scrollok(win_txt, TRUE);
	/* Leave cursor where it was */
	leaveok(win_txt, TRUE);

	refresh();

	set_signal_handler();

	core_port_height = (LINES - 5 - 2 - 3);
	if (core_port_height > nb_tasks_tot) {
		core_port_height = nb_tasks_tot;
	}
	start_tsc = rte_rdtsc();
	beg_tsc = start_tsc;
	/* + 1 for rounding */
	end_tsc = duration? start_tsc + (avg_start + duration + 1) * tsc_hz : 0;

	global_stats.avg_start = start_tsc + avg_start*tsc_hz;
	stats_update();

	stats_display_layout(0);
}

static void stats_display_latency(void)
{
	display_lock();

	wattron(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));

	/* Labels */
	mvwaddstrf(win_stat, 0, 0,   "Core");
	mvwaddstrf(win_stat, 1, 0,   "  Nb");
	mvwvline(win_stat, 1, 4,  ACS_VLINE, n_latency + 2);
	mvwaddstrf(win_stat, 0, 5, " Port Nb");
	mvwaddstrf(win_stat, 1, 5, "  RX");

	mvwaddstrf(win_stat, 0, 31, "Measured Latency");

	mvwvline(win_stat, 1, 13,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 14, "  Min (us)");
	mvwvline(win_stat, 1, 26,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 27, "  Max (us)");
	mvwvline(win_stat, 1, 39,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 40, "  Avg (us)");
	mvwvline(win_stat, 1, 52,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 53, " STDDev (us)");
	mvwvline(win_stat, 1, 65,  ACS_VLINE, n_mempools + 1);
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);

	for (uint16_t i = 0; i < n_latency; ++i) {
		mvwaddstrf(win_stat, 2 + i, 0, "%2u/%1u",
			   task_lats[i].lcore_id,
			   task_lats[i].task_id);

		mvwaddstrf(win_stat, 2 + i, 8, "%u",
			   task_lats[i].rx_port);
	}

	display_unlock();
}

static void stats_display_l4gen(void)
{
	display_lock();

	wattron(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));

	/* Labels */
	mvwaddstrf(win_stat, 0, 0,   "Core");
	mvwaddstrf(win_stat, 1, 0,   "  Nb");

	mvwaddstrf(win_stat, 0, 4, "       Setup rate (flows/s)          ");
	mvwvline(win_stat, 0, 4,  ACS_VLINE, n_l4gen + 2);
	mvwaddstrf(win_stat, 1, 5, "   TCP   ");
	mvwvline(win_stat, 1, 14,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 15, "   UDP   ");
	mvwvline(win_stat, 1, 24,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 25, "  Total  ");
	mvwvline(win_stat, 0, 34,  ACS_VLINE, n_l4gen + 2);

	mvwaddstrf(win_stat, 0, 35, "        Teardown rate (flows/s)      ");
	mvwaddstrf(win_stat, 1, 35, "TCP w/o reTX");
	mvwvline(win_stat, 1, 47,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 48, "TCP w/  reTX");
	mvwvline(win_stat, 1, 60,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 61, "     UDP    ");
	mvwvline(win_stat, 0, 73,  ACS_VLINE, n_l4gen + 2);


	mvwaddstrf(win_stat, 0, 74, "Expire rate (flows/s)");
	mvwaddstrf(win_stat, 1, 74, "    TCP   ");
	mvwvline(win_stat, 1, 84,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 85, "    UDP   ");
	mvwvline(win_stat, 0, 95,  ACS_VLINE, n_l4gen + 2);

	mvwaddstrf(win_stat, 0, 96, "         Other       ");
	mvwaddstrf(win_stat, 1, 96, "active (#)");
	mvwvline(win_stat, 1, 106,  ACS_VLINE, n_l4gen + 1);
	mvwaddstrf(win_stat, 1, 107, " reTX (/s)");
	mvwvline(win_stat, 0, 117,  ACS_VLINE, n_l4gen + 2);

	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);

	for (uint16_t i = 0; i < n_l4gen; ++i) {
		mvwaddstrf(win_stat, 2 + i, 0, "%2u/%1u",
			   task_l4_stats[i].lcore_id,
			   task_l4_stats[i].task_id);
	}

	display_unlock();
}

static void stats_display_mempools(void)
{
	display_lock();

	wattron(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));
	/* Labels */
	mvwaddstrf(win_stat, 0, 2,   "Port");
	mvwaddstrf(win_stat, 1, 0,   "  Nb");
	mvwvline(win_stat, 1, 4,  ACS_VLINE, n_mempools + 2);
	mvwaddstrf(win_stat, 1, 5,   "Queue");

	mvwvline(win_stat, 0, 10,  ACS_VLINE, n_mempools + 3);
	mvwaddstrf(win_stat, 0, 50, "Sampled statistics");
	mvwaddstrf(win_stat, 1, 11, "Occup (%%)");
	mvwvline(win_stat, 1, 20,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 21, "    Used (#)");
	mvwvline(win_stat, 1, 33,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 34, "    Free (#)");
	mvwvline(win_stat, 1, 46,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 47, "   Total (#)");
	mvwvline(win_stat, 1, 59,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 60, " Mem Used (KB)");
	mvwvline(win_stat, 1, 74,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 75, " Mem Free (KB)");
	mvwvline(win_stat, 1, 89,  ACS_VLINE, n_mempools + 1);
	mvwaddstrf(win_stat, 1, 90, " Mem Tot  (KB)");
	mvwvline(win_stat, 0, 104,  ACS_VLINE, n_mempools + 2);
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);

	for (uint16_t i = 0; i < n_mempools; ++i) {
		mvwaddstrf(win_stat, 2 + i, 0, "%4u", mempool_stats[i].port);
		mvwaddstrf(win_stat, 2 + i, 5, "%5u", mempool_stats[i].queue);
		mvwaddstrf(win_stat, 2 + i, 47, "%12zu", mempool_stats[i].size);
		mvwaddstrf(win_stat, 2 + i, 90, "%14zu", mempool_stats[i].size * MBUF_SIZE/1024);
	}

	display_unlock();
}

static void display_stats_rings(void);
static void stats_display_rings(void)
{
	int top = 1;
	int left = 11;

	display_lock();

	wattron(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));
	mvwaddstrf(win_stat, 0, 31, "Ring Information");
	/* Labels */
	mvwaddstrf(win_stat, top, left-5, "Ring");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);
	left += 12;

	mvwaddstrf(win_stat, top, left-5, "Port");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);

	left += 12;
	mvwaddstrf(win_stat, top, left-9, "Occup (%%)");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);

	left += 10;
	mvwaddstrf(win_stat, top, left-5, "Free");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);

	left += 10;
	mvwaddstrf(win_stat, top, left-5, "Size");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);

	left += 3;
	mvwaddstrf(win_stat, top, left-2, "SC");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);

	left += 3;
	mvwaddstrf(win_stat, top, left-2, "SP");
	mvwvline(win_stat, top, left, ACS_VLINE, rings_height+1);
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);

	top++;

	for (uint16_t i = 0; i < n_rings; ++i) {
		left = 0;
		mvwaddstrf(win_stat, top, left, "%s", ring_stats[i].ring->name);
		left += 12;
		for (uint32_t j = 0; j < ring_stats[i].nb_ports; j++) {
			mvwaddstrf(win_stat, top+j, left, "%s", ring_stats[i].port[j]->name);
		}

		left += 12 + 12 + 10 + 10;
		mvwaddstrf(win_stat, top, left, "%s", (ring_stats[i].ring->flags & RING_F_SC_DEQ) ? " y" : " n");
		left += 3;
		mvwaddstrf(win_stat, top, left, "%s", (ring_stats[i].ring->flags & RING_F_SP_ENQ) ? " y" : " n" );
		top += ring_stats[i].nb_ports ? ring_stats[i].nb_ports : 1;
	}

	display_stats_rings();

	display_unlock();
}

static void stats_display_eth_ports(void)
{
	char name[32];
	char *ptr;

	display_lock();
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));
	wattron(win_stat, A_BOLD);
	/* Labels */
	mvwaddstrf(win_stat, 0, 2,   "Port");
	mvwaddstrf(win_stat, 1, 0,   "  Nb");
	mvwvline(win_stat, 1, 4,  ACS_VLINE, nb_active_interfaces + 2);
	mvwaddstrf(win_stat, 1, 5,   "Name");
	mvwvline(win_stat, 1, 13,  ACS_VLINE, nb_active_interfaces + 2);
	mvwaddstrf(win_stat, 1, 14,   "Type");

	mvwvline(win_stat, 0, 21,  ACS_VLINE, nb_active_interfaces + 3);
	mvwaddstrf(win_stat, 0, 22, "                        Statistics per second");
	mvwaddstrf(win_stat, 1, 22, "no mbufs (#)");
	mvwvline(win_stat, 1, 34,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 35, "ierrors (#)");
	mvwvline(win_stat, 1, 46,  ACS_VLINE, nb_active_interfaces + 1);

	mvwaddstrf(win_stat, 1, 47, "oerrors (#)");
	mvwvline(win_stat, 1, 58,  ACS_VLINE, nb_active_interfaces + 1);

	mvwaddstrf(win_stat, 1, 47+12, "RX (Kpps)");
	mvwvline(win_stat, 1, 56+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 57+12, "TX (Kpps)");
	mvwvline(win_stat, 1, 66+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 67+12, "RX (Kbps)");
	mvwvline(win_stat, 1, 76+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 77+12, "TX (Kbps)");
	mvwvline(win_stat, 1, 86+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 87+12, "  RX (%%)");
	mvwvline(win_stat, 1, 95+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 96+12, "  TX (%%)");
	mvwvline(win_stat, 0, 104+12,  ACS_VLINE, nb_active_interfaces + 2);

	mvwaddstrf(win_stat, 0, 105+12, "                        Total Statistics");
	mvwaddstrf(win_stat, 1, 105+12, "           RX");
	mvwvline(win_stat, 1, 118+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 119+12, "           TX");
	mvwvline(win_stat, 1, 132+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 133+12, " no mbufs (#)");
	mvwvline(win_stat, 1, 146+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 147+12, "  ierrors (#)");
	mvwvline(win_stat, 1, 160+12,  ACS_VLINE, nb_active_interfaces + 1);
	mvwaddstrf(win_stat, 1, 161+12, "  oerrors (#)");
	mvwvline(win_stat, 0, 174+12,  ACS_VLINE, nb_active_interfaces + 2);
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);
	uint8_t count = 0;
	for (uint8_t i = 0; i < nb_interface; ++i) {
		if (prox_port_cfg[i].active) {
			mvwaddstrf(win_stat, 2 + count, 0, "%4u", i);
			mvwaddstrf(win_stat, 2 + count, 5, "%8s", prox_port_cfg[i].name);
			strncpy(name, prox_port_cfg[i].driver_name, 31);
			if ((ptr = strstr(name, "_pmd")) != NULL) {
				*ptr = '\x0';
			}
			if (strncmp(name, "rte_", 4) == 0) {
				mvwaddstrf(win_stat, 2 + count, 14, "%7s", name+4);
			} else {
				mvwaddstrf(win_stat, 2 + count, 14, "%7s", name);
			}
			count++;
		}
	}
	display_unlock();
}

static void stats_display_core_ports(unsigned chosen_page)
{
	display_lock();
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));
	if (msr_support) {
		col_offset = 20;
	}
	/* Sub-section separator lines */
	mvwvline(win_stat, 1,  4,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 13,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 33,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 53,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 63,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 73,  ACS_VLINE, nb_tasks_tot + 1);
	if (msr_support){
		mvwvline(win_stat, 1, 83,  ACS_VLINE, nb_tasks_tot + 1);
		mvwvline(win_stat, 1, 93,  ACS_VLINE, nb_tasks_tot + 1);
	}
	mvwvline(win_stat, 1, 98 + col_offset,  ACS_VLINE, nb_tasks_tot + 1);
	mvwvline(win_stat, 1, 113 + col_offset, ACS_VLINE, nb_tasks_tot + 1);
	if (cqm.supported) {
		mvwvline(win_stat, 1, 143 + col_offset, ACS_VLINE, nb_tasks_tot + 1);
	}

	wattron(win_stat, A_BOLD);
	/* Section separators (bold) */
	mvwvline(win_stat, 0, 23, ACS_VLINE, nb_tasks_tot + 2);
	mvwvline(win_stat, 0, 44, ACS_VLINE, nb_tasks_tot + 2);
	mvwvline(win_stat, 0, 83 + col_offset, ACS_VLINE, nb_tasks_tot + 2);
	if (cqm.supported) {
		mvwvline(win_stat, 0, 118 + col_offset, ACS_VLINE, nb_tasks_tot + 2);
	}

	/* Labels */
	mvwaddstrf(win_stat, 0, 8,   "Core/Task");
	mvwaddstrf(win_stat, 1, 0,   "  Nb");
	mvwaddstrf(win_stat, 1, 5,   "Name");
	mvwaddstrf(win_stat, 1, 14,  "Mode     ");

	mvwaddstrf(win_stat, 0, 24, " Port ID/Ring Name");
	mvwaddstrf(win_stat, 1, 24, "       RX");
	mvwaddstrf(win_stat, 1, 34, "        TX");

	if (!msr_support) {
		mvwaddstrf(win_stat, 0, 45, "        Statistics per second         ");
	}
	else {
		mvwaddstrf(win_stat, 0, 45, "                  Statistics per second                   ");
	}
	mvwaddstrf(win_stat, 1, 45, "%s", "Idle (%)");
	mvwaddstrf(win_stat, 1, 54, "   RX (k)");
	mvwaddstrf(win_stat, 1, 64, "   TX (k)");
	mvwaddstrf(win_stat, 1, 74, " Drop (k)");
	if (msr_support) {
		mvwaddstrf(win_stat, 1, 84, "      CPP");
		mvwaddstrf(win_stat, 1, 94, "Clk (GHz)");
	}

	mvwaddstrf(win_stat, 0, 84 + col_offset, "              Total Statistics             ");
	mvwaddstrf(win_stat, 1, 84 + col_offset, "            RX");
	mvwaddstrf(win_stat, 1, 99 + col_offset, "            TX");
	mvwaddstrf(win_stat, 1, 114 + col_offset, "          Drop");


	if (cqm.supported) {
		mvwaddstrf(win_stat, 0, 129 + col_offset, "  Cache QoS Monitoring  ");
		mvwaddstrf(win_stat, 1, 129 + col_offset, "occupancy (KB)");
		mvwaddstrf(win_stat, 1, 144 + col_offset, " fraction");
	}
	wattroff(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));

	uint16_t line_no = 0;
	uint32_t lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		const struct lcore_cfg *const cur_core = &lcore_cfg[lcore_id];

		for (uint8_t task_id = 0; task_id < cur_core->n_tasks_all; ++task_id) {
			const struct task_args *const targ = &cur_core->targs[task_id];

			if (line_no >= core_port_height * chosen_page && line_no < core_port_height * (chosen_page + 1)) {

				if (cur_core->n_tasks_run == 0) {
					wattron(win_stat, A_BOLD);
					wbkgdset(win_stat, COLOR_PAIR(RED_ON_NOTHING));
				}
				if (task_id == 0)
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 0, "%2u/", lcore_id);
				if (cur_core->n_tasks_run == 0) {
					wattroff(win_stat, A_BOLD);
					wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
				}

				// Core number and name
				if (!lconf_task_is_running(cur_core, task_id)) {
					wattron(win_stat, A_BOLD);
					wbkgdset(win_stat, COLOR_PAIR(RED_ON_NOTHING));
				}
				mvwaddstrf(win_stat, line_no % core_port_height + 2, 3, "%1u", task_id);

				if (!lconf_task_is_running(cur_core, task_id)) {
					wattroff(win_stat, A_BOLD);
					wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
				}
				mvwaddstrf(win_stat, line_no % core_port_height + 2, 5, "%s", task_id == 0 ? cur_core->name : "");
				mvwaddstrf(win_stat, line_no % core_port_height + 2, 14, "%.9s", targ->task_init->mode_str);
				if (strlen(targ->task_init->mode_str) > 9)
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 22 , "~");
				// Rx port information
				if (targ->nb_rxrings == 0) {
					uint32_t pos_offset = 24;

					for (int i = 0; i < targ->nb_rxports; i++) {
						wbkgdset(win_stat, link_color(targ->rx_ports[i]));
						pos_offset += mvwaddstrf(win_stat, line_no % core_port_height + 2, pos_offset, "%u", targ->rx_ports[i]);
						wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
						/* Space between ports */
						if (i != targ->nb_rxports -1)
							pos_offset++;
						if (pos_offset - 24 >= 9)
							break;
					}
				}
				uint8_t ring_id;
				for (ring_id = 0; ring_id < targ->nb_rxrings && ring_id < 9; ++ring_id) {
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 24 + ring_id, "%s", targ->rx_rings[ring_id]->name);
				}
				if (ring_id == 9 && ring_id < targ->nb_rxrings) {
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 24 + ring_id -1 , "~");
				}
				// Tx port information
				uint8_t pos = 34;
				for (uint8_t i = 0; i < targ->nb_txports; ++i) {
					if (i) {
						if (pos - 34 >= 9) {
							mvwaddstrf(win_stat, line_no % core_port_height + 2, pos -1, "~");
							break;
						}
						++pos;
					}

					if (pos - 34 >= 10) {
						mvwaddstrf(win_stat, line_no % core_port_height + 2, pos -1, "~");
						break;
					}
					wbkgdset(win_stat, link_color(targ->tx_port_queue[i].port));
					mvwaddstrf(win_stat, line_no % core_port_height + 2, pos, "%u", targ->tx_port_queue[i].port);
					wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
					pos++;
				}
				for (ring_id = 0; ring_id < targ->nb_txrings && ring_id < 10; ++ring_id) {
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 34 + ring_id, "%s", targ->tx_rings[ring_id]->name);
				}
				if (ring_id == 10 && ring_id < targ->nb_txrings)
					mvwaddstrf(win_stat, line_no % core_port_height + 2, 34 + ring_id-1, "~");
			}
			PROX_ASSERT(line_no < RTE_MAX_LCORE*MAX_TASKS_PER_CORE);
			core_port_ordered[line_no] = set_line_no(lcore_id, task_id);
			++line_no;
		}
	}
	display_unlock();
}

static void redraw_tabs(unsigned screen_id)
{
	const char* views[] = {
		"tasks",
		"ports",
		"mem  ",
		"lat  ",
		"ring ",
		"l4gen",
	};
	const size_t len = 5;

	for (unsigned i = 0; i < sizeof(views)/sizeof(views[0]); ++i) {
		if (i == screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(BLACK_ON_GREEN));

		mvwaddstrf(win_tabs, 0, i*(len + 3), "%u ", i+1);
		if (i != screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(GREEN_ON_NOTHING));
		mvwaddstrf(win_tabs, 0, i*(len + 3) + 2, "%s", views[i]);
		if (i != screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(NO_COLOR));
		if (i == screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(NO_COLOR));
	}

	wrefresh(win_tabs);
}

static void stats_display_layout(uint8_t in_place)
{
	uint8_t cur_stats_height;

	switch (screen_state.chosen_screen) {
	case 0:
		cur_stats_height = core_port_height;
		break;
	case 1:
		cur_stats_height = nb_active_interfaces;
		break;
	case 2:
		cur_stats_height = n_mempools;
		break;
	case 3:
		cur_stats_height = n_latency;
		break;
	case 4:
		cur_stats_height = rings_height;
		break;
	case 5:
		cur_stats_height = n_l4gen;
		break;
	default:
		cur_stats_height = core_port_height;
	}

	display_lock();
	if (!in_place) {
		// moving existing windows does not work
		delwin(win_txt);
		delwin(win_general);
		delwin(win_title);
		delwin(win_tabs);
		delwin(win_cmd);
		delwin(win_txt);
		delwin(win_help);

		clear();
	}

	if (!in_place) {
		win_stat = create_subwindow(cur_stats_height + 2, 0, 4, 0);
		win_tabs = create_subwindow(1, 0, 1, 0);
		win_general = create_subwindow(2, 0, 2, 0);
		win_title = create_subwindow(1, 0, 0, 0);
		win_cmd = create_subwindow(1, 0, cur_stats_height + 2 + 4,  0);
		win_txt_height = LINES - cur_stats_height - 2 - 3 - 3;
		win_txt = create_subwindow(win_txt_height, 0, cur_stats_height + 4 + 3, 0);
		win_help = create_subwindow(1, 0, LINES - 1, 0);
	}
	/* Title box */
	wbkgd(win_title, COLOR_PAIR(BLACK_ON_GREEN));

	char title_str[128];

	redraw_tabs(screen_state.chosen_screen);
	snprintf(title_str, sizeof(title_str), "%s %s: %s", PROGRAM_NAME, VERSION_STR, prox_cfg.name);
	title_len = strlen(title_str);
	mvwaddstrf(win_title, 0, (COLS - title_len)/2, "%s", title_str);

	wattron(win_general, A_BOLD);
	wbkgdset(win_general, COLOR_PAIR(MAGENTA_ON_NOTHING));
	mvwaddstrf(win_general, 0, 9, "rx:         tx:          diff:                     rx:          tx:                        %%:");
	mvwaddstrf(win_general, 1, 9, "rx:         tx:          err:                      rx:          tx:          err:          %%:");
	wbkgdset(win_general, COLOR_PAIR(NO_COLOR));


	wbkgdset(win_general, COLOR_PAIR(BLUE_ON_NOTHING));
	mvwaddstrf(win_general, 0, 0, "Host pps ");
	mvwaddstrf(win_general, 1, 0, "NICs pps ");

	wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
	mvwaddstrf(win_general, 0, 56, "avg");
	mvwaddstrf(win_general, 1, 56, "avg");
	wbkgdset(win_general, COLOR_PAIR(NO_COLOR));
	wattroff(win_general, A_BOLD);

	/* Command line */
	wbkgd(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
	idlok(win_cmd, FALSE);
	/* Move cursor at insertion point */
	leaveok(win_cmd, FALSE);

	/* Help/status bar */
	wbkgd(win_help, COLOR_PAIR(BLACK_ON_WHITE));
	werase(win_help);
	waddstr(win_help, "Enter 'help' or command, <ESC> or 'quit' to exit, F1-F5 or 1-5 to switch screens and 0 to reset stats");
	wrefresh(win_help);
	mvwin(win_help, LINES - 1, 0);
	/* Log window */
	idlok(win_txt, FALSE);
	/* Get scrolling */
	scrollok(win_txt, TRUE);

	/* Leave cursor where it was */
	leaveok(win_txt, TRUE);

	wbkgd(win_txt, COLOR_PAIR(BLACK_ON_CYAN));
	wrefresh(win_txt);

	/* Draw everything to the screen */
	refresh();
	display_unlock();


	switch (screen_state.chosen_screen) {
	case 0:
		stats_display_core_ports(screen_state.chosen_page);
		break;
	case 1:
		stats_display_eth_ports();
		break;
	case 2:
		stats_display_mempools();
		break;
	case 3:
		stats_display_latency();
		break;
	case 4:
		stats_display_rings();
		break;
	case 5:
		stats_display_l4gen();
		break;
	}

	refresh_cmd_win();
	display_stats();
}

void display_end(void)
{
	pthread_mutex_destroy(&disp_mtx);

	if (scr != NULL) {
		endwin();
	}
}

static void update_global_stats(uint8_t task_id, struct global_stats *global_stats)
{
	const struct port_stats *port_stats = core_ports[task_id].port_stats;
	const uint64_t delta_t = port_stats->tsc[last_stat] - port_stats->tsc[!last_stat];
	uint64_t diff;

	if (core_ports[task_id].flags & PORT_STATS_RX) {
		diff = port_stats->rx_pkt_count[last_stat] - port_stats->rx_pkt_count[!last_stat];
		global_stats->rx_tot += diff;
		global_stats->rx_pps += diff * tsc_hz / delta_t;
	}

	if (core_ports[task_id].flags & PORT_STATS_TX) {
		diff = port_stats->tx_pkt_count[last_stat] - port_stats->tx_pkt_count[!last_stat];
		global_stats->tx_tot += diff;
		global_stats->tx_pps += diff * tsc_hz / delta_t;
	}

	global_stats->last_tsc = RTE_MAX(global_stats->last_tsc, port_stats->tsc[last_stat]);
}

static void display_core_port_stats(uint8_t task_id)
{
	const int line_no = task_id % core_port_height;

	const struct port_stats *port_stats = core_port_ordered[task_id]->port_stats;

	/* delta_t in units of clock ticks */
	uint64_t delta_t = port_stats->tsc[last_stat] - port_stats->tsc[!last_stat];

	uint64_t empty_cycles = port_stats->empty_cycles[last_stat] - port_stats->empty_cycles[!last_stat];

	if (empty_cycles > delta_t) {
		empty_cycles = 10000;
	}
	else {
		empty_cycles = empty_cycles * 10000 / delta_t;
	}

	// empty_cycles has 2 digits after point, (usefull when only a very small idle time)
	mvwaddstrf(win_stat, line_no + 2, 47, "%3lu.%02lu", empty_cycles / 100, empty_cycles % 100);

	// Display per second statistics in Kpps unit
	delta_t *= 1000;

	uint64_t nb_pkt;
	nb_pkt = (port_stats->rx_pkt_count[last_stat] - port_stats->rx_pkt_count[!last_stat]) * tsc_hz;
	if (nb_pkt && nb_pkt < delta_t) {
		mvwaddstrf(win_stat, line_no + 2, 54, "    0.%03lu", nb_pkt * 1000 / delta_t);
	}
	else {
		mvwaddstrf(win_stat, line_no + 2, 54, "%9lu", nb_pkt / delta_t);
	}

	nb_pkt = (port_stats->tx_pkt_count[last_stat] - port_stats->tx_pkt_count[!last_stat]) * tsc_hz;
	if (nb_pkt && nb_pkt < delta_t) {
		mvwaddstrf(win_stat, line_no + 2, 64, "    0.%03lu", nb_pkt * 1000 / delta_t);
	}
	else {
		mvwaddstrf(win_stat, line_no + 2, 64, "%9lu", nb_pkt / delta_t);
	}

	nb_pkt = (port_stats->tx_pkt_drop[last_stat] - port_stats->tx_pkt_drop[!last_stat]) * tsc_hz;
	if (nb_pkt && nb_pkt < delta_t) {
		mvwaddstrf(win_stat, line_no + 2, 74, "    0.%03lu", nb_pkt * 1000 / delta_t);
	}
	else {
		mvwaddstrf(win_stat, line_no + 2, 74, "%9lu", nb_pkt / delta_t);
	}

	if (msr_support) {
		uint8_t lcore_id = core_port_ordered[task_id]->lcore_id;
		uint64_t adiff = lcore_stats[lcore_id].afreq[last_stat] - lcore_stats[lcore_id].afreq[!last_stat];
		uint64_t mdiff = lcore_stats[lcore_id].mfreq[last_stat] - lcore_stats[lcore_id].mfreq[!last_stat];

		if ((port_stats->rx_pkt_count[last_stat] - port_stats->rx_pkt_count[!last_stat]) && mdiff) {
			mvwaddstrf(win_stat, line_no + 2, 84, "%9lu", delta_t/(port_stats->rx_pkt_count[last_stat] - port_stats->rx_pkt_count[!last_stat])*adiff/mdiff/1000);
		}
		else {
			mvwaddstrf(win_stat, line_no + 2, 84, "%9lu", 0L);
		}

		uint64_t mhz;
		if (mdiff)
			mhz = tsc_hz*adiff/mdiff/1000000;
		else
			mhz = 0;

		mvwaddstrf(win_stat, line_no + 2, 94, "%5lu.%03lu", mhz/1000, mhz%1000);
	}

	// Total statistics (packets)
	mvwaddstrf(win_stat, line_no + 2, 84 + col_offset, "%14lu", port_stats->tot_rx_pkt_count);
	mvwaddstrf(win_stat, line_no + 2, 99 + col_offset, "%14lu", port_stats->tot_tx_pkt_count);
	mvwaddstrf(win_stat, line_no + 2, 114 + col_offset, "%14lu", port_stats->tot_tx_pkt_drop);

	if (cqm.supported) {
		uint8_t lcore_id = core_port_ordered[task_id]->lcore_id;
		mvwaddstrf(win_stat, line_no + 2, 129 + col_offset, "%14lu", lcore_stats[lcore_id].cqm_bytes >> 10);
		mvwaddstrf(win_stat, line_no + 2, 144 + col_offset, "%6lu.%02lu", lcore_stats[lcore_id].cqm_fraction/100, lcore_stats[lcore_id].cqm_fraction%100);
	}
}

void stats_init(void)
{
	init_active_core_ports();
	init_active_eth_ports();
	init_mempools();
	init_latency();
	init_l4gen();
	init_rings();

	if ((msr_support = !msr_init()) == 0) {
		plog_warn("Failed to open msr pseudo-file (missing msr kernel module?)\n");
	}

	if (cqm_is_supported()) {
		if (!msr_support) {
			plog_warn("CPU supports CQM but msr module not loaded. Disabling CQM stats.\n");
		}
		else {
			if (0 != cqm_get_features(&cqm.features)) {
				plog_warn("Failed to get CQM features\n");
				cqm.supported = 0;
			}
			else {
				cqm_init_stat_core(rte_lcore_id());
				cqm.supported = 1;
			}

			for (uint8_t i = 0; i < RTE_MAX_LCORE; ++i) {
				cqm_assoc(i, lcore_stats[i].rmid);
			}
		}
	}
#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0) && RTE_VER_PATCH_RELEASE >= 1
	int i;
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if ((!strcmp(prox_port_cfg[port_id].driver_name, "rte_ixgbe_pmd")) && (prox_port_cfg[port_id].active)) {
			num_ixgbe_xstats = rte_eth_xstats_get(port_id, NULL, 0);
			eth_xstats = rte_zmalloc_socket(NULL, num_ixgbe_xstats*sizeof(struct rte_eth_xstats), RTE_CACHE_LINE_SIZE, prox_port_cfg[port_id].socket);
			PROX_PANIC(eth_xstats == NULL, "Error allocating memory for xstats");
			num_ixgbe_xstats = rte_eth_xstats_get(port_id, eth_xstats, num_ixgbe_xstats);
			for (i=0; i<num_ixgbe_xstats; i++) {
				if (strcmp(eth_xstats[i].name, "total octets received") == 0) {
					xstat_tor_offset = i;
					break;
				}
			}
			for (i=0; i<num_ixgbe_xstats; i++) {
				if (strcmp(eth_xstats[i].name, "total packets received") == 0) {
					xstat_tpr_offset = i;
					break;
				}
			}
			break;
		}
	}
	if ((xstat_tor_offset == -1) || (xstat_tpr_offset == -1) || (num_ixgbe_xstats == 0) || (eth_xstats == NULL)) {
		plog_warn("Failed to initialize xstat, running without xstats\n");
		num_ixgbe_xstats = 0;
	}
#endif
}

static void nic_read_stats(uint8_t port_id)
{
	unsigned is_ixgbe = (0 == strcmp(prox_port_cfg[port_id].driver_name, "rte_ixgbe_pmd"));

	struct eth_stats* stats = &eth_stats[port_id];

#ifdef PROX_HW_DIRECT_STATS
	if (is_ixgbe) {
		ixgbe_read_stats(port_id, stats, last_stat);
		return;
	}
#endif

	struct rte_eth_stats eth_stat;
	rte_eth_stats_get(port_id, &eth_stat);
	stats->tsc[last_stat] = rte_rdtsc();
	stats->no_mbufs[last_stat] = eth_stat.rx_nombuf;
	stats->ierrors[last_stat] = eth_stat.ierrors;
	stats->oerrors[last_stat] = eth_stat.oerrors;
	stats->rx_bytes[last_stat] = eth_stat.ibytes;
	if (is_ixgbe) {
#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0) && RTE_VER_PATCH_RELEASE >= 1
		if (num_ixgbe_xstats) {
			rte_eth_xstats_get(port_id, eth_xstats, num_ixgbe_xstats);
			stats->rx_tot[last_stat] = eth_xstats[xstat_tpr_offset].value;
			stats->rx_bytes[last_stat] = eth_xstats[xstat_tor_offset].value;
		} else
#endif
		{
			stats->rx_tot[last_stat] = eth_stat.ipackets + eth_stat.ierrors;
			// If CRC is stripped on ixgbe, then CRC bytes not counted in stats - add them back
			if (prox_port_cfg[port_id].port_conf.rxmode.hw_strip_crc == 1)
				stats->rx_bytes[last_stat] = eth_stat.ibytes + 4 * eth_stat.ipackets;
		}
	} else {
		stats->rx_tot[last_stat] = eth_stat.ipackets;
	}
	stats->tx_tot[last_stat] = eth_stat.opackets;
	stats->tx_bytes[last_stat] = eth_stat.obytes;
}

static void nic_stats_reset(uint8_t port_id)
{
	rte_eth_stats_reset(port_id);
}

void stats_update(void)
{
	/* Keep track of last 2 measurements. */
	last_stat = !last_stat;

	if (nb_tasks_tot == 0) {
		return;
	}

	for (uint8_t task_id = 0; task_id < nb_tasks_tot; ++task_id) {
		struct task_stats *stats = core_ports[task_id].stats;
		struct port_stats *cur_port_stats = core_ports[task_id].port_stats;

		/* Read TX first and RX second, in order to prevent displaying
		   a negative packet loss. Depending on the configuration
		   (when forwarding, for example), TX might be bigger than RX. */
		cur_port_stats->tsc[last_stat] = rte_rdtsc();
		cur_port_stats->tx_pkt_count[last_stat] = stats->tx_pkt_count;
		cur_port_stats->tx_pkt_drop[last_stat]  = stats->tx_pkt_drop;
		cur_port_stats->rx_pkt_count[last_stat] = stats->rx_pkt_count;
		cur_port_stats->empty_cycles[last_stat] = stats->empty_cycles;
	}

	if (msr_support) {
		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			if (lcore_stats[lcore_id].rmid) {
				cqm_read_ctr(&lcore_stats[lcore_id].cqm_data, lcore_stats[lcore_id].rmid);
			}
			msr_read(&lcore_stats[lcore_id].afreq[last_stat], lcore_id, 0xe8);
			msr_read(&lcore_stats[lcore_id].mfreq[last_stat], lcore_id, 0xe7);
		}
	}

	uint64_t cqm_data_core0 = 0;
	cqm_read_ctr(&cqm_data_core0, 0);

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			nic_read_stats(port_id);
		}
	}

	for (uint8_t mp_id = 0; mp_id < n_mempools; ++mp_id) {
		/* Note: The function free_count returns the number of used entries. */
		mempool_stats[mp_id].free = rte_mempool_count(mempool_stats[mp_id].pool);
	}

	for (uint16_t i = 0; i < n_latency; ++i) {
		struct task_lat *task_lat = task_lats[i].task;

		if (task_lat->use_lt != task_lat->using_lt)
			continue;

		struct lat_test *lat_test = &task_lat->lt[!task_lat->using_lt];
		if (lat_test->tot_pkts) {
			memcpy(&lat_stats[i], lat_test, sizeof(struct lat_test));
		}

		lat_test->tot_lat = 0;
		lat_test->var_lat = 0;
		lat_test->tot_pkts = 0;
#ifndef NO_LATENCY_PER_PACKET
		lat_test->cur_pkt = 0;
#endif
		lat_test->max_lat = 0;
		lat_test->min_lat = -1;
		memset(lat_test->buckets, 0, sizeof(lat_test->buckets));
		task_lat->use_lt = !task_lat->using_lt;
	}

	for (uint16_t i = 0; i < n_l4gen; ++i) {
		struct task_l4gen *task_l4gen = task_l4_stats[i].task;

		task_l4_stats[i].tsc[last_stat] = rte_rdtsc();
		task_l4_stats[i].l4_stats[last_stat] = task_l4gen->l4_stats;
	}

	for (uint8_t task_id = 0; task_id < nb_tasks_tot; ++task_id) {
		struct port_stats *cur_port_stats = core_ports[task_id].port_stats;

		/* no total stats for empty loops */
		cur_port_stats->tot_rx_pkt_count  += cur_port_stats->rx_pkt_count[last_stat] - cur_port_stats->rx_pkt_count[!last_stat];
		cur_port_stats->tot_tx_pkt_count  += cur_port_stats->tx_pkt_count[last_stat] - cur_port_stats->tx_pkt_count[!last_stat];
		cur_port_stats->tot_tx_pkt_drop   += cur_port_stats->tx_pkt_drop[last_stat] - cur_port_stats->tx_pkt_drop[!last_stat];
	}

	for (uint16_t r_id = 0; r_id < n_rings; ++r_id) {
		ring_stats[r_id].free = rte_ring_free_count(ring_stats[r_id].ring);
	}

	global_stats.tx_pps = 0;
	global_stats.rx_pps = 0;
	for (uint8_t task_id = 0; task_id < nb_tasks_tot; ++task_id) {
		update_global_stats(task_id, &global_stats);
	}

	if (cqm.supported) {
		// update CQM stats (calucate fraction and bytes reported) */
		uint64_t total_monitored = cqm_data_core0*cqm.features.upscaling_factor;

		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			if (lcore_stats[lcore_id].rmid) {
				lcore_stats[lcore_id].cqm_bytes = lcore_stats[lcore_id].cqm_data*cqm.features.upscaling_factor;
				total_monitored += lcore_stats[lcore_id].cqm_bytes;
			}
		}
		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			if (lcore_stats[lcore_id].rmid && total_monitored) {
				lcore_stats[lcore_id].cqm_fraction = lcore_stats[lcore_id].cqm_bytes*10000/total_monitored;
			}
			else
				lcore_stats[lcore_id].cqm_fraction = 0;
		}
	}

	if (global_stats.last_tsc > global_stats.avg_start) {
		if (!global_stats.started_avg) {
			global_stats.rx_tot_beg = global_stats.rx_tot;
			global_stats.tx_tot_beg = global_stats.tx_tot;
			global_stats.started_avg = 1;
			global_stats.avg_start = global_stats.last_tsc;

			global_stats.nic_rx_tot_beg = 0;
			global_stats.nic_tx_tot_beg = 0;
			global_stats.nic_ierrors_tot_beg = 0;
			/* Store the NIC stats */
			for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
				if (prox_port_cfg[port_id].active) {
					global_stats.nic_ierrors_tot_beg += eth_stats[port_id].ierrors[last_stat];
					global_stats.nic_rx_tot_beg += eth_stats[port_id].rx_tot[last_stat];
					global_stats.nic_tx_tot_beg += eth_stats[port_id].tx_tot[last_stat];
				}
			}
		}
		else {
			uint64_t avg_tsc_passed = global_stats.last_tsc - global_stats.avg_start;
			uint64_t thresh = ((uint64_t)-1)/tsc_hz;
			/* Use only precise arithmetic when there is no overflow */
			if (global_stats.rx_tot - global_stats.rx_tot_beg < thresh) {
				global_stats.rx_avg = (global_stats.rx_tot - global_stats.rx_tot_beg)*tsc_hz/avg_tsc_passed;
			}
			else {
				global_stats.rx_avg = (global_stats.rx_tot - global_stats.rx_tot_beg)/(avg_tsc_passed/tsc_hz);
			}

			if (global_stats.tx_tot - global_stats.tx_tot_beg < thresh) {
				global_stats.tx_avg = (global_stats.tx_tot - global_stats.tx_tot_beg)*tsc_hz/avg_tsc_passed;
			}
			else {
				global_stats.tx_avg = (global_stats.tx_tot - global_stats.tx_tot_beg)/(avg_tsc_passed/tsc_hz);
			}
		}
	}
}

static void pps_print(WINDOW *dst_scr, int y, int x, uint64_t val, int is_blue)
{
	uint64_t rx_pps_disp = val;
	uint64_t rx_pps_disp_frac = 0;
	uint32_t ten_pow3 = 0;
	static const char *units = " KMG";
	char rx_unit = ' ';

	while (rx_pps_disp > 1000) {
		rx_pps_disp /= 1000;
		rx_pps_disp_frac = (val - rx_pps_disp*1000) / 10;
		val /= 1000;
		ten_pow3++;
	}

	if (ten_pow3 >= strlen(units)) {
		wbkgdset(dst_scr, COLOR_PAIR(RED_ON_NOTHING));
		mvwaddstrf(dst_scr, y, x, "---");
		wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
		return;
	}

	rx_unit = units[ten_pow3];

	wattron(dst_scr, A_BOLD);
	if (is_blue) {
		wbkgdset(dst_scr, COLOR_PAIR(BLUE_ON_NOTHING));
	}
	else
		wbkgdset(dst_scr, COLOR_PAIR(CYAN_ON_NOTHING));

	mvwaddstrf(dst_scr, y, x, "%3lu", rx_pps_disp);
	if (rx_unit != ' ') {
		mvwaddstrf(dst_scr, y, x + 3, ".%02lu", rx_pps_disp_frac);
		wattroff(dst_scr, A_BOLD);
		wbkgdset(dst_scr, COLOR_PAIR(WHITE_ON_NOTHING));
		wattron(dst_scr, A_BOLD);
		mvwaddstrf(dst_scr, y, x + 6, "%c", rx_unit);
		wattroff(dst_scr, A_BOLD);
		wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
	}
	else {
		mvwaddstrf(dst_scr, y, x + 3, "    ");
	}
	wattroff(dst_scr, A_BOLD);
	wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
}

static void display_stats_general(void)
{
	/* moment when stats were gathered. */
	uint64_t cur_tsc = global_stats.last_tsc;
	uint64_t up_time = (cur_tsc - beg_tsc)/tsc_hz;
	uint64_t up_time2 = (cur_tsc - start_tsc)/tsc_hz;
	uint64_t rem_time = -1;
	char title_str[128] = {0};

	if (end_tsc)
		rem_time = end_tsc > cur_tsc? (end_tsc - cur_tsc)/tsc_hz : 0;

	if (up_time != up_time2) {
		if (end_tsc)
			snprintf(title_str, sizeof(title_str), "%5lu (%lu) up, %lu rem", up_time, up_time2, rem_time);
		else
			snprintf(title_str, sizeof(title_str), "%5lu (%lu) up", up_time, up_time2);
	}
	else {
		if (end_tsc)
			snprintf(title_str, sizeof(title_str), "%5lu up, %lu rem", up_time, rem_time);
		else
			snprintf(title_str, sizeof(title_str), "%5lu up", up_time);
	}

	/* Only print up time information if there is enough space */
	if ((int)((COLS + title_len)/2 + strlen(title_str) + 1) < COLS) {
		mvwaddstrf(win_title, 0, COLS - strlen(title_str), "%s", title_str);
		wrefresh(win_title);
	}

	/* Host: RX, TX, Diff */
	pps_print(win_general, 0, 12, global_stats.rx_pps, 1);
	pps_print(win_general, 0, 25, global_stats.tx_pps, 1);

	uint64_t diff = 0;
	if (global_stats.rx_pps > global_stats.tx_pps)
		diff = global_stats.rx_pps - global_stats.tx_pps;

	pps_print(win_general, 0, 40, diff, 1);

	if (global_stats.started_avg) {
		pps_print(win_general, 0, 64, global_stats.rx_avg, 0);
		pps_print(win_general, 0, 77, global_stats.tx_avg, 0);
	}

	wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
	wattron(win_general, A_BOLD);
	mvwaddstrf(win_general, 0, 103, "%6.2f", global_stats.tx_pps > global_stats.rx_pps?
		   100 : global_stats.tx_pps * 100.0 / global_stats.rx_pps);
	wattroff(win_general, A_BOLD);
	wbkgdset(win_general, COLOR_PAIR(NO_COLOR));

	uint64_t rx_diff_all = 0, tx_diff_all = 0, ierrors_diff_all = 0;
	uint64_t rx_tot_all = 0, tx_tot_all = 0, ierrors_tot_all = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			uint64_t delta_t = eth_stats[port_id].tsc[last_stat] - eth_stats[port_id].tsc[!last_stat];
			if (!delta_t)
				continue;
			uint64_t thresh = UINT64_MAX/tsc_hz;

			uint64_t rx_diff = eth_stats[port_id].rx_tot[last_stat] - eth_stats[port_id].rx_tot[!last_stat];
			uint64_t tx_diff = eth_stats[port_id].tx_tot[last_stat] - eth_stats[port_id].tx_tot[!last_stat];

			uint64_t errors_diff = eth_stats[port_id].ierrors[last_stat] - eth_stats[port_id].ierrors[!last_stat];
			ierrors_tot_all += eth_stats[port_id].ierrors[last_stat];
			rx_tot_all += eth_stats[port_id].rx_tot[last_stat];
			tx_tot_all += eth_stats[port_id].tx_tot[last_stat];

			if (rx_diff < thresh) {
				rx_diff_all += rx_diff*tsc_hz/delta_t;
			}
			else {
				if (delta_t >= tsc_hz)
					rx_diff_all += rx_diff/(delta_t/tsc_hz);
			}

			if (tx_diff < thresh) {
				tx_diff_all += tx_diff*tsc_hz/delta_t;
			}
			else {
				if (delta_t >= tsc_hz)
					tx_diff_all += tx_diff/(delta_t/tsc_hz);
			}
			if (errors_diff < thresh) {
				ierrors_diff_all += errors_diff*tsc_hz/delta_t;
			}
			else {
				if (delta_t >= tsc_hz)
					ierrors_diff_all += errors_diff/(delta_t/tsc_hz);
			}
		}
	}

	/* NIC: RX, TX, Diff */
	pps_print(win_general, 1, 12, rx_diff_all, 1);
	pps_print(win_general, 1, 25, tx_diff_all, 1);
	pps_print(win_general, 1, 40, ierrors_diff_all, 1);

	if (up_time2 && global_stats.started_avg && global_stats.avg_start < cur_tsc) {
		uint64_t time_offset = global_stats.avg_start;
		rx_tot_all -= global_stats.nic_rx_tot_beg;
		tx_tot_all -= global_stats.nic_tx_tot_beg;
		ierrors_tot_all -= global_stats.nic_ierrors_tot_beg;
		uint64_t tresh = UINT64_MAX/tsc_hz;

		if (rx_tot_all < tresh) {
			pps_print(win_general, 1, 64, rx_tot_all*tsc_hz/(cur_tsc - time_offset), 0);
		}
		else if (cur_tsc - time_offset > tsc_hz) {
			pps_print(win_general, 1, 64, rx_tot_all/((cur_tsc - time_offset)/tsc_hz), 0);
		}
		else {
			pps_print(win_general, 1, 64, UINT64_MAX, 0);
		}

		if (tx_tot_all < tresh) {
			pps_print(win_general, 1, 77, tx_tot_all*tsc_hz/(cur_tsc - time_offset), 0);
		}
		else if (cur_tsc - time_offset > tsc_hz) {
			pps_print(win_general, 1, 77, tx_tot_all/((cur_tsc - time_offset)/tsc_hz), 0);
		}
		else {
			pps_print(win_general, 1, 77, UINT64_MAX, 0);
		}

		if (ierrors_tot_all < tresh) {
			pps_print(win_general, 1, 91, ierrors_tot_all*tsc_hz/(cur_tsc - time_offset), 0);
		}
		else if (cur_tsc - time_offset > tsc_hz) {
			pps_print(win_general, 1, 91, ierrors_tot_all/((cur_tsc - time_offset)/tsc_hz), 0);
		}
		else {
			pps_print(win_general, 1, 91, UINT64_MAX, 0);
		}

		wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
		wattron(win_general, A_BOLD);
		uint64_t nics_in = ierrors_tot_all + rx_tot_all;
		uint64_t nics_out = tx_tot_all;
		mvwaddstrf(win_general, 1, 103, "%6.2f", nics_out > nics_in?
			   100 : nics_out * 100.0 / nics_in);
		wattron(win_general, A_BOLD);
		wbkgdset(win_general, COLOR_PAIR(NO_COLOR));
	}

	wrefresh(win_general);

	wattroff(win_stat, A_BOLD);
}

static void display_stats_core_ports(void)
{
	unsigned chosen_page = screen_state.chosen_page;

	for (uint8_t active_core = core_port_height * chosen_page; active_core < nb_tasks_tot && active_core < core_port_height * (chosen_page + 1); ++active_core) {
		display_core_port_stats(active_core);
	}
}

int stats_port(uint8_t port_id, struct get_port_stats *ps)
{
	if (!prox_port_cfg[port_id].active)
		return -1;

	ps->no_mbufs_diff = eth_stats[port_id].no_mbufs[last_stat] - eth_stats[port_id].no_mbufs[!last_stat];
	ps->ierrors_diff = eth_stats[port_id].ierrors[last_stat] - eth_stats[port_id].ierrors[!last_stat];
	ps->rx_bytes_diff = eth_stats[port_id].rx_bytes[last_stat] - eth_stats[port_id].rx_bytes[!last_stat];
	ps->tx_bytes_diff = eth_stats[port_id].tx_bytes[last_stat] - eth_stats[port_id].tx_bytes[!last_stat];
	ps->rx_pkts_diff = eth_stats[port_id].rx_tot[last_stat] - eth_stats[port_id].rx_tot[!last_stat];
	ps->tx_pkts_diff = eth_stats[port_id].tx_tot[last_stat] - eth_stats[port_id].tx_tot[!last_stat];

	ps->rx_tot = eth_stats[port_id].rx_tot[last_stat];
	ps->tx_tot = eth_stats[port_id].tx_tot[last_stat];
	ps->no_mbufs_tot = eth_stats[port_id].no_mbufs[last_stat];
	ps->ierrors_tot = eth_stats[port_id].ierrors[last_stat];

	ps->last_tsc = eth_stats[port_id].tsc[last_stat];
	ps->prev_tsc = eth_stats[port_id].tsc[!last_stat];

	return 0;
}

static void display_stats_eth_ports(void)
{
	uint8_t count = 0;
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			uint64_t delta_t = eth_stats[port_id].tsc[last_stat] - eth_stats[port_id].tsc[!last_stat];
			uint64_t thresh = UINT64_MAX/tsc_hz;

			uint64_t no_mbufs_diff = eth_stats[port_id].no_mbufs[last_stat] - eth_stats[port_id].no_mbufs[!last_stat];
			uint64_t ierrors_diff = eth_stats[port_id].ierrors[last_stat] - eth_stats[port_id].ierrors[!last_stat];
			uint64_t oerrors_diff = eth_stats[port_id].oerrors[last_stat] - eth_stats[port_id].oerrors[!last_stat];

			uint64_t rx_bytes_diff = eth_stats[port_id].rx_bytes[last_stat] - eth_stats[port_id].rx_bytes[!last_stat];
			uint64_t tx_bytes_diff = eth_stats[port_id].tx_bytes[last_stat] - eth_stats[port_id].tx_bytes[!last_stat];

			uint64_t rx_diff = eth_stats[port_id].rx_tot[last_stat] - eth_stats[port_id].rx_tot[!last_stat];
			uint64_t tx_diff = eth_stats[port_id].tx_tot[last_stat] - eth_stats[port_id].tx_tot[!last_stat];
			uint64_t rx_percent = rx_bytes_diff + 20 * rx_diff;
			uint64_t tx_percent = tx_bytes_diff + 20 * tx_diff;

			if (num_ixgbe_xstats == 0 && !strcmp(prox_port_cfg[port_id].driver_name, "rte_ixgbe_pmd")) {
				// On ixgbe, the rx_bytes counts bytes received by Host while rx_tot counts rx pkts by NIC
				// => do not take ierrors into account...and report only % received by host
				rx_percent -= ierrors_diff * 20;
			}

			if (no_mbufs_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 22, "%12lu", no_mbufs_diff*tsc_hz/delta_t);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 22, "%12lu", no_mbufs_diff/(delta_t/tsc_hz));
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 22, "%12s", "---");
			}

			if (ierrors_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 35, "%11lu", ierrors_diff*tsc_hz/delta_t);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 35, "%11lu", ierrors_diff/(delta_t/tsc_hz));
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 35, "%11s", "---");
			}

			if (oerrors_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 47, "%11lu", oerrors_diff*tsc_hz/delta_t);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 47, "%11lu", oerrors_diff/(delta_t/tsc_hz));
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 47, "%11s", "---");
			}

			if (rx_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 47 + 12, "%9lu", (rx_diff*tsc_hz/delta_t)/1000);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 47 + 12, "%9lu", (rx_diff/(delta_t/tsc_hz))/1000);
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 47 + 12, "%9s", "---");
			}

			if (tx_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 57 + 12, "%9lu", (tx_diff*tsc_hz/delta_t)/1000);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 57 + 12, "%9lu", (tx_diff/(delta_t/tsc_hz))/1000);
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 57 + 12, "%9s", "---");
			}

			if (rx_bytes_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 67 + 12, "%9lu", (rx_bytes_diff*tsc_hz/delta_t)/125);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 67 + 12, "%9lu", (rx_bytes_diff/(delta_t/tsc_hz))/125);
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 67 + 12 , "%9s", "---");
			}

			if (tx_bytes_diff < thresh) {
				mvwaddstrf(win_stat, 2 + count, 77 + 12, "%9lu", (tx_bytes_diff*tsc_hz/delta_t)/125);
			}
			else if (delta_t > tsc_hz) {
				mvwaddstrf(win_stat, 2 + count, 77 + 12, "%9lu", (tx_bytes_diff/(delta_t/tsc_hz))/125);
			}
			else {
				mvwaddstrf(win_stat, 2 + count, 77 + 12, "%9s", "---");
			}


			if (rx_percent) {
				if (rx_percent < thresh) {
					mvwaddstrf(win_stat, 2 + count, 87 + 12, "%3lu.%04lu", rx_percent * tsc_hz / delta_t / 12500000, (rx_percent * tsc_hz / delta_t / 1250) % 10000);
				}
				else {
					mvwaddstrf(win_stat, 2 + count, 87 + 12, "%3lu.%04lu", rx_percent / (delta_t /tsc_hz)/ 12500000, (rx_percent /(delta_t /tsc_hz) / 1250) % 10000);
				}
			}
			else
				mvwaddstrf(win_stat, 2 + count, 87 + 12, "%8u", 0);

			if (tx_percent) {
				if (tx_percent < thresh) {
					mvwaddstrf(win_stat, 2 + count, 96 + 12, "%3lu.%04lu", tx_percent * tsc_hz / delta_t / 12500000, (tx_percent * tsc_hz / delta_t / 1250) % 10000);
				}
				else {
					mvwaddstrf(win_stat, 2 + count, 96 + 12, "%3lu.%04lu", tx_percent / (delta_t /tsc_hz)/ 12500000, (tx_percent /(delta_t /tsc_hz) / 1250) % 10000);
				}
			}
			else
				mvwaddstrf(win_stat, 2 + count, 96 + 12, "%8u", 0);
			mvwaddstrf(win_stat, 2 + count, 105 + 12, "%13lu", eth_stats[port_id].rx_tot[last_stat]);
			mvwaddstrf(win_stat, 2 + count, 119 + 12, "%13lu", eth_stats[port_id].tx_tot[last_stat]);

			mvwaddstrf(win_stat, 2 + count, 133 + 12, "%13lu", eth_stats[port_id].no_mbufs[last_stat]);
			mvwaddstrf(win_stat, 2 + count, 147 + 12, "%13lu", eth_stats[port_id].ierrors[last_stat]);
			mvwaddstrf(win_stat, 2 + count, 173, "%13lu", eth_stats[port_id].oerrors[last_stat]);
			count++;
		}
	}
}

static void display_stats_mempools(void)
{
	for (uint16_t i = 0; i < n_mempools; ++i) {
		size_t used = mempool_stats[i].size - mempool_stats[i].free;
		uint32_t used_frac = used*10000/mempool_stats[i].size;

		mvwaddstrf(win_stat, 2 + i, 14, "%3u.%02u", used_frac/100, used_frac % 100);
		mvwaddstrf(win_stat, 2 + i, 21, "%12zu", used);
		mvwaddstrf(win_stat, 2 + i, 34, "%12zu", mempool_stats[i].free);
		mvwaddstrf(win_stat, 2 + i, 60, "%14zu", used * MBUF_SIZE/1024);
		mvwaddstrf(win_stat, 2 + i, 75, "%14zu", mempool_stats[i].free * MBUF_SIZE/1024);
	}
}

static void display_stats_rings(void)
{
	int top = 2;
	int left = 0;
	uint32_t used;

	for (uint32_t i = 0; i < n_rings; ++i) {
		left = 0;
		used = ((ring_stats[i].size - ring_stats[i].free)*10000)/ring_stats[i].size;
		left += 24;
		mvwaddstrf(win_stat, top, left, "%8u.%02u", used/100, used%100);
		left += 12;
		mvwaddstrf(win_stat, top, left, "%9u", ring_stats[i].free);
		left += 10;
		mvwaddstrf(win_stat, top, left, "%9u", ring_stats[i].size);
		top += ring_stats[i].nb_ports ? ring_stats[i].nb_ports : 1;
	}
}

uint64_t stats_core_task_lat_min(uint8_t lcore_id, uint8_t task_id)
{
	struct task_lat_stats *s;
	struct lat_test *lat_test;

	for (uint16_t i = 0; i < n_latency; ++i) {
		s = &task_lats[i];

		if (s->lcore_id == lcore_id && s->task_id == task_id) {
			lat_test = &lat_stats[i];
			if ((lat_test->min_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				return (lat_test->min_lat << LATENCY_ACCURACY)*1000000/tsc_hz;
			}
			else {
				return (lat_test->min_lat << LATENCY_ACCURACY)/(tsc_hz/1000000);
			}
		}
	}

	return 0;
}

uint64_t stats_core_task_lat_max(uint8_t lcore_id, uint8_t task_id)
{
	struct task_lat_stats *s;
	struct lat_test *lat_test;

	for (uint16_t i = 0; i < n_latency; ++i) {
		s = &task_lats[i];
		if (s->lcore_id == lcore_id && s->task_id == task_id) {
			lat_test = &lat_stats[i];
			if ((lat_test->max_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				return (lat_test->max_lat<<LATENCY_ACCURACY)*1000000/tsc_hz;
			}
			else {
				return (lat_test->max_lat<<LATENCY_ACCURACY)/(tsc_hz/1000000);
			}
		}
	}

	return 0;
}

uint64_t stats_core_task_lat_avg(uint8_t lcore_id, uint8_t task_id)
{
	struct task_lat_stats *s;
	struct lat_test *lat_test;

	for (uint16_t i = 0; i < n_latency; ++i) {
		s = &task_lats[i];
		if (s->lcore_id == lcore_id && s->task_id == task_id) {
			lat_test = &lat_stats[i];

			if (!lat_test->tot_pkts) {
				return 0;
			}

			if ((lat_test->tot_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				return (lat_test->tot_lat<<LATENCY_ACCURACY)*1000000/(lat_test->tot_pkts*tsc_hz);
			}
			else {
				return (lat_test->tot_lat<<LATENCY_ACCURACY)/(lat_test->tot_pkts*tsc_hz/1000000);
			}
		}
	}
	return 0;
}

uint64_t *buckets_core_lat(uint8_t lcore_id, uint8_t task_id)
{
	for (uint16_t i = 0; i < n_latency; ++i) {
		struct task_lat_stats* s = &task_lats[i];

		if (s->lcore_id == lcore_id && s->task_id == task_id) {
			struct lat_test *lat_test = &lat_stats[i];
			return lat_test->buckets;
		}
	}
	return NULL;
}

#ifndef NO_LATENCY_PER_PACKET
void stats_core_lat(uint8_t lcore_id, uint8_t task_id, unsigned *n_pkts, __attribute__((unused)) uint64_t *lat)
{
	*n_pkts = 0;
	int first_packet = 0;
	for (uint16_t i = 0; i < n_latency; ++i) {
		struct task_lat_stats* s = &task_lats[i];

		if (s->lcore_id == lcore_id && s->task_id == task_id) {
			struct lat_test *lat_test = &lat_stats[i];

			if (lat_test->tot_pkts < MAX_PACKETS_FOR_LATENCY) {
				*n_pkts = lat_test->tot_pkts ;
			} else {
				*n_pkts = MAX_PACKETS_FOR_LATENCY;
			}
			first_packet = (lat_test->cur_pkt + MAX_PACKETS_FOR_LATENCY - *n_pkts) % MAX_PACKETS_FOR_LATENCY;

			for (unsigned j = 0; j < *n_pkts && first_packet + j < MAX_PACKETS_FOR_LATENCY; j++) {
				lat[j] = (lat_test->lat[first_packet + j] << LATENCY_ACCURACY) * 1000000000/(tsc_hz);
			}

			for (unsigned j = 0; j + MAX_PACKETS_FOR_LATENCY < first_packet + *n_pkts ; j++) {
				lat[j + MAX_PACKETS_FOR_LATENCY - first_packet] = (lat_test->lat[j] << LATENCY_ACCURACY) * 1000000000/(tsc_hz);
			}
			plog_info("n_pkts = %d, first_packet = %d, cur_pkt = %d\n", *n_pkts, first_packet, lat_test->cur_pkt);
		}
	}
}
#endif

static void display_stats_l4gen(void)
{
	for (uint16_t i = 0; i < n_l4gen; ++i) {
		struct task_l4gen *task_l4gen = task_l4_stats[i].task;
		uint64_t delta_t = task_l4_stats[i].tsc[last_stat] - task_l4_stats[i].tsc[!last_stat];
		struct l4_stats *last = &task_l4_stats[i].l4_stats[last_stat];
		struct l4_stats *prev = &task_l4_stats[i].l4_stats[!last_stat];

		uint64_t tcp_created = last->tcp_created - prev->tcp_created;
		uint64_t udp_created = last->udp_created - prev->udp_created;

		uint64_t tcp_finished_no_retransmit = last->tcp_finished_no_retransmit - prev->tcp_finished_no_retransmit;
		uint64_t tcp_finished_retransmit = last->tcp_finished_retransmit - prev->tcp_finished_retransmit;
		uint64_t tcp_expired = last->tcp_expired - prev->tcp_expired;
		uint64_t tcp_retransmits = last->tcp_retransmits - prev->tcp_retransmits;
		uint64_t udp_finished = last->udp_finished - prev->udp_finished;
		uint64_t udp_expired = last->udp_expired - prev->udp_expired;

		mvwaddstrf(win_stat, 2 + i, 5, "%9"PRIu64"", tcp_created*rte_get_tsc_hz()/delta_t);
		mvwaddstrf(win_stat, 2 + i, 15, "%9"PRIu64"", udp_created*rte_get_tsc_hz()/delta_t);
		mvwaddstrf(win_stat, 2 + i, 25, "%9"PRIu64"", tcp_created*rte_get_tsc_hz()/delta_t + udp_created*rte_get_tsc_hz()/delta_t);

		mvwaddstrf(win_stat, 2 + i, 35, "%12"PRIu64"", tcp_finished_no_retransmit*rte_get_tsc_hz()/delta_t);
		mvwaddstrf(win_stat, 2 + i, 48, "%12"PRIu64"", tcp_finished_retransmit*rte_get_tsc_hz()/delta_t);
		mvwaddstrf(win_stat, 2 + i, 61, "%12"PRIu64"", udp_finished*rte_get_tsc_hz()/delta_t);

		mvwaddstrf(win_stat, 2 + i, 74, "%10"PRIu64"", tcp_expired*rte_get_tsc_hz()/delta_t);
		mvwaddstrf(win_stat, 2 + i, 85, "%10"PRIu64"", udp_expired*rte_get_tsc_hz()/delta_t);

		uint64_t tot_created = last->tcp_created + last->udp_created;
		uint64_t tot_finished = last->tcp_finished_retransmit + last->tcp_finished_no_retransmit +
			last->udp_finished + last->udp_expired + last->tcp_expired;

		mvwaddstrf(win_stat, 2 + i, 96, "%10"PRIu64"",  tot_created - tot_finished);
		mvwaddstrf(win_stat, 2 + i, 107, "%10"PRIu64"", tcp_retransmits*rte_get_tsc_hz()/delta_t);
	}
}

static void display_stats_latency(void)
{
	for (uint16_t i = 0; i < n_latency; ++i) {
		struct lat_test *lat_test = &lat_stats[i];
		if (lat_test->tot_pkts) {
			uint64_t avg_usec, avg_nsec, min_usec, min_nsec, max_usec, max_nsec;

			if ((lat_test->tot_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				avg_usec = (lat_test->tot_lat<<LATENCY_ACCURACY)*1000000/(lat_test->tot_pkts*tsc_hz);
				avg_nsec = ((lat_test->tot_lat<<LATENCY_ACCURACY)*1000000 - avg_usec*lat_test->tot_pkts*tsc_hz)*1000/(lat_test->tot_pkts*tsc_hz);
			}
			else {
				avg_usec = (lat_test->tot_lat<<LATENCY_ACCURACY)/(lat_test->tot_pkts*tsc_hz/1000000);
				avg_nsec = 0;
			}

			if ((lat_test->min_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				min_usec = (lat_test->min_lat<<LATENCY_ACCURACY)*1000000/tsc_hz;
				min_nsec = ((lat_test->min_lat<<LATENCY_ACCURACY)*1000000 - min_usec*tsc_hz)*1000/tsc_hz;
			}
			else {
				min_usec = (lat_test->min_lat<<LATENCY_ACCURACY)/(tsc_hz/1000000);
				min_nsec = 0;
			}


			if ((lat_test->max_lat << LATENCY_ACCURACY) < UINT64_MAX/1000000) {
				max_usec = (lat_test->max_lat<<LATENCY_ACCURACY)*1000000/tsc_hz;
				max_nsec = ((lat_test->max_lat<<LATENCY_ACCURACY)*1000000 - max_usec*tsc_hz)*1000/tsc_hz;
			}
			else {
				max_usec = (lat_test->max_lat<<LATENCY_ACCURACY)/(tsc_hz/1000000);
				max_nsec = 0;
			}

			mvwaddstrf(win_stat, 2 + i, 16, "%6"PRIu64".%03"PRIu64"", min_usec, min_nsec);
			mvwaddstrf(win_stat, 2 + i, 29, "%6"PRIu64".%03"PRIu64"", max_usec, max_nsec);
			mvwaddstrf(win_stat, 2 + i, 42, "%6"PRIu64".%03"PRIu64"", avg_usec, avg_nsec);
			mvwaddstrf(win_stat, 2 + i, 53, "%12.3f", sqrt((((lat_test->var_lat << (2 * LATENCY_ACCURACY)) / lat_test->tot_pkts)*1000000.0/tsc_hz*1000000/tsc_hz) - (((lat_test->tot_lat << LATENCY_ACCURACY) / lat_test->tot_pkts*1000000.0/tsc_hz * (lat_test->tot_lat << LATENCY_ACCURACY) /lat_test->tot_pkts * 1000000/tsc_hz))));
		}
	}
}

void display_screen(int screen_id)
{
	if (screen_id < 0 || screen_id > 5) {
		plog_err("Unsupported screen %d\n", screen_id);
		return;
	}

	if (screen_state.chosen_screen == screen_id) {
		stats_display_layout(1);
	}
	else {
		screen_state.chosen_screen = screen_id;
		stats_display_layout(0);
	}
}

void display_page_up(void)
{
	if (screen_state.chosen_page) {
		--screen_state.chosen_page;
		stats_display_layout(0);
	}
}

void display_page_down(void)
{
	if (nb_tasks_tot > core_port_height * (screen_state.chosen_page + 1)) {
		++screen_state.chosen_page;
		stats_display_layout(0);
	}
}

void display_refresh(void)
{
	stats_display_layout(1);
}

void display_stats(void)
{
	display_lock();
	switch (screen_state.chosen_screen) {
	case 0:
		display_stats_core_ports();
		break;
	case 1:
		display_stats_eth_ports();
		break;
	case 2:
		display_stats_mempools();
		break;
	case 3:
		display_stats_latency();
		break;
	case 4:
		display_stats_rings();
		break;
	case 5:
		display_stats_l4gen();
		break;
	}
	display_stats_general();
	wrefresh(win_stat);
	display_unlock();
}

static void reset_port_stats(void)
{
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			nic_stats_reset(port_id);
			memset(&eth_stats[port_id], 0, sizeof(struct eth_stats));
		}
	}
}

void stats_reset(void)
{
	uint64_t last_tsc = global_stats.last_tsc;

	memset(&global_stats, 0, sizeof(struct global_stats));
	global_stats.last_tsc = last_tsc;

	for (uint8_t task_id = 0; task_id < nb_tasks_tot; ++task_id) {
		struct port_stats *cur_port_stats = core_ports[task_id].port_stats;
		cur_port_stats->tot_rx_pkt_count = 0;
		cur_port_stats->tot_tx_pkt_count = 0;
		cur_port_stats->tot_tx_pkt_drop = 0;
	}

	reset_port_stats();

	start_tsc = rte_rdtsc();
	global_stats.avg_start = rte_rdtsc();
}

uint64_t global_last_tsc(void)
{
	return global_stats.last_tsc;
}

uint64_t global_total_tx(void)
{
	return global_stats.tx_tot;
}

uint64_t global_total_rx(void)
{
	return global_stats.rx_tot;
}

uint64_t global_avg_tx(void)
{
	return global_stats.tx_avg;
}

uint64_t global_avg_rx(void)
{
	return global_stats.rx_avg;
}

uint64_t global_pps_tx(void)
{
	return global_stats.tx_pps;
}

uint64_t global_pps_rx(void)
{
	return global_stats.rx_pps;
}

uint64_t tot_ierrors_per_sec(void)
{
	uint64_t ret = 0;
	uint64_t *ierrors;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			ierrors = eth_stats[port_id].ierrors;
			ret += ierrors[last_stat] - ierrors[!last_stat];
		}
	}

	return ret;
}

uint64_t tot_ierrors_tot(void)
{
	uint64_t ret = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			ret += eth_stats[port_id].ierrors[last_stat];
		}
	}

	return ret;
}

char pages[32768] = {0};
int cur_idx = 0;
size_t pages_len = 0;

void display_print_page(void)
{
	int n_lines = 0;
	int cur_idx_prev = cur_idx;

	if (cur_idx >= (int)pages_len) {
		return;
	}

	display_lock();
	for (size_t i = cur_idx; i < pages_len; ++i) {
		if (pages[i] == '\n') {
			n_lines++;
			if (n_lines == win_txt_height - 2) {
				pages[i] = 0;
				cur_idx = i + 1;
				break;
			}
		}
	}

	waddstr(win_txt, pages + cur_idx_prev);
	if (cur_idx != cur_idx_prev && cur_idx < (int)pages_len)
		waddstr(win_txt, "\nPRESS ENTER FOR MORE...\n");
	else {
		pages_len = 0;
	}
	wrefresh(win_txt);
	display_unlock();
}

void display_print(const char *str)
{
	display_lock();

	if (scr == NULL) {
		fputs(str, stdout);
		fflush(stdout);
		display_unlock();
		return;
	}

	/* Check if the whole string can fit on the screen. */
	pages_len = strlen(str);
	int n_lines = 0;
	memset(pages, 0, sizeof(pages));
	memcpy(pages, str, pages_len);
	cur_idx = 0;
	for (size_t i = 0; i < pages_len; ++i) {
		if (pages[i] == '\n') {
			n_lines++;
			if (n_lines == win_txt_height - 2) {
				pages[i] = 0;
				cur_idx = i + 1;
				break;
			}
		}
	}

	waddstr(win_txt, pages);
	if (cur_idx != 0)
		waddstr(win_txt, "\nPRESS ENTER FOR MORE...\n");
	else
		pages_len = 0;

	wrefresh(win_txt);
	display_unlock();
}
#endif

#ifndef BRAS_STATS

void display_init(__attribute__((unused)) unsigned avg_start, __attribute__((unused)) unsigned duration){}
void display_end(void){}

void reset_stats(void){}
void update_stats(void){}
void display_stats(void) {}

uint64_t global_last_tsc(void) {return 0;}
uint64_t global_total_tx(void) {return 0;}
uint64_t global_total_rx(void) {return 0;}
uint64_t global_avg_tx(void) {return 0;}
uint64_t global_avg_rx(void) {return 0;}

uint64_t stats_core_task_tot_rx(__attribute__((unused)) uint8_t lcore_id, __attribute__((unused)) uint8_t task_id) {return 0;}
uint64_t stats_core_task_tot_tx(__attribute__((unused)) uint8_t lcore_id, __attribute__((unused)) uint8_t task_id) {return 0;}
uint64_t stats_core_task_tot_drop(__attribute__((unused)) uint8_t lcore_id, __attribute__((unused)) uint8_t task_id) {return 0;}
uint64_t stats_core_task_last_tsc(__attribute__((unused)) uint8_t lcore_id, __attribute__((unused)) uint8_t task_id) {return 0;}

#endif
