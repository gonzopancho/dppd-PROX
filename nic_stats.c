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

#if defined(BRAS_STATS) && defined(PROX_HW_DIRECT_STATS)

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>

#include "stats.h"

/* Directly access hardware counters instead of going through DPDK. This allows getting
 * specific counters that DPDK does not report or aggregates with other ones.
 */

/* Definitions for IXGBE (taken from PMD) */
#define PROX_IXGBE_MPC(_i)           (0x03FA0 + ((_i) * 4)) /* 8 of these 3FA0-3FBC*/
#define PROX_IXGBE_QBRC_L(_i)        (0x01034 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_QBRC_H(_i)        (0x01038 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_QPRC(_i)          (0x01030 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_GPTC              0x04080
#define PROX_IXGBE_TPR               0x040D0
#define PROX_IXGBE_TORL              0x040C0
#define PROX_IXGBE_TORH              0x040C4
#define PROX_IXGBE_GOTCL             0x04090
#define PROX_IXGBE_GOTCH             0x04094

#define IXGBE_QUEUE_STAT_COUNTERS 16

#define PROX_IXGBE_PCI_REG_ADDR(hw, reg) \
        ((volatile uint32_t *)((char *)(hw)->hw_addr + (reg)))
#define PROX_IXGBE_READ_REG(hw, reg) \
        prox_ixgbe_read_addr(PROX_IXGBE_PCI_REG_ADDR((hw), (reg)))
#define PROX_IXGBE_PCI_REG(reg) (*((volatile uint32_t *)(reg)))
static inline uint32_t prox_ixgbe_read_addr(volatile void* addr)
{
        return rte_le_to_cpu_32(PROX_IXGBE_PCI_REG(addr));
}
struct _ixgbe_hw {
        unsigned char *hw_addr;
};

void ixgbe_read_stats(uint8_t port_id, struct eth_stats* stats, int last_stat)
{
	unsigned i;

	struct rte_eth_dev* dev = &rte_eth_devices[port_id];

	/* WARNING: Assumes hardware address is first field of structure! This may change! */
	struct _ixgbe_hw* hw = (struct _ixgbe_hw *)(dev->data->dev_private);

	stats->no_mbufs[last_stat] = dev->data->rx_mbuf_alloc_failed;

	/* Since we only read deltas from the NIC, we have to add to previous values
	 * even though we actually substract again later to find out the rates!
	 */
	stats->ierrors[last_stat] = stats->ierrors[!last_stat];
	stats->rx_bytes[last_stat] = stats->rx_bytes[!last_stat];
	stats->rx_tot[last_stat] = stats->rx_tot[!last_stat];
	stats->tx_bytes[last_stat] = stats->tx_bytes[!last_stat];
	stats->tx_tot[last_stat] = stats->tx_tot[!last_stat];

	/* WARNING: In this implementation, we count as ierrors only the "no descriptor"
	 * missed packets cases and not the actual receive errors.
	 */
	for (i = 0; i < 8; i++) {
		stats->ierrors[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_MPC(i));
	}

	/* RX stats */
#if 0
	/* This version is equivalent to what ixgbe PMD does. It only accounts for packets
	 * actually received on the host.
	 */
	for (i = 0; i < IXGBE_QUEUE_STAT_COUNTERS; i++) {
		/* ipackets: */
		stats->rx_tot[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_QPRC(i));
		/* ibytes: */
		stats->rx_bytes[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_QBRC_L(i));
		stats->rx_bytes[last_stat] += ((uint64_t)PROX_IXGBE_READ_REG(hw, PROX_IXGBE_QBRC_H(i)) << 32);
	}
#else
	/* This version reports the packets received by the NIC, regardless of whether they
	 * reached the host or not, etc. (no need to add ierrors to this packet count)
	 */
	stats->rx_tot[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_TPR);
	stats->rx_bytes[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_TORL);
	stats->rx_bytes[last_stat] += ((uint64_t)PROX_IXGBE_READ_REG(hw, PROX_IXGBE_TORH) << 32);
#endif

	/* TX stats */
	/* opackets: */
	stats->tx_tot[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_GPTC);
	/* obytes: */
	stats->tx_bytes[last_stat] += PROX_IXGBE_READ_REG(hw, PROX_IXGBE_GOTCL);
	stats->tx_bytes[last_stat] += ((uint64_t)PROX_IXGBE_READ_REG(hw, PROX_IXGBE_GOTCH) << 32);

	stats->tsc[last_stat] = rte_rdtsc();
}

#endif
