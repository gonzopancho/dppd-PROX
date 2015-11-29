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

#ifndef _PROX_CKSUM_H_
#define _PROX_CKSUM_H_

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>

#define CALC_TX_OL(l2_len, l3_len) ((uint64_t)(l2_len) | (uint64_t)(l3_len) << 7)

void prox_ip_cksum_sw(struct ipv4_hdr *buf, uint32_t cksum, uint16_t *res);
void prox_write_udp_cksum_pseudo_hdr(uint8_t *buf, uint16_t l2_len, uint16_t l3_len);
void prox_write_tcp_cksum_pseudo_hdr(uint8_t *buf, uint16_t l2_len, uint16_t l3_len);


#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
#define CKSUM_ETH_IP      ( (sizeof(struct ether_hdr)                            << 0) | (sizeof(struct ipv4_hdr) << 7))
#define CKSUM_ETH_MPLS_IP (((sizeof(struct ether_hdr) + sizeof(struct mpls_hdr)) << 0) | (sizeof(struct ipv4_hdr) << 7))
#else
#define CKSUM_ETH_IP      ( (sizeof(struct ether_hdr)                            << 9) | sizeof(struct ipv4_hdr))
#define CKSUM_QINQ_ETH_IP ( ((sizeof(struct qinq_hdr))                           << 9) | sizeof(struct ipv4_hdr))

#define CKSUM_ETH_MPLS_IP (((sizeof(struct ether_hdr) + sizeof(struct mpls_hdr)) << 9) | (sizeof(struct ipv4_hdr)))
#endif


#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
static inline void prox_ip_cksum_hw(struct rte_mbuf *mbuf, uint16_t data)
{
	mbuf->pkt.vlan_macip.data = data;

	mbuf->ol_flags |= PKT_TX_IP_CKSUM;
}
#endif

#endif /* _PROX_CKSUM_H_ */
