##
# Copyright(c) 2010-2015 Intel Corporation.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

rte_version_h := $(RTE_SDK)/$(RTE_TARGET)/include/rte_version.h

hash := \#

rte_ver = $(shell grep -i define\ $(1) $(rte_version_h) | cut -d' ' -f3)
rte_ver_cur := $(call rte_ver,RTE_VER_MAJOR).$(call rte_ver,RTE_VER_MINOR)

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = prox
CFLAGS += -DPROGRAM_NAME=\"$(APP)\"

CFLAGS += -O2
CFLAGS += -fno-stack-protector

ifeq ($(BNG_QINQ),)
CFLAGS += -DUSE_QINQ
else ifeq ($(BNG_QINQ),y)
CFLAGS += -DUSE_QINQ
endif

ifeq ($(MPLS_ROUTING),)
CFLAGS += -DMPLS_ROUTING
else ifeq ($(MPLS_ROUTING),y)
CFLAGS += -DMPLS_ROUTING
endif

LD_LUA  = $(shell pkg-config --silence-errors --libs-only-l lua)
CFLAGS += $(shell pkg-config --silence-errors --cflags lua)
ifeq ($(LD_LUA),)
LD_LUA  = $(shell pkg-config --silence-errors --libs-only-l lua5.2)
CFLAGS += $(shell pkg-config --silence-errors --cflags lua5.2)
ifeq ($(LD_LUA),)
LD_LUA =-llua
endif
endif


LDFLAGS += -lpcap

LD_TINFO = $(shell pkg-config --silence-errors --libs-only-l tinfo)
LDFLAGS += -lpcap $(LD_TINFO)

ifeq ($(PROX_DISPLAY),)
CFLAGS += -DBRAS_STATS
LDFLAGS += -lncurses -lncursesw -ledit $(LD_LUA)
else ifeq ($(PROX_DISPLAY),y)
CFLAGS += -DBRAS_STATS
LDFLAGS += -lncurses -lncursesw -ledit $(LD_LUA)
endif

ifeq ($(HW_DIRECT_STATS),y)
CFLAGS += -DPROX_HW_DIRECT_STATS
endif

ifeq ($(dbg),y)
EXTRA_CFLAGS += -ggdb
endif

ifeq ($(log),)
CFLAGS += -DPROX_MAX_LOG_LVL=2
else
CFLAGS += -DPROX_MAX_LOG_LVL=$(log)
endif

CFLAGS += -DBRAS_PREFETCH_OFFSET=2
CFLAGS += -DHARD_CRC
#CFLAGS += -DBRAS_RX_BULK
#CFLAGS += -DASSERT
#CFLAGS += -DENABLE_EXTRA_USER_STATISTICS
CFLAGS += -DGRE_TP
CFLAGS += -std=gnu99
CFLAGS += -D_GNU_SOURCE                # for PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-unused
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-unused-result

# all source are stored in SRCS-y

SRCS-y := task_init.c

SRCS-y += handle_nop.c
SRCS-y += handle_impair.c
SRCS-y += handle_drop.c
SRCS-y += handle_lat.c
SRCS-y += handle_qos.c
SRCS-y += handle_qinq_decap4.c
SRCS-y += handle_routing.c
SRCS-y += handle_untag.c
SRCS-y += handle_mplstag.c
SRCS-y += handle_qinq_decap6.c

# support for GRE encap/decap dropped in latest DPDK versions
ifeq ($(lastword $(sort $(rte_ver_cur) 2.0)),2.0)
SRCS-y += handle_gre_decap_encap.c
endif

SRCS-y += handle_lb_qinq.c
SRCS-y += handle_lb_pos.c
SRCS-y += handle_lb_net.c
SRCS-y += handle_qinq_encap4.c
SRCS-y += handle_qinq_encap6.c
SRCS-y += handle_classify.c
SRCS-y += handle_l2fwd.c
SRCS-y += handle_police.c
SRCS-y += handle_acl.c
SRCS-y += handle_gen.c
SRCS-y += handle_mirror.c
SRCS-y += handle_genl4.c
SRCS-y += handle_ipv6_tunnel.c
SRCS-y += handle_read.c
SRCS-y += handle_nat.c
ifneq ($(rte_ver_cur),1.7)
SRCS-y += handle_nsh.c
endif
SRCS-y += handle_lb_5tuple.c
SRCS-y += handle_blockudp.c
SRCS-y += toeplitz.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += handle_pf_acl.c

SRCS-y += thread_nop.c
SRCS-y += thread_generic.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += thread_pipeline.c

SRCS-y += prox_args.c prox_cfg.c prox_cksum.c prox_port_cfg.c

SRCS-y += cfgfile.c clock.c commands.c cqm.c msr.c defaults.c
SRCS-y += display.c log.c hash_utils.c main.c parse_utils.c
SRCS-y += run.c input_conn.c input_curses.c
SRCS-y += rx_pkt.c lconf.c tx_pkt.c tx_worker.c expire_cpe.c ip_subnet.c
SRCS-$(HW_DIRECT_STATS) += nic_stats.c
SRCS-y += cmd_parser.c input.c prox_shared.c prox_lua_types.c
SRCS-y += genl4_bundle.c heap.c genl4_stream_tcp.c genl4_stream_udp.c cdf.c

include $(RTE_SDK)/mk/rte.extapp.mk
