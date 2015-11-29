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
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include <pcap.h>

#if RTE_VERSION < RTE_VERSION_NUM(2,1,0,0)
#error "Unsupported DPDK version"
#endif

#define ETYPE_IPv4	0x0008	/* IPv4 in little endian */
#define ETYPE_IPv6	0xDD86	/* IPv6 in little endian */
#define ETYPE_ARP	0x0608	/* ARP in little endian */
#define ETYPE_VLAN	0x0081	/* 802-1aq - VLAN */
#define ETYPE_MPLSU	0x4788	/* MPLS unicast */
#define ETYPE_MPLSM	0x4888	/* MPLS multicast */
#define ETYPE_8021ad	0xA888	/* Q-in-Q */
#define ETYPE_LLDP	0xCC88	/* Link Layer Discovery Protocol (LLDP) */
#define ETYPE_EoGRE	0x5865	/* EoGRE in little endian */


struct app_cfg {
	char file_path_lua[1024];
	char file_path_pcap[1024];
};

struct app_cfg app_cfg = {
	.file_path_lua = "cfg.lua",
};

/* #define MAX_PKTS (32768*8) */
#define MAX_PKTS UINT32_MAX

static void usage(const char *app_name)
{
	fprintf(stderr, "Usage: %s DPDK_OPTIONS -- pcap_file.pcap.\n\n"
		"   example: %s -c 0x3 -n 1 -- ~/dump.pcap\n\n"
                "   One argument pointing to the pcap file should be passed to\n"
		"   this program.  This program extracts flows from a pcap file and\n"
		"   creates configuration files that can be used with the L4 gen task in\n"
		"   prox. Together with the lua output file, a set of bin files (in the\n"
		"   bin sub-directory) are created as well. These are references from\n"
		"   within the lua output file.\n", app_name, app_name);
}

struct pkt_tuple {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t proto_id;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t l2_types[4];
} __attribute__((packed));

static void pkt_tuple_debug(struct pkt_tuple *pt)
{
	printf("src_ip: %#010x\n", pt->src_addr);
	printf("dst_ip: %#010x\n", pt->dst_addr);
	printf("dst_port: %#06x (%u)\n", pt->dst_port, rte_bswap16(pt->dst_port));
	printf("src_port: %#06x (%u)\n", pt->src_port, rte_bswap16(pt->src_port));
	printf("proto_id: %#04x (%s)\n", pt->proto_id, pt->proto_id == 0x11? "UDP" : "TCP");
	printf("l2 types: \n");
	for (int i = 0; i < 4; ++i)
		printf("  - %#04x\n", pt->l2_types[i]);
}

static int parse_pkt(const void *buf, struct pkt_tuple *pt, const uint8_t **l4_hdr, const uint8_t **payload, uint16_t *len)
{
	const struct ether_hdr *peth = buf;
	int l2_types_count = 0;
	const struct ipv4_hdr* pip = 0;

	/* L2 */
	memset(pt->l2_types, 0, sizeof(pt->l2_types));
	pt->l2_types[l2_types_count++] = peth->ether_type;

	switch (peth->ether_type) {
	case ETYPE_IPv4:
			pip = (const struct ipv4_hdr *)(peth + 1);
		break;
	case ETYPE_VLAN: {
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
		pt->l2_types[l2_types_count++] = vlan->eth_proto;
		if (vlan->eth_proto == ETYPE_IPv4) {
			pip = (const struct ipv4_hdr *)(peth + 1);
		}
		else if (vlan->eth_proto == ETYPE_VLAN) {
			const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
			pt->l2_types[l2_types_count++] = vlan->eth_proto;
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (const struct ipv4_hdr *)(peth + 1);
			}
			else if (vlan->eth_proto == ETYPE_IPv6) {
				return 1;
			}
			else {
				/* TODO: handle BAD PACKET */
				return 1;
			}
		}
	}
		break;
	case ETYPE_8021ad: {
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
		pt->l2_types[l2_types_count++] = vlan->eth_proto;
		if (vlan->eth_proto == ETYPE_VLAN) {
			const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
			pt->l2_types[l2_types_count++] = vlan->eth_proto;
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (const struct ipv4_hdr *)(peth + 1);
			}
			else {
				return 1;
			}
		}
		else {
			return 1;
		}
	}
		break;
	case ETYPE_MPLSU:
		break;
	default:
		break;
	}

	/* L3 */
	if ((pip->version_ihl >> 4) == 4) {

		if ((pip->version_ihl & 0x0f) != 0x05) {
			/* TODO: optional fields */
			return 1;
		}

		pt->proto_id = pip->next_proto_id;
		pt->src_addr = pip->src_addr;
		pt->dst_addr = pip->dst_addr;
	}
	else {
		/* TODO: IPv6 and bad packets */
		return 1;
	}

	/* L4 parser */
	if (pt->proto_id == IPPROTO_UDP) {
		const struct udp_hdr *udp = (const struct udp_hdr*)(pip + 1);
		*l4_hdr = (const uint8_t*)udp;
		pt->src_port = udp->src_port;
		pt->dst_port = udp->dst_port;
		*payload = ((const uint8_t*)udp) + sizeof(struct udp_hdr);
		*len = rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct udp_hdr);
	}
	else if (pt->proto_id == IPPROTO_TCP) {
		const struct tcp_hdr *tcp = (const struct tcp_hdr*)(pip + 1);
		*l4_hdr = (const uint8_t*)tcp;
		pt->src_port = tcp->src_port;
		pt->dst_port = tcp->dst_port;

		*payload = ((const uint8_t*)tcp) + ((tcp->data_off >> 4)*4);
		*len = rte_be_to_cpu_16(pip->total_length) - sizeof(struct ipv4_hdr) - ((tcp->data_off >> 4)*4);
	}
	else {
		fprintf(stderr, "unsupported protocol %d\n", pt->proto_id);
		return 1;
	}

	return 0;
}

struct pkt_entry {
	uint64_t time;
	uint8_t *data;
	uint32_t data_len;
	struct timeval tv;
	uint32_t stream_id;
	struct pkt_tuple *tuple;
	struct pkt_entry *next;
};

enum l4gen_peer {PEER_SERVER, PEER_CLIENT};
struct peer_action {
	enum l4gen_peer   peer;
	uint32_t          beg;
	uint32_t          len;
};

static void pkt_entry_to_pcap(struct pkt_entry *cur, const char *file_path, int end)
{
	static pcap_t *handle;
	static pcap_dumper_t *pcap_dumper;
	uint32_t n_pkts = 65536;
	struct pcap_pkthdr header = {0};
	static int once = 0;

	if (end && once) {
		once = 0;
		pcap_dump_close(pcap_dumper);
		pcap_close(handle);
		printf("done\n");
		return ;
	}

	char err_str[PCAP_ERRBUF_SIZE];

	if (once == 0) {
		printf("started\n");
		once = 1;
		handle = pcap_open_dead(DLT_EN10MB, n_pkts);
		pcap_dumper = pcap_dump_open(handle, file_path);
	}

	do {
		header.len = cur->data_len;
		header.caplen = header.len;
		header.ts = cur->tv;

		pcap_dump((unsigned char *)pcap_dumper, &header, cur->data);
	} while ((cur = cur->next));
}

static const char *ip_to_str(uint32_t be_ip)
{
	uint32_t ip = rte_bswap32(be_ip);
	static char ret[32];

	snprintf(ret, sizeof(ret), "%d.%d.%d.%d",
		 ip >> 24 & 0xff,
		 ip >> 16 & 0xff,
		 ip >> 8 & 0xff,
		 ip & 0xff);
	return ret;
}

struct bundle_entry {
	struct pkt_entry *pkt_entry;
	struct bundle_entry *next;
};

static int check_exists(uint32_t be_dst_ip, uint16_t be_dst_port)
{
	static struct rte_hash *hash_uniq_servers = NULL;

	if (!hash_uniq_servers) {
		struct rte_hash_parameters hash_args = {
			.name = "hash name3",
			.entries = 16384 * 8,
			//.bucket_entries = 8,
			.key_len = sizeof(uint32_t) + sizeof(uint16_t), /* ip + port*/
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
		};
		hash_uniq_servers = rte_hash_create(&hash_args);
	}

	uint8_t key[sizeof(uint32_t) + sizeof(uint16_t)];

	memcpy(key                    , &be_dst_ip, sizeof(be_dst_ip));
	memcpy(key + sizeof(be_dst_ip), &be_dst_port, sizeof(be_dst_port));
	if (rte_hash_lookup(hash_uniq_servers, key) > 0) {
		return 1;
	}
	int err;

	if ((err = rte_hash_add_key(hash_uniq_servers, key)) < 0) {
		fprintf(stderr, "Failed to add key to unique servers with err = %d\n", err);
		exit(EXIT_FAILURE);
	}
	return 0;
}

uint64_t tot_alloc;
uint64_t tot_used;

#define MEMSIZE (1024*1024*128)
static void *my_malloc(size_t size)
{
	static uint8_t *mem = NULL;
	static uint64_t cur_used = 0;
	static uint64_t cur_alloc = 0;

	if (size > MEMSIZE) {
		fprintf(stderr, "requested mem is too big (%zu)\n", size);
		exit(EXIT_FAILURE);
	}

	if (cur_used + size > cur_alloc) {
		mem = rte_zmalloc_socket(NULL, MEMSIZE, RTE_CACHE_LINE_SIZE, 0);
		if (mem == NULL) {
			fprintf(stderr, "rte_zmalloc failed after %"PRIu64" alloc'ed\n", tot_alloc);
			exit(EXIT_FAILURE);
		}
		cur_alloc = MEMSIZE;
		tot_alloc += MEMSIZE;
		cur_used = 0;
	}

	uint8_t* ret = &mem[cur_used];

	cur_used += size;
	tot_used += size;

	return ret;
}

uint32_t count = 0;
pcap_t *handle;
uint64_t file_end_pos;
uint64_t file_beg_pos;

static void print_progress(void)
{
	printf("\rpacket count = %u, mem = %"PRIu64"M/%"PRIu64"M, file pos = %"PRIu64"%%", count, tot_used >> 20, tot_alloc >> 20, (ftell(pcap_file(handle)) - file_beg_pos)*100/(file_end_pos - file_beg_pos));
	fflush(stdout);
}

static int func(void *a)
{
	uint32_t n_elems = 64*1024;

	const struct rte_hash_parameters hash_bundle_table = {
		.name = "hash name2",
		.entries = n_elems * 8,
		//.bucket_entries = 8,
		.key_len = sizeof(uint32_t), /* client ip */
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};

	struct rte_hash *hash_bundles = rte_hash_create(&hash_bundle_table);
	struct bundle_entry *hash_bundle_entries = rte_zmalloc_socket(NULL, n_elems * 8 * sizeof(struct bundle_entry), RTE_CACHE_LINE_SIZE, 0);

	const struct rte_hash_parameters hash_comm_table = {
		.name = "hash name",
		.entries = n_elems * 8,
		//.bucket_entries = 8,
		.key_len = sizeof(struct pkt_tuple),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};

	struct rte_hash *hash = rte_hash_create(&hash_comm_table);
	struct pkt_entry *entries = rte_zmalloc_socket(NULL, n_elems * 8 * sizeof(entries[0]), RTE_CACHE_LINE_SIZE, 0);
 	if (NULL == hash) {
	        fprintf(stderr, "Failed to create hash\n");
        }
	uint32_t n_pkt_tuples = 0;

	FILE *file_lua = fopen(app_cfg.file_path_lua ,"w");
	char err_str[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(app_cfg.file_path_pcap, err_str);
	file_beg_pos = ftell(pcap_file(handle));
	fseek(pcap_file(handle), 0, SEEK_END);
	file_end_pos = ftell(pcap_file(handle));
	fseek(pcap_file(handle), file_beg_pos, SEEK_SET);

	if (!handle) {
		fprintf(stderr, "pcap_open_offline failed, %s\n", err_str);
		return EXIT_FAILURE;
	}

	const uint8_t *buf;
	struct pcap_pkthdr header;
	int cnt = 0;
	int n_streams = 0;
	int max_streams = 2000;
	const uint64_t sec = rte_get_tsc_hz();
	uint64_t last_progress = rte_rdtsc() - sec;

	while ((buf = (const uint8_t *)pcap_next(handle, &header)) && (count++ < MAX_PKTS)) {
		if (rte_rdtsc() > last_progress + sec) {
			print_progress();
			last_progress += sec;
		}
		size_t pkt_len = header.len;
		struct pkt_tuple pt;
		const uint8_t *l4_hdr, *payload;
		uint16_t len;

		const struct ether_hdr *ether = (const struct ether_hdr *)buf;
		const struct ipv4_hdr *ipv4 = (const struct ipv4_hdr *)(ether + 1);

		parse_pkt(buf, &pt, &l4_hdr, &payload, &len);

		int pos = rte_hash_lookup(hash, (const void *)&pt);


		if (pos < 0) {
			/* flip src/dst ip/port */
			struct pkt_tuple pt2 = pt;

			pt2.src_addr = pt.dst_addr;
			pt2.src_port = pt.dst_port;
			pt2.dst_addr = pt.src_addr;
			pt2.dst_port = pt.src_port;

			pos = rte_hash_lookup(hash, (const void *)&pt2);

			if (pos < 0) {
				/* Would cause new stream to be added */
				if (n_streams == max_streams)
					continue;
				n_streams++;

				pos = rte_hash_add_key(hash, (const void *)&pt);
				if (pos < 0) {
					fprintf(stderr, "Failed to add key\n");
					return EXIT_FAILURE;
				}
				entries[pos].stream_id = n_pkt_tuples;
				entries[pos].tuple = my_malloc(sizeof(struct pkt_tuple));
				n_pkt_tuples++;
				*entries[pos].tuple = pt;
			}
                }

		if (entries[pos].data == NULL) {
			entries[pos].data = my_malloc(header.len);

			rte_memcpy(entries[pos].data, buf, header.len);
			entries[pos].data_len = header.len;
			entries[pos].tv = header.ts;
		}
		else {
			struct pkt_entry *cur = entries + pos;
			while (cur->next != NULL) {
				cur = cur->next;
			}
			cur->next = my_malloc(sizeof(struct pkt_entry));
			cur = cur->next;

			cur->data = my_malloc(header.len);

			rte_memcpy(cur->data, buf, header.len);
			cur->data_len = header.len;
			cur->tv = header.ts;
		}
	}
	print_progress();
	printf("\n");

	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	int pos;

#define MAX_DATA_LEN (1024*1024*64)

	uint32_t client_content_len, server_content_len;
	uint8_t *client_content = my_malloc(MAX_DATA_LEN);

	if (NULL == client_content) {
		fprintf(stderr, "malloc failed for client_content\n");
	}
	uint8_t *server_content = my_malloc(MAX_DATA_LEN);
	if (NULL == server_content) {
		fprintf(stderr, "malloc failed for server_content\n");
	}

	uint32_t count2 = 0;
	int bcount = 0;

	/* Iterate through the hash table and handle each flow */
	while ((pos = rte_hash_iterate(hash, &next_key, &next_data, &iter)) >= 0) {
		struct pkt_entry *cur = entries + pos;
		struct pkt_tuple *pt = cur->tuple;

		int n_actions_in_flow = 0;

		uint8_t client_hdr[128];
		uint16_t client_hdr_len = 0;
		uint8_t server_hdr[128];
		uint16_t server_hdr_len = 0;

		client_content_len = 0;
		server_content_len = 0;
		struct peer_action action[8192];
		int skip = 0;
		int had_fin = 0;

		do {
			struct pkt_tuple pt_res;
			const uint8_t *l4_hdr, *payload;
			struct peer_action *a;
			uint16_t len;

			if (n_actions_in_flow == 8192) {
				int tot_in_flow = n_actions_in_flow;
				do {
					tot_in_flow++;
				} while ((cur = cur->next));

				fprintf(stderr, "%d packets in flow, only supporting up to %d\n", tot_in_flow, n_actions_in_flow);
				break;
			}

			parse_pkt(cur->data, &pt_res, &l4_hdr, &payload, &len);

			/* client */
			if (!memcmp(pt, &pt_res, sizeof(*pt))) {
				if (client_hdr_len == 0) {
					client_hdr_len = l4_hdr - cur->data;
					rte_memcpy(client_hdr, cur->data, client_hdr_len);

				}

				if (len) {
					if (pt->proto_id == 0x06 && n_actions_in_flow && action[n_actions_in_flow - 1].peer == PEER_CLIENT) {
						a->len  += len;
					}
					else {
						a = &action[n_actions_in_flow++];

						a->peer = PEER_CLIENT;
						a->beg  = client_content_len;
						a->len  = len;
					}

					if (client_content_len + len > MAX_DATA_LEN) {
						fprintf(stderr, "Client data is more than %zu\n", sizeof(client_content));
						/* exit(EXIT_FAILURE); */
						skip = 1;
					}

					if (!skip)
						rte_memcpy(client_content + client_content_len, payload, len);
					client_content_len += len;
				}
				else if (((const struct tcp_hdr *)l4_hdr)->tcp_flags & 0x01) {
					struct peer_action *a = &action[n_actions_in_flow++];
					a->peer = PEER_CLIENT;
					a->beg  = client_content_len;
					a->len  = 0;
					had_fin = 1;
				}
			}
			/* server */
			else {
				if (server_hdr_len == 0) {
					server_hdr_len = l4_hdr - cur->data;
					rte_memcpy(server_hdr, cur->data, server_hdr_len);
				}

				if (len) {
					if (pt->proto_id == 0x06 && n_actions_in_flow && action[n_actions_in_flow - 1].peer == PEER_SERVER) {
						a->len  += len;
					}
					else {
						a = &action[n_actions_in_flow++];

						a->peer = PEER_SERVER;
						a->beg  = server_content_len;
						a->len  = len;
					}

					if (server_content_len + len > MAX_DATA_LEN) {
						skip = 1;
					}

					if (!skip)
						rte_memcpy(server_content + server_content_len, payload, len);
					server_content_len += len;
				}
				else if (((const struct tcp_hdr *)l4_hdr)->tcp_flags & 0x01) {
					struct peer_action *a = &action[n_actions_in_flow++];
					a->peer = PEER_CLIENT; /* TODO: Allow server to also FIN the connection (this will require over-provisioning the server)*/
					a->beg  = client_content_len;
					a->len  = 0;
					had_fin = 1;
				}
			}

			if (had_fin)
				break;
		} while ((cur = cur->next));
		int keep = pt->proto_id == 0x11;
		static int tot_tcp = 0;
		static int fin_have = 0;
		bcount++;

		if (pt->proto_id == 0x06) {
			fin_have += had_fin;
			tot_tcp++;
			keep = had_fin;
		}

		/* Through RTSP the client and server agree on which
		   UDP port to use to transfer the media. The server
		   than starts transmitting media to the client
		   through the agreed-upon port. Currently, this is
		   identified as a stream where only the client sends
		   data to the server since the code assumes that the
		   first packet is originating from the client. In
		   reality, this client is the server. Skip these
		   kinds of streams for now. */
		if (server_hdr_len == 0)
			keep = 0;

		if (!keep)
			continue;

		/* Since this is the first packet for this flow, it is
		   assumed to come from the client. For detecting a
		   set of streams that belong together, use the src IP
		   (i.e. client). */
		uint32_t client_ip = pt->src_addr;
		int pos2 = rte_hash_lookup(hash_bundles, (const void *)&client_ip);
		if (pos2 < 0) {
			/* First stream in bundle */
			pos2 = rte_hash_add_key(hash_bundles, (const void*)&client_ip);
			struct bundle_entry *entry = &hash_bundle_entries[pos2];
			entry->pkt_entry = &entries[pos];
		}
		else {
			struct bundle_entry *entry = &hash_bundle_entries[pos2];

			while (entry->next) {
				entry = entry->next;
			}

			entry->next = my_malloc(sizeof(struct bundle_entry));

			entry = entry->next;
			entry->pkt_entry = &entries[pos];
		}

		uint32_t stream_id = entries[pos].stream_id;
		fprintf(file_lua, "stream_%d = {\n", stream_id);

		char client_bin_file[1024];
		char server_bin_file[1024];
		snprintf(client_bin_file, sizeof(client_bin_file), "bin/stream_%d-client.bin", stream_id);
		snprintf(server_bin_file, sizeof(server_bin_file), "bin/stream_%d-server.bin", stream_id);

		fprintf(file_lua, "   client_data = {header = bin_read(\"%s\", 0, %d), content = bin_read(\"%s\", %d)},\n", client_bin_file, client_hdr_len, client_bin_file, client_hdr_len);

		fprintf(file_lua, "   server_data = {header = bin_read(\"%s\", 0, %d), content = bin_read(\"%s\", %d)},\n", server_bin_file, server_hdr_len, server_bin_file, server_hdr_len);

		fprintf(file_lua, "   actions = {\n");
		for (int i = 0; i < n_actions_in_flow; ++i) {
			struct peer_action *a = &action[i];

			fprintf(file_lua, "      %s_content(%d, %d),\n",
			       a->peer == PEER_CLIENT? "client" : "server",
			       a->beg, a->len);
		}
		fprintf(file_lua, "   },\n");
		fprintf(file_lua, "   l4_proto = \"%s\",\n", pt->proto_id == 0x06? "tcp": "udp");
		fprintf(file_lua, "}\n");

		FILE *f;

		f = fopen(client_bin_file, "w+");
		fwrite(client_hdr, client_hdr_len, 1, f);
		fwrite(client_content, client_content_len, 1, f);
		fclose(f);

		f = fopen(server_bin_file, "w+");
		fwrite(server_hdr, server_hdr_len, 1, f);
		fwrite(server_content, server_content_len, 1, f);
		fclose(f);

		/* TODO: Other options */
	}


	const void *next_key2;
	void *next_data2;
	uint32_t iter2 = 0;
	int pos2;

	uint32_t bundle_count = 1;

	fprintf(file_lua, "bundles = {}\n");
	while ((pos2 = rte_hash_iterate(hash_bundles, &next_key2, &next_data2, &iter2)) >= 0) {
		struct bundle_entry *entry = &hash_bundle_entries[pos2];
		struct pkt_tuple *pt = entry->pkt_entry->tuple;
		uint32_t be_src_ip = pt->src_addr;
		uint16_t be_src_port = pt->src_port;

		fprintf(file_lua, "bundles[%d] = {}\n", bundle_count);
		fprintf(file_lua, "bundles[%d].streams = {", bundle_count);
		do {
			fprintf(file_lua, "stream_%d, ", entry->pkt_entry->stream_id);
		} while ((entry = entry->next));
		fprintf(file_lua, "}\n");

		fprintf(file_lua, "bundles[%d].clients = {\n", bundle_count);
		fprintf(file_lua, "   ip   = ip(\"%s\"), ip_mask = 0x0,\n", ip_to_str(be_src_ip));
		fprintf(file_lua, "   port = %d, port_mask = 0xffff,\n", rte_bswap16(be_src_port));
		fprintf(file_lua, "}\n");

		entry = &hash_bundle_entries[pos2];

		do {
			struct pkt_tuple *pt = entry->pkt_entry->tuple;
			uint32_t be_dst_ip = pt->dst_addr;
			uint16_t be_dst_port = pt->dst_port;

			/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Need application layer graph to avoid the following workaround. A single server instance will then be able to reply to messages depending on what has been sent. */
			while (check_exists(be_dst_ip, be_dst_port)) {
				be_dst_port = rte_bswap16(rte_bswap16(be_dst_port) + 1);
			}

			fprintf(file_lua, "stream_%d.servers = {\n", entry->pkt_entry->stream_id);
			fprintf(file_lua, "   ip   = ip(\"%s\"), ip_mask = 0x0,\n", ip_to_str(be_dst_ip));
			fprintf(file_lua, "   port = %d, port_mask = 0x0,\n", rte_bswap16(be_dst_port));
			fprintf(file_lua, "}\n");

		} while ((entry = entry->next));

		bundle_count++;
	}



	fprintf(file_lua, 	"\n\n\n\nclient_streams = {};\n\n"
		"for i, e in ipairs(bundles) do\n"
		"      client_streams[i] = {bundle = e, imix_fraction = 1}\n"
		"end\n"
		"\n"
		"n_listen = 0\n"
		"server_streams = {}\n"
		"for i, e in ipairs(client_streams) do\n"
		"   for j, stream in ipairs(e.bundle.streams) do\n"
		"      n_listen = n_listen + 1\n"
		"      server_streams[n_listen] = stream\n"
		"   end\n"
		"end\n");
	fclose(file_lua);

#if 0
	char file_name[128];
	iter2 = 0;

	while ((pos2 = rte_hash_iterate(hash_bundles, &next_key2, &next_data2, &iter2)) >= 0) {
		struct bundle_entry *entry = &hash_bundle_entries[pos2];
		struct pkt_tuple *pt = entry->pkt_entry->tuple;

		do {
			snprintf(file_name, sizeof(file_name), "/home/bn/bundle-pcaps/stream-%d.pcap", entry->pkt_entry->stream_id);
			pkt_entry_to_pcap(entry->pkt_entry, file_name, 0);
			pkt_entry_to_pcap(NULL, NULL, 1);
		} while ((entry = entry->next));
		streams++;
	}
#endif
	printf("Finished with %d bundles\n", bundle_count);
	return 0;
}

int main(int argc, char *argv[])
{
	int new_argc = argc, skipped = 0;
	const char *app_name = argv[0];

	for (int i = 0; i < argc; ++i) {
		if (!strcmp(argv[i], "--")) {
			new_argc = i;
			skipped = i + 1;
			break;
		}
	}


	int ret = rte_eal_init(new_argc, argv);

	argv += skipped;
	argc -= skipped;

	if (argc != 1) {
		usage(app_name);
		return EXIT_FAILURE;
	}

	strcpy(app_cfg.file_path_pcap, argv[0]);
	return func(0);
}
