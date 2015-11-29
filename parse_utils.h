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

#ifndef _PARSE_UTILS_H_
#define _PARSE_UTILS_H_

#include <inttypes.h>
#include "ip_subnet.h"

struct ipv6_addr;
struct ether_addr;

int parse_int_mask(uint32_t* val, uint32_t* mask, const char *saddr);

int parse_range(uint32_t* lo, uint32_t* hi, const char *saddr);

/* parses CIDR notation. Note that bits within the address that are
   outside the subnet (as specified by the prefix) are set to 0. */
int parse_ip4_cidr(struct ip4_subnet *val, const char *saddr);
int parse_ip6_cidr(struct ip6_subnet *val, const char *saddr);

int parse_ip(uint32_t *paddr, const char *saddr);

int parse_ip6(struct ipv6_addr *addr, const char *saddr);

int parse_mac(struct ether_addr *paddr, const char *saddr);

/* return error on overflow or invalid suffix*/
int parse_kmg(uint32_t* val, const char *str);

int parse_bool(uint32_t* val, const char *str);

int parse_flag(uint32_t* val, uint32_t flag, const char *str);

int parse_list_set(uint32_t *list, const char *str, uint32_t max_limit);

int parse_int(uint32_t* val, const char *str);

int parse_str(char* dst, const char *str, size_t max_len);

int parse_path(char *dst, const char *str, size_t max_len);

int parse_port_name(uint32_t *val, const char *str);

int parse_port_name_list(uint32_t *val, uint32_t *tot, uint8_t max_vals, const char *str);

/* Parses a comma separated list containing a remapping of ports
   specified by their name. Hence, all port names referenced from the
   list have to be added using add_port_name() before this function
   can be used. The first elements in the list are mapped to 0, the
   second to 1, etc. Multiple elements can be mapped to the same
   index. If multiple elements are used, they are separated by
   pipes. An example would be p0|p1,p2|p3. In this example, p0 and p1
   both map to 0 and p2 and p3 map both map to 1. The mapping should
   contain at least enough entries as port ids. */
int parse_remap(uint8_t *mapping, const char *str);

int add_port_name(uint32_t val, const char *str);

int add_var(const char* name, const char *val, uint8_t cli);

/* Parses str and returns pointer to the key value */
char *get_cfg_key(char *str);

/* Changes strings in place. */
void strip_spaces(char *strings[], const uint32_t count);

/* Contains error string if any of the above returned an error. */
const char* get_parse_err(void);

#endif /* _PARSE_UTILS_H_ */
