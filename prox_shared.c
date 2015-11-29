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

#include "prox_shared.h"
#include "prox_globals.h"

#define N_SHARED_DATA 128

struct prox_sh {
	char name[128];
	void *data;
};

struct prox_sh sh_system[N_SHARED_DATA];
uint32_t n_sh_system;

struct prox_sh sh_socket[MAX_SOCKETS][N_SHARED_DATA];
uint32_t n_sh_socket[MAX_SOCKETS];

struct prox_sh sh_core[RTE_MAX_LCORE][N_SHARED_DATA];
uint32_t n_sh_core[RTE_MAX_LCORE];

static int prox_sh_add(struct prox_sh *sh, uint32_t *n, const char *name, void *data)
{
	if (*n == N_SHARED_DATA)
		return -1;

	for (uint32_t i = 0; i < *n; ++i) {
		if (!strcmp(sh[i].name, name)) {
			return -1;
		}
	}

	strncpy(sh[*n].name, name, 128);
	sh[*n].data = data;
	(*n)++;
	return 0;
}

static void *prox_sh_find(struct prox_sh *sh, const uint32_t n, const char *name)
{
	for (uint32_t i = 0; i < n; ++i) {
		if (!strcmp(sh[i].name, name)) {
			return sh[i].data;
		}
	}

	return NULL;
}

int prox_sh_add_system(const char *name, void *data)
{
	return prox_sh_add(sh_system, &n_sh_system, name, data);
}

int prox_sh_add_socket(const int socket_id, const char *name, void *data)
{
	if (socket_id >= MAX_SOCKETS)
		return -1;

	return prox_sh_add(sh_socket[socket_id], &n_sh_socket[socket_id], name, data);
}

int prox_sh_add_core(const int core_id, const char *name, void *data)
{
	if (core_id >= RTE_MAX_LCORE)
		return -1;

	return prox_sh_add(sh_core[core_id], &n_sh_core[core_id], name, data);
}

void *prox_sh_find_system(const char *name)
{
	return prox_sh_find(sh_system, n_sh_system, name);
}

void *prox_sh_find_socket(const int socket_id, const char *name)
{
	if (socket_id >= MAX_SOCKETS)
		return NULL;

	return prox_sh_find(sh_socket[socket_id], n_sh_socket[socket_id], name);
}

void *prox_sh_find_core(const int core_id, const char *name)
{
	if (core_id >= RTE_MAX_LCORE)
		return NULL;

	return prox_sh_find(sh_core[core_id], n_sh_core[core_id], name);
}
