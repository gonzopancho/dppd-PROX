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

#ifndef _LOG_H_
#define _LOG_H_

#define PROX_LOG_ERR  0
#define PROX_LOG_WARN 1
#define PROX_LOG_INFO 2
#define PROX_LOG_DBG  3

#if PROX_MAX_LOG_LVL > PROX_LOG_DBG
#error Highest supported log level is 3
#endif

int get_n_warnings(void);
/* Return previous warnings, only stores last 5 warnings and invalid i return NULL*/
const char* get_warning(int i);

struct rte_mbuf;

#if PROX_MAX_LOG_LVL >= PROX_LOG_ERR
void plog_err(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogx_err(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogd_err(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
void plogdx_err(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline void plog_err(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 1, 2))) static inline void plogx_err(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogd_err(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogdx_err(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_WARN
void plog_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogx_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogd_warn(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
void plogdx_warn(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline void plog_warn(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 1, 2))) static inline void plogx_warn(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogd_warn(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogdx_warn(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_INFO
void plog_info(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogx_info(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogd_info(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
void plogdx_info(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline void plog_info(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 1, 2))) static inline void plogx_info(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogd_info(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogdx_info(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_DBG
void plog_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogx_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
void plogd_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
void plogdx_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline void plog_dbg(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 1, 2))) static inline void plogx_dbg(__attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogd_dbg(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
__attribute__((format(printf, 2, 3))) static inline void plogdx_dbg(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {}
#endif

void plog_init(const char *log_name, int log_name_pid);
int plog_set_lvl(int lvl);

#endif /* _LOG_H_ */
