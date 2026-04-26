/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_LOG_H
#define WIFICAPC_LOG_H

#include <stdarg.h>

enum log_level {
	LL_ERR   = 0,
	LL_WARN  = 1,
	LL_INFO  = 2,
	LL_DEBUG = 3,
};

void log_init(enum log_level level, int use_syslog);
void log_close(void);
void log_set_level(enum log_level level);

void log_msg(enum log_level level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define log_err(...)   log_msg(LL_ERR,   __VA_ARGS__)
#define log_warn(...)  log_msg(LL_WARN,  __VA_ARGS__)
#define log_info(...)  log_msg(LL_INFO,  __VA_ARGS__)
#define log_debug(...) log_msg(LL_DEBUG, __VA_ARGS__)

#endif
