/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

static enum log_level g_level   = LL_INFO;
static int            g_syslog  = 0;

static const char *level_name(enum log_level lvl)
{
	switch (lvl) {
	case LL_ERR:   return "ERR";
	case LL_WARN:  return "WRN";
	case LL_INFO:  return "INF";
	case LL_DEBUG: return "DBG";
	}
	return "???";
}

static int level_to_syslog(enum log_level lvl)
{
	switch (lvl) {
	case LL_ERR:   return LOG_ERR;
	case LL_WARN:  return LOG_WARNING;
	case LL_INFO:  return LOG_INFO;
	case LL_DEBUG: return LOG_DEBUG;
	}
	return LOG_INFO;
}

void log_init(enum log_level level, int use_syslog)
{
	g_level  = level;
	g_syslog = use_syslog;
	if (g_syslog)
		openlog("wificapc", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void log_close(void)
{
	if (g_syslog)
		closelog();
}

void log_set_level(enum log_level level)
{
	g_level = level;
}

void log_msg(enum log_level level, const char *fmt, ...)
{
	if (level > g_level)
		return;

	va_list ap;
	va_start(ap, fmt);

	if (g_syslog) {
		vsyslog(level_to_syslog(level), fmt, ap);
	} else {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);
		char tbuf[32];
		strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);
		fprintf(stderr, "%s.%03ld %s ", tbuf, ts.tv_nsec / 1000000,
		        level_name(level));
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	}

	va_end(ap);
}
