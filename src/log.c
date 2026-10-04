/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

static enum log_level  g_level   = LL_INFO;
static int             g_syslog  = 0;
static enum log_format g_format  = LOG_FMT_TEXT;

static const char *level_name_lc(enum log_level lvl)
{
	switch (lvl) {
	case LL_ERR:   return "error";
	case LL_WARN:  return "warn";
	case LL_INFO:  return "info";
	case LL_DEBUG: return "debug";
	}
	return "unknown";
}

/* Append `in` to `out` (cap bytes incl. NUL) as a JSON string body, escaping
 * per RFC 8259. Returns bytes written (excl. NUL). */
static size_t json_escape(char *out, size_t cap, const char *in)
{
	size_t o = 0;
	for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
		const char *esc = NULL;
		char ubuf[8];
		switch (*p) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\n': esc = "\\n";  break;
		case '\r': esc = "\\r";  break;
		case '\t': esc = "\\t";  break;
		default:
			if (*p < 0x20) {
				snprintf(ubuf, sizeof ubuf, "\\u%04x", *p);
				esc = ubuf;
			}
			break;
		}
		if (esc) {
			size_t l = strlen(esc);
			if (o + l + 1 >= cap) break;
			memcpy(out + o, esc, l);
			o += l;
		} else {
			if (o + 2 >= cap) break;
			out[o++] = (char)*p;
		}
	}
	out[o] = '\0';
	return o;
}

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

void log_set_format(enum log_format fmt)
{
	g_format = fmt;
}

void log_msg(enum log_level level, const char *fmt, ...)
{
	if (level > g_level)
		return;

	va_list ap;
	va_start(ap, fmt);

	if (g_syslog) {
		vsyslog(level_to_syslog(level), fmt, ap);
	} else if (g_format == LOG_FMT_JSON) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		struct tm tm;
		localtime_r(&ts.tv_sec, &tm);
		char tbuf[32];
		strftime(tbuf, sizeof tbuf, "%Y-%m-%dT%H:%M:%S", &tm);
		char msg[1024], esc[2048];
		vsnprintf(msg, sizeof msg, fmt, ap);
		json_escape(esc, sizeof esc, msg);
		fprintf(stderr, "{\"ts\":\"%s.%03ldZ\",\"level\":\"%s\",\"msg\":\"%s\"}\n",
		        tbuf, ts.tv_nsec / 1000000, level_name_lc(level), esc);
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
