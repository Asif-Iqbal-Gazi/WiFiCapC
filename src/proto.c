/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "proto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"

#define MAX_TOKENS 64

/* Run E (an emitter call returning ssize_t). On overflow return -1, else
 * advance pos. Keeps each call site to one statement. */
#define EMIT(E) do {                          \
		ssize_t _r = (E);                     \
		if (_r < 0) return -1;                \
		pos = (size_t)_r;                     \
	} while (0)

/*
 * Append n bytes of src into buf at pos, keeping it NUL-terminated.
 * Returns new pos, or -1 if it would overflow cap (must keep room for NUL).
 */
static ssize_t append_raw(char *buf, size_t cap, size_t pos,
                          const char *src, size_t n)
{
	if (pos + n + 1 > cap)
		return -1;
	memcpy(buf + pos, src, n);
	pos += n;
	buf[pos] = '\0';
	return (ssize_t)pos;
}

static ssize_t append_str(char *buf, size_t cap, size_t pos, const char *s)
{
	return append_raw(buf, cap, pos, s, strlen(s));
}

ssize_t proto_append(char *buf, size_t cap, size_t pos, const char *s)
{
	return append_raw(buf, cap, pos, s, strlen(s));
}

ssize_t proto_escape_string(char *buf, size_t cap, size_t pos, const char *s)
{
	if (pos + 1 + 1 > cap) return -1;
	buf[pos++] = '"';
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		const char *esc = NULL;
		char ubuf[8];
		switch (*p) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\b': esc = "\\b";  break;
		case '\f': esc = "\\f";  break;
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
			if (pos + l + 2 > cap) return -1;
			memcpy(buf + pos, esc, l);
			pos += l;
		} else {
			if (pos + 1 + 2 > cap) return -1;
			buf[pos++] = (char)*p;
		}
	}
	if (pos + 1 + 1 > cap) return -1;
	buf[pos++] = '"';
	buf[pos]   = '\0';
	return (ssize_t)pos;
}

static ssize_t comma_if_needed(char *buf, size_t cap, size_t pos, int *first)
{
	if (*first) {
		*first = 0;
		return (ssize_t)pos;
	}
	return append_raw(buf, cap, pos, ",", 1);
}

ssize_t proto_field_str(char *buf, size_t cap, size_t pos, int *first,
                        const char *key, const char *val)
{
	EMIT(comma_if_needed(buf, cap, pos, first));
	EMIT(proto_escape_string(buf, cap, pos, key));
	EMIT(append_raw(buf, cap, pos, ":", 1));
	EMIT(proto_escape_string(buf, cap, pos, val));
	return (ssize_t)pos;
}

ssize_t proto_field_int(char *buf, size_t cap, size_t pos, int *first,
                        const char *key, int64_t val)
{
	char num[32];
	int  n = snprintf(num, sizeof num, "%lld", (long long)val);
	if (n < 0 || (size_t)n >= sizeof num) return -1;
	EMIT(comma_if_needed(buf, cap, pos, first));
	EMIT(proto_escape_string(buf, cap, pos, key));
	EMIT(append_raw(buf, cap, pos, ":", 1));
	EMIT(append_raw(buf, cap, pos, num, (size_t)n));
	return (ssize_t)pos;
}

ssize_t proto_field_bool(char *buf, size_t cap, size_t pos, int *first,
                         const char *key, int val)
{
	const char *s = val ? "true" : "false";
	EMIT(comma_if_needed(buf, cap, pos, first));
	EMIT(proto_escape_string(buf, cap, pos, key));
	EMIT(append_raw(buf, cap, pos, ":", 1));
	EMIT(append_str(buf, cap, pos, s));
	return (ssize_t)pos;
}

ssize_t proto_reply_ok_begin(char *buf, size_t cap, size_t pos, int64_t id)
{
	char hdr[64];
	int  n = snprintf(hdr, sizeof hdr,
	                  "{\"id\":%lld,\"ok\":true,\"data\":{",
	                  (long long)id);
	if (n < 0 || (size_t)n >= sizeof hdr) return -1;
	return append_raw(buf, cap, pos, hdr, (size_t)n);
}

ssize_t proto_reply_err(char *buf, size_t cap, size_t pos,
                        int64_t id, const char *err)
{
	char hdr[64];
	int  n = snprintf(hdr, sizeof hdr,
	                  "{\"id\":%lld,\"ok\":false,\"error\":",
	                  (long long)id);
	if (n < 0 || (size_t)n >= sizeof hdr) return -1;
	EMIT(append_raw(buf, cap, pos, hdr, (size_t)n));
	EMIT(proto_escape_string(buf, cap, pos, err));
	EMIT(append_raw(buf, cap, pos, "}\n", 2));
	return (ssize_t)pos;
}

ssize_t proto_reply_end(char *buf, size_t cap, size_t pos)
{
	return append_raw(buf, cap, pos, "}}\n", 3);
}

ssize_t proto_event_begin(char *buf, size_t cap, size_t pos, const char *tag)
{
	EMIT(append_str(buf, cap, pos, "{\"event\":"));
	EMIT(proto_escape_string(buf, cap, pos, tag));
	EMIT(append_str(buf, cap, pos, ",\"data\":{"));
	return (ssize_t)pos;
}

ssize_t proto_event_end(char *buf, size_t cap, size_t pos)
{
	return proto_reply_end(buf, cap, pos);
}

/* ---- parsing ----------------------------------------------------------- */

static int tok_eq(const char *json, jsmntok_t *t, const char *s)
{
	if (t->type != JSMN_STRING) return 0;
	int len = t->end - t->start;
	return (int)strlen(s) == len && memcmp(json + t->start, s, len) == 0;
}

static void tok_terminate(char *json, jsmntok_t *t)
{
	json[t->end] = '\0';
}

int proto_parse_request(char *line, size_t len,
                        struct proto_request *req,
                        const char **err)
{
	jsmn_parser p;
	jsmntok_t   toks[MAX_TOKENS];

	req->id       = -1;
	req->cmd      = NULL;
	req->args_raw = NULL;

	jsmn_init(&p);
	int n = jsmn_parse(&p, line, len, toks, MAX_TOKENS);
	if (n < 0) {
		*err = "malformed json";
		return -1;
	}
	if (n < 1 || toks[0].type != JSMN_OBJECT) {
		*err = "expected json object";
		return -1;
	}

	for (int i = 1; i < n; i++) {
		if (toks[i].parent != 0) continue;          /* only top-level keys */
		if (i + 1 >= n)          { *err = "truncated"; return -1; }

		jsmntok_t *k = &toks[i];
		jsmntok_t *v = &toks[i + 1];

		if (tok_eq(line, k, "id") && v->type == JSMN_PRIMITIVE) {
			tok_terminate(line, v);
			req->id = strtoll(line + v->start, NULL, 10);
		} else if (tok_eq(line, k, "cmd") && v->type == JSMN_STRING) {
			tok_terminate(line, v);
			req->cmd = line + v->start;
		} else if (tok_eq(line, k, "args") &&
		           (v->type == JSMN_OBJECT || v->type == JSMN_ARRAY)) {
			tok_terminate(line, v);
			req->args_raw = line + v->start;
		}
	}

	if (!req->cmd) {
		*err = "missing cmd";
		return -1;
	}
	return 0;
}

/* ---- args extraction ---------------------------------------------------- */

/* Scan a JSON object string and return a token-table that locates the value
 * for `key` at the top level. The caller passes in scratch storage for the
 * tokens. Returns the index of the value token, or -1 if not found. */
static int find_top_level_value(const char *json, jsmntok_t *toks, int max,
                                const char *key, int *n_out)
{
	jsmn_parser p;
	jsmn_init(&p);
	int n = jsmn_parse(&p, json, strlen(json), toks, (unsigned)max);
	if (n < 1 || toks[0].type != JSMN_OBJECT) return -1;
	*n_out = n;

	int klen = (int)strlen(key);
	for (int i = 1; i < n; i++) {
		if (toks[i].parent != 0) continue;
		if (toks[i].type   != JSMN_STRING) continue;
		int len = toks[i].end - toks[i].start;
		if (len == klen && memcmp(json + toks[i].start, key, (size_t)klen) == 0) {
			if (i + 1 >= n) return -1;
			return i + 1;
		}
	}
	return -1;
}

int proto_args_get_int(const char *args_raw, const char *key, int64_t *out)
{
	if (!args_raw) return -1;
	jsmntok_t toks[32];
	int total = 0;
	int vi = find_top_level_value(args_raw, toks, 32, key, &total);
	if (vi < 0 || toks[vi].type != JSMN_PRIMITIVE) return -1;

	char buf[32];
	int  len = toks[vi].end - toks[vi].start;
	if (len <= 0 || (size_t)len >= sizeof buf) return -1;
	memcpy(buf, args_raw + toks[vi].start, (size_t)len);
	buf[len] = '\0';

	if (buf[0] != '-' && (buf[0] < '0' || buf[0] > '9')) return -1;
	char *end;
	errno = 0;
	long long v = strtoll(buf, &end, 10);
	if (errno || *end != '\0') return -1;
	*out = (int64_t)v;
	return 0;
}

int proto_args_get_str(const char *args_raw, const char *key,
                       char *out, size_t out_cap)
{
	if (!args_raw || out_cap == 0) return -1;
	jsmntok_t toks[32];
	int total = 0;
	int vi = find_top_level_value(args_raw, toks, 32, key, &total);
	if (vi < 0 || toks[vi].type != JSMN_STRING) return -1;

	int len = toks[vi].end - toks[vi].start;
	if (len < 0 || (size_t)len >= out_cap) return -1;
	memcpy(out, args_raw + toks[vi].start, (size_t)len);
	out[len] = '\0';
	return 0;
}

int proto_args_get_int_array(const char *args_raw, const char *key,
                             int *out, int max, int *n)
{
	if (!args_raw || !out || !n || max <= 0) return -1;
	jsmntok_t toks[128];
	int total = 0;
	int vi = find_top_level_value(args_raw, toks, 128, key, &total);
	if (vi < 0 || toks[vi].type != JSMN_ARRAY) return -1;

	int parent = vi;
	int wrote  = 0;

	for (int i = vi + 1; i < total && wrote < max; i++) {
		if (toks[i].parent != parent) continue;
		if (toks[i].type   != JSMN_PRIMITIVE) return -1;

		char buf[32];
		int  len = toks[i].end - toks[i].start;
		if (len <= 0 || (size_t)len >= sizeof buf) return -1;
		memcpy(buf, args_raw + toks[i].start, (size_t)len);
		buf[len] = '\0';

		char *end;
		errno = 0;
		long v = strtol(buf, &end, 10);
		if (errno || *end != '\0' || v < 0 || v > 65535) return -1;
		out[wrote++] = (int)v;
	}
	*n = wrote;
	return 0;
}
