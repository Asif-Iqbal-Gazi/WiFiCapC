/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_PROTO_H
#define WIFICAPC_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * proto: line-delimited JSON envelope helpers.
 *
 * Three message kinds:
 *   request : {"id":N,"cmd":"...","args":{...}}
 *   reply   : {"id":N,"ok":true|false,"data":{...}|"error":"..."}
 *   event   : {"event":"...","data":{...}}
 */

/* Parsed view of an inbound request. Strings point into the caller-supplied
 * line buffer — valid only until the buffer is reused. */
struct proto_request {
	int64_t     id;             /* -1 if missing */
	const char *cmd;            /* NUL-terminated */
	const char *args_raw;       /* NUL-terminated JSON object/value, or NULL */
};

/* Parse a single line into req. Mutates line (NULs inserted). Returns 0 on
 * success, -1 on malformed input. On failure, *err is filled with a short
 * reason. */
int proto_parse_request(char *line, size_t len,
                        struct proto_request *req,
                        const char **err);

/*
 * Tiny JSON emitter — appends to a caller-supplied buffer with bounded length.
 * All emitters return the new length on success, or -1 if the buffer would
 * overflow. The buffer is always NUL-terminated on success.
 *
 * Typical use:
 *   char buf[1024]; size_t n = 0;
 *   n = proto_reply_ok_begin(buf, sizeof buf, n, req->id);
 *   n = proto_obj_field_str(buf, sizeof buf, n, "pong", "yes");
 *   n = proto_reply_end(buf, sizeof buf, n);
 */

/* Emit a reply prefix:  {"id":N,"ok":true,"data":{   */
ssize_t proto_reply_ok_begin(char *buf, size_t cap, size_t pos, int64_t id);

/* Emit a complete error reply:  {"id":N,"ok":false,"error":"..."}\n */
ssize_t proto_reply_err(char *buf, size_t cap, size_t pos,
                        int64_t id, const char *err);

/* Close the data object started by *_begin and append newline:  }}\n */
ssize_t proto_reply_end(char *buf, size_t cap, size_t pos);

/* Emit an event prefix:  {"event":"TAG","data":{    */
ssize_t proto_event_begin(char *buf, size_t cap, size_t pos, const char *tag);

/* Same as proto_reply_end. */
ssize_t proto_event_end(char *buf, size_t cap, size_t pos);

/* Object-field emitters. They prepend a comma when not the first field
 * inside the current object (caller passes first=1 for the first one and 0
 * thereafter; helper updates *first). Each function escapes string values
 * per RFC 8259. */
ssize_t proto_field_str (char *buf, size_t cap, size_t pos, int *first,
                         const char *key, const char *val);
ssize_t proto_field_int (char *buf, size_t cap, size_t pos, int *first,
                         const char *key, int64_t val);
ssize_t proto_field_bool(char *buf, size_t cap, size_t pos, int *first,
                         const char *key, int val);

/* Append a NUL-terminated raw byte string, escaping per JSON rules. */
ssize_t proto_escape_string(char *buf, size_t cap, size_t pos, const char *s);

#endif
