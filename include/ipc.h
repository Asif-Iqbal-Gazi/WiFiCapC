/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_IPC_H
#define WIFICAPC_IPC_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Single Unix-domain stream socket, multi-client, line-delimited.
 *
 * The owner provides one callback that is invoked for every complete inbound
 * line (excluding the trailing '\n'). The line buffer is mutable and remains
 * valid for the duration of the call only. A reply (zero or more lines)
 * should be appended to the per-client outbox via ipc_send_to.
 *
 * Async events (no inbound trigger) are broadcast via ipc_broadcast.
 */

typedef int (*ipc_on_line_fn)(int client_fd, char *line, size_t len,
                              void *user);

struct ipc;

/* Create the listening socket at sock_path. Existing file is unlinked.
 * Returns the server handle, or NULL on error. */
struct ipc *ipc_create(const char *sock_path, mode_t mode);

void ipc_destroy(struct ipc *s);

void ipc_set_on_line(struct ipc *s, ipc_on_line_fn cb, void *user);

/* Run the event loop until ipc_stop is called. Returns 0 on graceful stop,
 * -1 on fatal error. */
int  ipc_run(struct ipc *s);

void ipc_stop(struct ipc *s);

/* Queue a line (no trailing newline expected) to a single client. The
 * server appends '\n' and flushes when the socket is writable. */
int  ipc_send_to(struct ipc *s, int client_fd,
                 const char *line, size_t len);

/* Send a line to every connected client. */
int  ipc_broadcast(struct ipc *s, const char *line, size_t len);

#endif
