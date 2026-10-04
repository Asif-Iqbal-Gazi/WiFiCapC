/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_IPC_H
#define WIFICAPC_IPC_H

#include <stddef.h>
#include <stdint.h>
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

/*
 * Per-client event subscriptions (X4). Every event belongs to one of these
 * categories; a client starts subscribed to all of them and can narrow via
 * the subscribe/unsubscribe IPC commands (e.g. the agent drops IFACE to
 * avoid the 4/sec iface.channel ticks it ignores). ipc.c only does the
 * bitmask filter; the event-name <-> bit mapping lives in main.c.
 */
enum {
	IPC_EVT_AP_NEW    = 1u << 0,
	IPC_EVT_AP_LOST   = 1u << 1,
	IPC_EVT_STA_NEW   = 1u << 2,
	IPC_EVT_STA_LOST  = 1u << 3,
	IPC_EVT_HANDSHAKE = 1u << 4,  /* handshake.*/ /* + pmkid.captured */
	IPC_EVT_IFACE     = 1u << 5,  /* iface.channel + iface.mode */
};
/* Macro, not an enumerator: 0xffffffff exceeds int range (ISO C < C23). */
#define IPC_EVT_ALL 0xffffffffu

/* Send an event line only to clients subscribed to (any bit of) `mask`. */
int  ipc_broadcast_event(struct ipc *s, uint32_t mask,
                         const char *line, size_t len);

/* Add / remove subscription bits for one client. Returns 0, or -1 if the
 * fd is not a connected client. */
int  ipc_client_subscribe  (struct ipc *s, int client_fd, uint32_t bits);
int  ipc_client_unsubscribe(struct ipc *s, int client_fd, uint32_t bits);

/*
 * Register an arbitrary fd into the server's epoll loop. Used by the channel
 * hopper (timerfd) and, later, by the AF_PACKET capture socket.
 *
 * The callback fires whenever epoll reports `events` on the fd. Up to 8
 * extra fds may be registered.
 */
typedef void (*ipc_on_fd_fn)(int fd, uint32_t events, void *user);

int ipc_add_fd   (struct ipc *s, int fd, uint32_t events,
                  ipc_on_fd_fn cb, void *user);
int ipc_remove_fd(struct ipc *s, int fd);

#endif
