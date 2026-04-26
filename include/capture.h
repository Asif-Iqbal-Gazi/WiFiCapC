/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_CAPTURE_H
#define WIFICAPC_CAPTURE_H

#include "iface.h"
#include "table.h"

#include <stdint.h>

/*
 * Raw 802.11 capture via AF_PACKET on a monitor-mode interface.
 *
 * One capture instance per process. Owns:
 *   - the AF_PACKET socket bound to the iface
 *   - a periodic timerfd that drives table_evict_expired
 *
 * Both fds are registered with the parent epoll loop via ipc_add_fd.
 */

struct capture;
struct ipc;     /* forward decl from ipc.h */

struct capture *capture_create(struct iface *iface,
                               struct table *table,
                               struct ipc   *ipc);

void capture_destroy(struct capture *c);

/* Open the AF_PACKET socket and register both the socket and the eviction
 * timer with the epoll loop. Returns 0 on success. The iface MUST already be
 * in monitor mode and link-up. */
int  capture_start(struct capture *c);

/* Close the socket and disarm the timer. Safe to call when not started. */
int  capture_stop(struct capture *c);

int  capture_is_running(const struct capture *c);

/* Counters for diagnostics. */
uint64_t capture_frames_total(const struct capture *c);
uint64_t capture_frames_dropped(const struct capture *c);

#endif
