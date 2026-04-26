/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_CHANHOP_H
#define WIFICAPC_CHANHOP_H

#include "iface.h"

/*
 * chanhop: timerfd-driven channel hopping over a fixed list.
 *
 * Owns one timerfd, registered with the main epoll loop. On each tick it
 * advances the cursor, calls iface_set_channel, and emits an event.
 *
 * Single hopper per process (the underlying iface only has one current chan).
 */

#define CHANHOP_MAX_CHANNELS 64

struct chanhop;

typedef void (*chanhop_on_tick_fn)(int channel, int freq_mhz, void *user);

/* Create a hopper bound to iface i. The provided ipc handle is remembered
 * so the timerfd can be properly unregistered when the hopper is freed. */
struct ipc;
struct chanhop *chanhop_create(struct iface *i, struct ipc *ipc);
void           chanhop_destroy(struct chanhop *h);

/* Start hopping over the given channels at interval_ms per tick.
 * If already running, restarts with the new schedule. n must be 1..CHANHOP_MAX_CHANNELS.
 * interval_ms must be > 0. The first channel is set immediately (synchronous). */
int  chanhop_start(struct chanhop *h, const int *channels, int n, int interval_ms);

/* Stop hopping. The current channel remains where it was last set. */
int  chanhop_stop(struct chanhop *h);

/* Pin to a single channel (stops any active hop). */
int  chanhop_pin(struct chanhop *h, int channel);

/* Status helpers. */
int  chanhop_is_running(const struct chanhop *h);
int  chanhop_current(const struct chanhop *h);

/* Register a callback fired on each successful channel change. */
void chanhop_set_on_tick(struct chanhop *h, chanhop_on_tick_fn cb, void *user);

/* Called by the main loop when the hopper's timerfd is readable. */
void chanhop_on_timer(struct chanhop *h);

/* Returns the timerfd so the main loop can map epoll events back to the hopper. */
int  chanhop_fd(const struct chanhop *h);

#endif
