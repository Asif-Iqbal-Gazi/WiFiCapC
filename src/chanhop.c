/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "chanhop.h"
#include "ipc.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

struct chanhop {
	struct iface       *iface;
	struct ipc         *ipc;          /* not owned; for fd unregistration */
	int                 timerfd;
	int                 channels[CHANHOP_MAX_CHANNELS];
	int                 n_channels;
	int                 cursor;
	int                 interval_ms;
	int                 running;
	int                 current;      /* last channel actually set */
	chanhop_on_tick_fn  on_tick;
	void               *on_tick_user;
};

struct chanhop *chanhop_create(struct iface *i, struct ipc *ipc)
{
	struct chanhop *h = calloc(1, sizeof *h);
	if (!h) return NULL;

	h->iface    = i;
	h->ipc      = ipc;
	h->timerfd  = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (h->timerfd < 0) {
		log_err("timerfd_create: %s", strerror(errno));
		free(h);
		return NULL;
	}
	return h;
}

void chanhop_destroy(struct chanhop *h)
{
	if (!h) return;
	if (h->timerfd >= 0) {
		/* Unregister BEFORE close so the IPC layer can never call our
		 * on_tick callback after our struct is freed. */
		if (h->ipc) ipc_remove_fd(h->ipc, h->timerfd);
		close(h->timerfd);
	}
	free(h);
}

int chanhop_fd(const struct chanhop *h) { return h->timerfd; }

void chanhop_set_on_tick(struct chanhop *h, chanhop_on_tick_fn cb, void *user)
{
	h->on_tick      = cb;
	h->on_tick_user = user;
}

static int arm_timer(struct chanhop *h, int interval_ms)
{
	struct itimerspec its = {0};
	its.it_value.tv_sec     = interval_ms / 1000;
	its.it_value.tv_nsec    = (long)(interval_ms % 1000) * 1000000L;
	its.it_interval         = its.it_value;
	if (timerfd_settime(h->timerfd, 0, &its, NULL) < 0) {
		log_err("timerfd_settime: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int disarm_timer(struct chanhop *h)
{
	struct itimerspec its = {0};
	if (timerfd_settime(h->timerfd, 0, &its, NULL) < 0) {
		log_err("timerfd_settime(disarm): %s", strerror(errno));
		return -1;
	}
	return 0;
}

int chanhop_start(struct chanhop *h, const int *channels, int n,
                  int interval_ms)
{
	if (!h || !channels || n <= 0 || n > CHANHOP_MAX_CHANNELS ||
	    interval_ms <= 0) {
		errno = EINVAL;
		return -1;
	}

	memcpy(h->channels, channels, (size_t)n * sizeof(int));
	h->n_channels  = n;
	h->cursor      = 0;
	h->interval_ms = interval_ms;

	/* Set first channel synchronously so the caller observes immediate
	 * effect; subsequent hops happen on timer ticks. */
	if (iface_set_channel(h->iface, h->channels[0]) < 0)
		return -1;
	h->current = h->channels[0];
	if (h->on_tick)
		h->on_tick(h->current, h->iface->freq_mhz, h->on_tick_user);

	if (arm_timer(h, interval_ms) < 0)
		return -1;

	h->running = 1;
	log_info("chanhop: %d channels, interval %d ms", n, interval_ms);
	return 0;
}

int chanhop_stop(struct chanhop *h)
{
	if (!h) return -1;
	if (!h->running) return 0;
	disarm_timer(h);
	h->running = 0;
	log_info("chanhop: stopped on channel %d", h->current);
	return 0;
}

int chanhop_pin(struct chanhop *h, int channel)
{
	if (!h) return -1;
	if (h->running) chanhop_stop(h);
	if (iface_set_channel(h->iface, channel) < 0) return -1;
	h->current = channel;
	if (h->on_tick)
		h->on_tick(h->current, h->iface->freq_mhz, h->on_tick_user);
	return 0;
}

int chanhop_is_running(const struct chanhop *h) { return h && h->running; }
int chanhop_current   (const struct chanhop *h) { return h ? h->current : 0; }

void chanhop_on_timer(struct chanhop *h)
{
	uint64_t expirations;
	ssize_t  n = read(h->timerfd, &expirations, sizeof expirations);
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			log_warn("chanhop read: %s", strerror(errno));
		return;
	}
	if (!h->running || h->n_channels == 0) return;

	h->cursor = (h->cursor + 1) % h->n_channels;
	int ch    = h->channels[h->cursor];

	if (iface_set_channel(h->iface, ch) < 0) {
		/* Don't stop the hop — log and try again next tick. */
		log_warn("chanhop: failed to set channel %d", ch);
		return;
	}
	h->current = ch;
	if (h->on_tick)
		h->on_tick(ch, h->iface->freq_mhz, h->on_tick_user);
}
