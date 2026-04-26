/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "table.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

struct table {
	struct ap_record  aps [TABLE_MAX_APS];
	struct sta_record stas[TABLE_MAX_STAS];
	int               ap_ttl;
	int               sta_ttl;
	table_emit_fn     emit;
	void             *user;
	int               n_aps;
	int               n_stas;
};

static int mac_eq(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

static int mac_zero(const uint8_t a[6])
{
	static const uint8_t z[6] = {0};
	return memcmp(a, z, 6) == 0;
}

static struct ap_record *find_ap(struct table *t, const uint8_t bssid[6])
{
	for (int i = 0; i < TABLE_MAX_APS; i++)
		if (t->aps[i].in_use && mac_eq(t->aps[i].bssid, bssid))
			return &t->aps[i];
	return NULL;
}

static struct sta_record *find_sta(struct table *t, const uint8_t mac[6])
{
	for (int i = 0; i < TABLE_MAX_STAS; i++)
		if (t->stas[i].in_use && mac_eq(t->stas[i].mac, mac))
			return &t->stas[i];
	return NULL;
}

static struct ap_record *alloc_ap(struct table *t)
{
	for (int i = 0; i < TABLE_MAX_APS; i++)
		if (!t->aps[i].in_use) return &t->aps[i];
	return NULL;
}

static struct sta_record *alloc_sta(struct table *t)
{
	for (int i = 0; i < TABLE_MAX_STAS; i++)
		if (!t->stas[i].in_use) return &t->stas[i];
	return NULL;
}

struct table *table_create(int ap_ttl, int sta_ttl,
                           table_emit_fn cb, void *user)
{
	struct table *t = calloc(1, sizeof *t);
	if (!t) return NULL;
	t->ap_ttl  = ap_ttl  > 0 ? ap_ttl  : 120;
	t->sta_ttl = sta_ttl > 0 ? sta_ttl : 300;
	t->emit    = cb;
	t->user    = user;
	return t;
}

void table_destroy(struct table *t)
{
	free(t);
}

void table_observe_ap(struct table *t, const struct dot11_info *d,
                      int channel, int rssi, time_t now)
{
	struct ap_record *ap = find_ap(t, d->bssid);
	int is_new = (ap == NULL);

	if (is_new) {
		ap = alloc_ap(t);
		if (!ap) {
			log_warn("table: ap table full, dropping new BSSID");
			return;
		}
		memset(ap, 0, sizeof *ap);
		memcpy(ap->bssid, d->bssid, 6);
		ap->first_seen = now;
		ap->in_use     = 1;
		t->n_aps++;
	}

	if (d->has_ssid) {
		ap->ssid_len = d->ssid_len;
		memcpy(ap->ssid, d->ssid, d->ssid_len + 1);
	}
	/* Prefer the channel from the DS Parameter IE when present (more
	 * accurate than the radio's freq when scanning fast). */
	int ch = d->has_ds_chan ? d->ds_chan : channel;
	if (ch > 0) ap->channel = ch;
	if (rssi != 127) ap->rssi = rssi;
	ap->last_seen = now;
	ap->frames++;

	if (is_new && t->emit)
		t->emit(TABLE_EVT_AP_NEW, ap, NULL, t->user);
}

void table_observe_sta(struct table *t, const struct dot11_info *d,
                       int channel, int rssi, time_t now,
                       const uint8_t *ap_bssid)
{
	struct sta_record *sta = find_sta(t, d->sa);
	int is_new = (sta == NULL);

	if (is_new) {
		sta = alloc_sta(t);
		if (!sta) {
			log_warn("table: sta table full, dropping new MAC");
			return;
		}
		memset(sta, 0, sizeof *sta);
		memcpy(sta->mac, d->sa, 6);
		sta->first_seen = now;
		sta->in_use     = 1;
		t->n_stas++;
	}

	if (channel > 0) sta->channel = channel;
	if (rssi != 127) sta->rssi    = rssi;
	if (ap_bssid && !mac_zero(ap_bssid) && !mac_eq(ap_bssid, (uint8_t[6]){0xff,0xff,0xff,0xff,0xff,0xff})) {
		memcpy(sta->ap_bssid, ap_bssid, 6);
		sta->have_ap = 1;
	}
	sta->last_seen = now;
	sta->frames++;

	if (is_new && t->emit)
		t->emit(TABLE_EVT_STA_NEW, NULL, sta, t->user);
}

void table_evict_expired(struct table *t, time_t now)
{
	for (int i = 0; i < TABLE_MAX_APS; i++) {
		struct ap_record *ap = &t->aps[i];
		if (!ap->in_use) continue;
		if (now - ap->last_seen > t->ap_ttl) {
			if (t->emit)
				t->emit(TABLE_EVT_AP_LOST, ap, NULL, t->user);
			ap->in_use = 0;
			t->n_aps--;
		}
	}
	for (int i = 0; i < TABLE_MAX_STAS; i++) {
		struct sta_record *sta = &t->stas[i];
		if (!sta->in_use) continue;
		if (now - sta->last_seen > t->sta_ttl) {
			if (t->emit)
				t->emit(TABLE_EVT_STA_LOST, NULL, sta, t->user);
			sta->in_use = 0;
			t->n_stas--;
		}
	}
}

void table_clear(struct table *t)
{
	memset(t->aps,  0, sizeof t->aps);
	memset(t->stas, 0, sizeof t->stas);
	t->n_aps  = 0;
	t->n_stas = 0;
}

int table_snapshot_aps(const struct table *t, struct ap_record *out, int max)
{
	int n = 0;
	for (int i = 0; i < TABLE_MAX_APS && n < max; i++)
		if (t->aps[i].in_use) out[n++] = t->aps[i];
	return n;
}

int table_snapshot_stas(const struct table *t, struct sta_record *out, int max)
{
	int n = 0;
	for (int i = 0; i < TABLE_MAX_STAS && n < max; i++)
		if (t->stas[i].in_use) out[n++] = t->stas[i];
	return n;
}

int table_n_aps (const struct table *t) { return t->n_aps;  }
int table_n_stas(const struct table *t) { return t->n_stas; }

void table_cache_beacon(struct table *t, const uint8_t bssid[6],
                        const uint8_t *frame, size_t len)
{
	struct ap_record *ap = find_ap(t, bssid);
	if (!ap) return;
	if (len > TABLE_BEACON_MAX) len = TABLE_BEACON_MAX;
	memcpy(ap->last_beacon, frame, len);
	ap->last_beacon_len = len;
}

const struct ap_record *table_find_ap(const struct table *t, const uint8_t bssid[6])
{
	/* find_ap is non-const internally; this wrapper restores const-correctness
	 * for read-only callers. */
	return find_ap((struct table *)t, bssid);
}
