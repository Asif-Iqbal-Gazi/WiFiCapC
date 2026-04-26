/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "handshake.h"
#include "log.h"
#include "pcap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct hs_pair {
	int                 in_use;
	uint8_t             ap_bssid[6];
	uint8_t             sta_mac[6];
	int                 channel;
	int                 rssi;
	struct pcap_writer *pcap;
	char                pcap_path[256];
	uint8_t             msg_bitmap;       /* bit i set if M(i+1) seen */
	int                 have_pmkid;
	int                 emitted_handshake;
	int                 emitted_pmkid;
	time_t              first_seen;
	time_t              last_seen;
};

struct handshake {
	struct table   *table;
	char            dir[128];   /* keeps dir + "/<12hex>_<12hex>.pcap" < 256 */
	int             stale_timeout;
	hs_emit_fn      emit;
	void           *user;
	struct hs_pair  pairs[HS_MAX_PAIRS];
	int             n_pairs;
};

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) { return memcmp(a, b, 6) == 0; }

/* Direction-aware pair lookup: a frame may flow AP→STA or STA→AP, so a
 * (bssid, sa) pair is the same handshake whether sa==STA or sa==BSSID. */
static struct hs_pair *find_pair(struct handshake *h,
                                 const uint8_t ap[6], const uint8_t sta[6])
{
	for (int i = 0; i < HS_MAX_PAIRS; i++) {
		struct hs_pair *p = &h->pairs[i];
		if (!p->in_use) continue;
		if (mac_eq(p->ap_bssid, ap) && mac_eq(p->sta_mac, sta)) return p;
	}
	return NULL;
}

static struct hs_pair *alloc_pair(struct handshake *h)
{
	for (int i = 0; i < HS_MAX_PAIRS; i++)
		if (!h->pairs[i].in_use) return &h->pairs[i];
	return NULL;
}

static int ensure_dir(const char *path)
{
	if (mkdir(path, 0700) == 0) return 0;
	if (errno == EEXIST)        return 0;
	log_err("mkdir(%s): %s", path, strerror(errno));
	return -1;
}

static void mac_hex(const uint8_t m[6], char out[13])
{
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x",
	         m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void payload_emit(struct handshake *h, enum hs_event evt,
                         const struct hs_pair *p,
                         const char *hash22000_path)
{
	if (!h->emit) return;
	struct hs_emit_payload pl = {
		.pcap_path       = p->pcap_path[0] ? p->pcap_path : NULL,
		.hash22000_path  = hash22000_path,
		.channel         = p->channel,
		.rssi            = p->rssi,
		.msg_seen_bitmap = p->msg_bitmap,
		.have_pmkid      = p->have_pmkid,
	};
	memcpy(pl.ap_bssid, p->ap_bssid, 6);
	memcpy(pl.sta_mac,  p->sta_mac,  6);
	h->emit(evt, &pl, h->user);
}

static int open_pcap_for_pair(struct handshake *h, struct hs_pair *p)
{
	if (p->pcap) return 0;
	if (ensure_dir(h->dir) < 0) return -1;

	char ap_hex[13], sta_hex[13];
	mac_hex(p->ap_bssid, ap_hex);
	mac_hex(p->sta_mac,  sta_hex);
	snprintf(p->pcap_path, sizeof p->pcap_path,
	         "%s/%s_%s.pcap", h->dir, ap_hex, sta_hex);

	p->pcap = pcap_open(p->pcap_path);
	if (!p->pcap) {
		p->pcap_path[0] = '\0';
		return -1;
	}

	/* Prepend the most recent beacon for this AP, if we have one cached.
	 * Without it hcxpcapngtool can collect MIC/nonces but won't produce
	 * a complete hash because the SSID is unknown. */
	const struct ap_record *ap = table_find_ap(h->table, p->ap_bssid);
	if (ap && ap->last_beacon_len > 0)
		(void)pcap_write(p->pcap, ap->last_beacon, ap->last_beacon_len);

	log_info("handshake: opened %s", p->pcap_path);
	return 0;
}

static void close_pair(struct handshake *h, struct hs_pair *p)
{
	if (!p->in_use) return;
	if (p->pcap) {
		pcap_close(p->pcap);
		p->pcap = NULL;
	}
	if (h->emit)
		payload_emit(h, HS_EVT_DONE, p, NULL);
	memset(p, 0, sizeof *p);
	h->n_pairs--;
}

struct handshake *handshake_create(struct table *table,
                                   const char *out_dir,
                                   int stale_timeout_sec,
                                   hs_emit_fn cb, void *user)
{
	struct handshake *h = calloc(1, sizeof *h);
	if (!h) return NULL;
	h->table         = table;
	h->stale_timeout = stale_timeout_sec > 0 ? stale_timeout_sec : 30;
	h->emit          = cb;
	h->user          = user;
	if (out_dir)
		snprintf(h->dir, sizeof h->dir, "%s", out_dir);
	else
		snprintf(h->dir, sizeof h->dir, "/tmp/wificapc/handshakes");
	return h;
}

void handshake_destroy(struct handshake *h)
{
	if (!h) return;
	for (int i = 0; i < HS_MAX_PAIRS; i++)
		if (h->pairs[i].in_use)
			close_pair(h, &h->pairs[i]);
	free(h);
}

int handshake_set_dir(struct handshake *h, const char *dir)
{
	if (!dir || !*dir) return -1;
	snprintf(h->dir, sizeof h->dir, "%s", dir);
	return ensure_dir(h->dir);
}

const char *handshake_dir(const struct handshake *h) { return h->dir; }
int         handshake_n_pairs(const struct handshake *h) { return h->n_pairs; }

void handshake_observe(struct handshake *h,
                       const uint8_t *frame, size_t frame_len,
                       const uint8_t *payload, size_t payload_len,
                       const struct dot11_info *d,
                       int channel, int rssi)
{
	if (!h) return;
	if (d->kind != DOT11_FRAME_DATA) return;

	struct eapol_info ek;
	if (eapol_parse(payload, payload_len, d, &ek) < 0) return;
	if (!ek.is_eapol_key) return;

	/* Decide which side is AP vs STA. The dot11 layer already extracted
	 * BSSID; the other party (sa) is by definition the supplicant. But
	 * for AP→STA frames, sa == BSSID, so use d->da as the STA. */
	uint8_t ap[6], sta[6];
	memcpy(ap, d->bssid, 6);
	if (mac_eq(d->sa, ap)) memcpy(sta, d->da, 6);
	else                   memcpy(sta, d->sa, 6);

	struct hs_pair *p = find_pair(h, ap, sta);
	if (!p) {
		p = alloc_pair(h);
		if (!p) {
			log_warn("handshake: pair table full, dropping new pair");
			return;
		}
		memset(p, 0, sizeof *p);
		p->in_use     = 1;
		memcpy(p->ap_bssid, ap, 6);
		memcpy(p->sta_mac,  sta, 6);
		p->first_seen = time(NULL);
		h->n_pairs++;
	}
	p->channel   = channel;
	p->rssi      = rssi;
	p->last_seen = time(NULL);

	if (open_pcap_for_pair(h, p) < 0) return;
	(void)pcap_write(p->pcap, frame, frame_len);

	if (ek.msg >= EAPOL_MSG_M1 && ek.msg <= EAPOL_MSG_M4)
		p->msg_bitmap |= (uint8_t)(1u << (ek.msg - 1));

	if (ek.msg == EAPOL_MSG_M1 && ek.has_pmkid && !p->emitted_pmkid) {
		p->have_pmkid    = 1;
		p->emitted_pmkid = 1;
		log_info("handshake: PMKID captured for %02x:..:%02x → %02x:..:%02x",
		         ap[0], ap[5], sta[0], sta[5]);
		payload_emit(h, HS_EVT_PMKID, p, NULL);
	}

	/* Emit a handshake-captured event the first time we see anything past
	 * M1 — that's the earliest moment the exchange is provably happening. */
	int got_real = (p->msg_bitmap & 0x0E) != 0; /* M2|M3|M4 */
	if (got_real && !p->emitted_handshake) {
		p->emitted_handshake = 1;
		log_info("handshake: 4-way captured for %02x:..:%02x → %02x:..:%02x bitmap=0x%x",
		         ap[0], ap[5], sta[0], sta[5], p->msg_bitmap);
		payload_emit(h, HS_EVT_HANDSHAKE, p, NULL);
	}
}

void handshake_tick(struct handshake *h, time_t now)
{
	for (int i = 0; i < HS_MAX_PAIRS; i++) {
		struct hs_pair *p = &h->pairs[i];
		if (!p->in_use) continue;
		if (now - p->last_seen > h->stale_timeout)
			close_pair(h, p);
	}
}
