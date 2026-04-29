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

/* Maximum EAPOL M2 packet size we will store (bytes).
 * A typical WPA2 M2 is ~200-300 bytes; 1024 is conservative headroom. */
#define M2_EAPOL_MAX 1024

struct hs_pair {
	int      in_use;
	uint8_t  ap_bssid[6];
	uint8_t  sta_mac[6];
	int      channel;
	int      rssi;
	uint8_t  msg_bitmap;          /* bit i set if M(i+1) seen */
	int      have_pmkid;
	int      emitted_handshake;
	int      emitted_pmkid;
	time_t   first_seen;
	time_t   last_seen;
	char     hash22000_path[256]; /* written by write_hash22000 */
	char     pcap_path[256];      /* per-pair raw capture (radiotap+802.11) */
	struct pcap_writer *pcap;     /* opened on first frame, closed on retire */
	int      beacon_written;      /* the cached beacon was written to pcap */

	/* .22000 assembly material */
	uint8_t  pmkid_bytes[16];
	uint8_t  anonce[32];
	int      have_anonce;
	uint8_t  mic[16];
	uint8_t  m2_eapol[M2_EAPOL_MAX]; /* M2 EAPOL packet, MIC field zeroed */
	size_t   m2_eapol_len;
	int      have_m2;
};

struct handshake {
	struct table  *table;
	char           dir[128];
	int            stale_timeout;
	hs_emit_fn     emit;
	void          *user;
	struct hs_pair pairs[HS_MAX_PAIRS];
	int            n_pairs;
};

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) { return memcmp(a, b, 6) == 0; }

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

static void hex_encode(char *out, const uint8_t *in, size_t n)
{
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[i*2  ] = h[in[i] >> 4];
		out[i*2+1] = h[in[i] & 0xf];
	}
	out[n*2] = '\0';
}

/*
 * Write a hashcat .22000 file for the pair.
 * Writes a PMKID line (WPA*01) if we have the PMKID, and/or an EAPOL line
 * (WPA*02) if we have ANonce + M2.  Does nothing if we have neither.
 */
static void write_hash22000(struct handshake *h, struct hs_pair *p)
{
	if (!p->have_pmkid && !(p->have_anonce && p->have_m2))
		return;

	char ap_hex[13], sta_hex[13];
	mac_hex(p->ap_bssid, ap_hex);
	mac_hex(p->sta_mac,  sta_hex);
	snprintf(p->hash22000_path, sizeof p->hash22000_path,
	         "%s/%s_%s.22000", h->dir, ap_hex, sta_hex);

	/* SSID hex from recon table; empty string if unknown. */
	char ssid_hex[65] = "";
	const struct ap_record *apr = table_find_ap(h->table, p->ap_bssid);
	if (apr && apr->ssid_len > 0)
		hex_encode(ssid_hex, (const uint8_t *)apr->ssid, apr->ssid_len);

	if (ensure_dir(h->dir) < 0) {
		p->hash22000_path[0] = '\0';
		return;
	}

	FILE *f = fopen(p->hash22000_path, "w");
	if (!f) {
		log_err("handshake: open %s: %s", p->hash22000_path, strerror(errno));
		p->hash22000_path[0] = '\0';
		return;
	}

	/* WPA*01 — PMKID line */
	if (p->have_pmkid) {
		char pmkid_hex[33];
		hex_encode(pmkid_hex, p->pmkid_bytes, 16);
		fprintf(f, "WPA*01*%s*%s*%s*%s***\n",
		        pmkid_hex, ap_hex, sta_hex, ssid_hex);
	}

	/* WPA*02 — EAPOL line (needs ANonce + M2 with MIC) */
	if (p->have_anonce && p->have_m2) {
		char mic_hex[33], anonce_hex[65];
		char eapol_hex[M2_EAPOL_MAX * 2 + 1];
		hex_encode(mic_hex,    p->mic,      16);
		hex_encode(anonce_hex, p->anonce,   32);
		hex_encode(eapol_hex,  p->m2_eapol, p->m2_eapol_len);
		/* messagepair: 0=M1+M2, 2=M2+M3 */
		int mp = (p->msg_bitmap & 0x04) && !(p->msg_bitmap & 0x01) ? 2 : 0;
		fprintf(f, "WPA*02*%s*%s*%s*%s*%s*%s*%02x\n",
		        mic_hex, ap_hex, sta_hex, ssid_hex,
		        anonce_hex, eapol_hex, mp);
	}

	fclose(f);
	log_info("handshake: wrote %s", p->hash22000_path);
}

static void payload_emit(struct handshake *h, enum hs_event evt,
                         const struct hs_pair *p)
{
	if (!h->emit) return;
	struct hs_emit_payload pl = {
		.pcap_path       = p->pcap_path[0] ? p->pcap_path : NULL,
		.hash22000_path  = p->hash22000_path[0] ? p->hash22000_path : NULL,
		.channel         = p->channel,
		.rssi            = p->rssi,
		.msg_seen_bitmap = p->msg_bitmap,
		.have_pmkid      = p->have_pmkid,
	};
	memcpy(pl.ap_bssid, p->ap_bssid, 6);
	memcpy(pl.sta_mac,  p->sta_mac,  6);
	h->emit(evt, &pl, h->user);
}

/* Open the per-pair pcap on the first frame we keep, and stamp the most
 * recent beacon at the head — hcxpcapngtool needs the SSID + RSN IE that
 * the beacon carries to assemble a usable handshake. Idempotent. */
static void ensure_pcap(struct handshake *h, struct hs_pair *p)
{
	if (p->pcap) return;
	if (ensure_dir(h->dir) < 0) return;

	char ap_hex[13], sta_hex[13];
	mac_hex(p->ap_bssid, ap_hex);
	mac_hex(p->sta_mac,  sta_hex);
	snprintf(p->pcap_path, sizeof p->pcap_path,
	         "%s/%s_%s.pcap", h->dir, ap_hex, sta_hex);

	p->pcap = pcap_open(p->pcap_path);
	if (!p->pcap) {
		p->pcap_path[0] = '\0';
		return;
	}
	if (h->table) {
		const struct ap_record *apr = table_find_ap(h->table, p->ap_bssid);
		if (apr && apr->last_beacon_len > 0) {
			(void)pcap_write(p->pcap, apr->last_beacon, apr->last_beacon_len);
			p->beacon_written = 1;
		}
	}
}

static void close_pair(struct handshake *h, struct hs_pair *p)
{
	if (!p->in_use) return;
	write_hash22000(h, p);

	/* A pair is "usable" iff write_hash22000 produced a file, i.e. we
	 * captured PMKID or (ANonce + M2). Pairs that only produced an M3
	 * (or other partial states) carry no handshake material that
	 * wpa-sec / hcxpcapngtool can do anything with — uploading them
	 * just trains wpa-sec to mark our submissions invalid. Drop the
	 * pcap on disk and clear pcap_path so the agent emits nothing. */
	int usable = (p->hash22000_path[0] != '\0');
	if (p->pcap) {
		pcap_close(p->pcap);
		p->pcap = NULL;
	}
	if (p->pcap_path[0]) {
		if (usable) {
			log_info("handshake: closed %s", p->pcap_path);
		} else {
			if (unlink(p->pcap_path) == 0)
				log_debug("handshake: dropped incomplete pcap %s",
				          p->pcap_path);
			p->pcap_path[0] = '\0';
		}
	}
	payload_emit(h, HS_EVT_DONE, p);
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

	uint8_t ap[6], sta[6];
	memcpy(ap, d->bssid, 6);
	if (mac_eq(d->sa, ap)) memcpy(sta, d->da, 6);
	else                   memcpy(sta, d->sa, 6);

	struct hs_pair *p = find_pair(h, ap, sta);
	if (!p) {
		p = alloc_pair(h);
		if (!p) {
			log_warn("handshake: pair table full, dropping");
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

	/* Capture every EAPOL-Key frame for this pair into the per-pair pcap.
	 * The cached beacon (BSSID's last beacon) was written when the pcap was
	 * opened so hcxpcapngtool can reach the SSID + RSN IE. wpa-sec.org and
	 * any offline cracker that runs hcxpcapngtool over the upload accept
	 * this directly — they reject raw .22000. */
	ensure_pcap(h, p);
	if (p->pcap && frame && frame_len > 0)
		(void)pcap_write(p->pcap, frame, frame_len);

	if (ek.msg >= EAPOL_MSG_M1 && ek.msg <= EAPOL_MSG_M4)
		p->msg_bitmap |= (uint8_t)(1u << (ek.msg - 1));

	/* ANonce comes from M1 or M3 (both are AP→STA with ACK=1). */
	if ((ek.msg == EAPOL_MSG_M1 || ek.msg == EAPOL_MSG_M3) &&
	    ek.has_nonce && !p->have_anonce) {
		memcpy(p->anonce, ek.nonce, 32);
		p->have_anonce = 1;
	}

	/* PMKID from M1 key data. */
	if (ek.msg == EAPOL_MSG_M1 && ek.has_pmkid && !p->emitted_pmkid) {
		p->have_pmkid    = 1;
		p->emitted_pmkid = 1;
		memcpy(p->pmkid_bytes, ek.pmkid, 16);
		log_info("handshake: PMKID captured for %02x:..:%02x → %02x:..:%02x",
		         ap[0], ap[5], sta[0], sta[5]);
		payload_emit(h, HS_EVT_PMKID, p);
	}

	/* Store M2: full EAPOL packet with MIC zeroed (needed for WPA*02 line). */
	if (ek.msg == EAPOL_MSG_M2 && !p->have_m2 && ek.has_mic) {
		size_t off = ek.eapol_frame_off;
		size_t len = ek.eapol_frame_len;
		if (off + len <= payload_len) {
			if (len > M2_EAPOL_MAX) len = M2_EAPOL_MAX;
			memcpy(p->m2_eapol, payload + off, len);
			p->m2_eapol_len = len;
			/* Zero MIC at EAPOL byte offset 81 (= 4 header + 77 key-desc). */
			if (len >= 4 + 77 + 16)
				memset(p->m2_eapol + 4 + 77, 0, 16);
			memcpy(p->mic, ek.mic, 16);
			p->have_m2 = 1;
		}
	}

	/* Emit handshake.captured the first time we see anything past M1. */
	int got_real = (p->msg_bitmap & 0x0E) != 0; /* M2|M3|M4 */
	if (got_real && !p->emitted_handshake) {
		p->emitted_handshake = 1;
		log_info("handshake: 4-way captured for %02x:..:%02x → %02x:..:%02x bitmap=0x%x",
		         ap[0], ap[5], sta[0], sta[5], p->msg_bitmap);
		payload_emit(h, HS_EVT_HANDSHAKE, p);
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
