/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_HANDSHAKE_H
#define WIFICAPC_HANDSHAKE_H

#include "dot11.h"
#include "eapol.h"
#include "table.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Per-(AP, STA) handshake collector.
 *
 * On the first EAPOL-Key frame seen for a pair we open a per-pair pcap file
 * and prepend the most recent beacon (so hcxpcapngtool can reach the SSID +
 * RSN IE). Every subsequent EAPOL frame for that pair appends.
 *
 * Two completion signals fire:
 *   pmkid.captured     when an M1 frame carries a PMKID KDE
 *   handshake.captured when M2 (or M3 or M4) lands — proves a real exchange
 *                      happened, even if cracking later requires more frames
 *
 * Stale handshakes are evicted after a timeout; the pcap is closed and
 * `proc_run_hcxpcapngtool` is invoked on it to produce a `.22000` file.
 */

#define HS_MAX_PAIRS 64

enum hs_event {
	HS_EVT_HANDSHAKE = 0,    /* one or more 4-way frames captured */
	HS_EVT_PMKID,            /* M1 with PMKID KDE captured */
	HS_EVT_DONE,             /* pair retired; pcap closed; .22000 path may attach */
};

struct hs_emit_payload {
	const char     *pcap_path;
	const char     *hash22000_path; /* may be NULL until conversion finishes */
	uint8_t         ap_bssid[6];
	uint8_t         sta_mac[6];
	int             channel;
	int             rssi;
	uint8_t         msg_seen_bitmap; /* bit 0=M1, 1=M2, 2=M3, 3=M4 */
	int             have_pmkid;
};

typedef void (*hs_emit_fn)(enum hs_event evt,
                           const struct hs_emit_payload *p,
                           void *user);

struct handshake;

struct handshake *handshake_create(struct table *table,
                                   const char *out_dir,
                                   int stale_timeout_sec,
                                   hs_emit_fn cb, void *user);
void              handshake_destroy(struct handshake *h);

/* Set the directory pcaps are written into (created if missing). */
int  handshake_set_dir(struct handshake *h, const char *dir);
const char *handshake_dir(const struct handshake *h);

/*
 * Feed a captured frame. Called by capture.c for every data frame (the
 * module decides whether it's EAPOL itself).
 *
 * `frame` is the raw radiotap+802.11 bytes that arrived from AF_PACKET;
 * `payload` points to the 802.11 MAC frame inside `frame`; `payload_len` is
 * its length.
 */
void handshake_observe(struct handshake *h,
                       const uint8_t *frame, size_t frame_len,
                       const uint8_t *payload, size_t payload_len,
                       const struct dot11_info *d,
                       int channel, int rssi);

/* Periodic eviction of stale records; idempotent. */
void handshake_tick(struct handshake *h, time_t now);

/* How many pairs are currently being tracked. */
int  handshake_n_pairs(const struct handshake *h);

#endif
