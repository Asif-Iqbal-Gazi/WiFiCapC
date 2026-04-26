/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_TABLE_H
#define WIFICAPC_TABLE_H

#include "dot11.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * In-memory AP / STA tables.
 *
 * Backing storage: fixed-cap arrays with linear scan. We expect O(10s) APs and
 * O(100s) STAs in any one location; linear scan beats hash-table overhead for
 * those cardinalities. If real-world deployment shows otherwise, swap for an
 * open-addressed hash without changing the public API.
 *
 * Concurrency: single-threaded — only the main loop touches these.
 */

#define TABLE_MAX_APS    256
#define TABLE_MAX_STAS   1024
#define TABLE_VENDOR_MAX 32
#define TABLE_BEACON_MAX 512   /* most recent beacon, radiotap+802.11 */

struct ap_record {
	uint8_t  bssid[6];
	uint8_t  ssid_len;
	char     ssid[DOT11_SSID_MAX + 1];
	int      channel;
	int      rssi;          /* most recent dBm */
	char     vendor[TABLE_VENDOR_MAX];
	time_t   first_seen;
	time_t   last_seen;
	uint64_t frames;
	int      in_use;

	/* most recent beacon as captured (radiotap header + 802.11 frame).
	 * Used by the handshake module so each per-pair pcap starts with a
	 * beacon — hcxpcapngtool needs the SSID + RSN IE to build the hash. */
	uint8_t  last_beacon[TABLE_BEACON_MAX];
	size_t   last_beacon_len;
};

struct sta_record {
	uint8_t  mac[6];
	uint8_t  ap_bssid[6];   /* zeroed if not yet associated */
	int      have_ap;
	int      channel;
	int      rssi;
	char     vendor[TABLE_VENDOR_MAX];
	time_t   first_seen;
	time_t   last_seen;
	uint64_t frames;
	int      in_use;
};

enum table_event {
	TABLE_EVT_AP_NEW = 0,
	TABLE_EVT_AP_LOST,
	TABLE_EVT_STA_NEW,
	TABLE_EVT_STA_LOST,
};

struct table;

typedef void (*table_emit_fn)(enum table_event evt,
                              const struct ap_record  *ap,
                              const struct sta_record *sta,
                              void *user);

/* Create the tables with given TTLs (seconds). Caller-supplied callback fires
 * for new/lost APs and STAs. */
struct table *table_create(int ap_ttl_sec, int sta_ttl_sec,
                           table_emit_fn cb, void *user);
void          table_destroy(struct table *t);

/* Update APIs called from the capture path. They register/refresh entries
 * and emit *_NEW the first time a MAC is seen. `now` is the current
 * monotonic-ish wall time (seconds). */
void table_observe_ap (struct table *t, const struct dot11_info *d,
                       int channel, int rssi, time_t now);
void table_observe_sta(struct table *t, const struct dot11_info *d,
                       int channel, int rssi, time_t now,
                       const uint8_t *ap_bssid /* may be NULL */);

/*
 * Cache the most recent beacon raw bytes for a known BSSID. The beacon is
 * stored as captured (radiotap + 802.11). Truncated to TABLE_BEACON_MAX.
 * No-op if BSSID is unknown.
 */
void table_cache_beacon(struct table *t, const uint8_t bssid[6],
                        const uint8_t *frame, size_t len);

/* Look up by BSSID; returns NULL if not present. */
const struct ap_record *table_find_ap(const struct table *t, const uint8_t bssid[6]);

/* Scan tables and emit *_LOST for any record whose last_seen was longer ago
 * than the configured TTL. Call periodically. */
void table_evict_expired(struct table *t, time_t now);

/* Wipe everything (no events emitted). */
void table_clear(struct table *t);

/* Snapshot iteration. Returns count of entries copied (capped at max).
 * Records are returned in arbitrary order; in_use flag is always 1. */
int table_snapshot_aps (const struct table *t, struct ap_record  *out, int max);
int table_snapshot_stas(const struct table *t, struct sta_record *out, int max);

/* Counts. */
int table_n_aps (const struct table *t);
int table_n_stas(const struct table *t);

#endif
