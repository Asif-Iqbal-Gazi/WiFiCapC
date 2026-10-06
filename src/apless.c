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

struct apless {
	struct inject    *inject;
	struct handshake *hs;
	struct rogue      sessions[APLESS_MAX_SESSIONS];
	uint32_t          nic;              /* increments to fabricate distinct BSSIDs */
};

struct apless *apless_create(struct inject *inject, struct handshake *hs)
{
	struct apless *a = calloc(1, sizeof *a);
	if (!a) return NULL;
	a->inject = inject;
	a->hs     = hs;
	log_info("apless: rogue-AP M2 responder armed (opt-in attack)");
	return a;
}

void apless_destroy(struct apless *a)
{
	free(a);
}

void apless_on_frame(struct apless *a, const struct dot11_info *d,
                     const uint8_t *raw, size_t raw_len, int channel)
{
	(void)a; (void)d; (void)raw; (void)raw_len; (void)channel;
	/* TODO (next increment): directed probe-req -> rogue proberesp (impersonate
	 * the probed ESSID); auth/assoc-req -> auth/assoc responses + inject our
	 * EAPOL M1 with a fresh ANONCE; EAPOL M2 -> register our M1 with the
	 * handshake collector and finalise the .22000. */
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
