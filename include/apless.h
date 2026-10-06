/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * A: ap-less / rogue-AP M2 attack.  OFF by default — this is the tool's
 * loudest, most active attack and is opt-in only (set_apless / --apless).
 *
 * When enabled, the daemon answers client PROBE REQUESTs by impersonating the
 * exact ESSID the client is looking for, completes a fake association, injects
 * its own EAPOL M1, and captures the client's M2 — crackable WPA handshake
 * material from a device whose real AP isn't in range. It is the handshake
 * analogue of hcxdumptool's default client attack. Standalone
 * capture / PMKID / deauth never touch this path.
 *
 * Design + rationale: docs/IDEAS/ap-less-m2-attack.md.
 */
#ifndef APLESS_H
#define APLESS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct apless;
struct inject;
struct handshake;
struct dot11_info;

/* Create the rogue-AP responder. The captured M2 is handed to `hs` (the
 * handshake collector) to finalise into a .22000. Returns NULL on OOM. */
struct apless *apless_create(struct handshake *hs);
void           apless_destroy(struct apless *a);

/* Feed a received, already-parsed mgmt/EAPOL frame. A no-op unless it is a
 * client probe-req / auth / assoc-req / EAPOL frame for a session we track.
 * `inject` (passed per-call so it's always the live injector) sends the rogue
 * replies; `channel` is the currently tuned channel. */
void apless_on_frame(struct apless *a, struct inject *inject,
                     const struct dot11_info *d,
                     const uint8_t *raw, size_t raw_len, int channel);

/* Evict rogue sessions that never completed, bounding memory. */
void apless_tick(struct apless *a, time_t now);

#endif /* APLESS_H */
