/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_INJECT_H
#define WIFICAPC_INJECT_H

#include "iface.h"

#include <stddef.h>
#include <stdint.h>

/*
 * 802.11 frame injection on the existing AF_PACKET monitor-mode socket.
 *
 * Two attacks are exposed:
 *
 *   inject_deauth — sends one or more deauthentication frames spoofed to
 *     look like they came from the AP (addr2 = bssid). Targeted at a single
 *     STA, or broadcast (FF:FF:FF:FF:FF:FF) when sta is NULL.
 *
 *   inject_assoc  — actively associates to the AP using the iface's real
 *     MAC as source. The intent is to elicit M1 of the 4-way handshake,
 *     which on most APs leaks the PMKID. Capture catches the response
 *     passively — this function only sends the auth + assoc requests.
 */

struct inject;

struct inject *inject_create(int sock_fd, const struct iface *iface);
void           inject_destroy(struct inject *i);

/*
 * Toggle MAC randomization for inject_assoc. When enabled, every
 * inject_assoc() call generates a fresh locally-administered, unicast
 * random MAC and uses it as the source address for both the auth and
 * the assoc frame (so the AP sees a coherent dialog). Off by default —
 * the iface's hardware MAC is used. inject_deauth is unaffected; it
 * spoofs the AP's own BSSID as the source by design.
 */
void inject_set_mac_rand(struct inject *i, int enable);

/*
 * Send `count` deauthentication frames (count >= 1).
 *
 * `bssid` is the access point.
 * `sta` may be NULL for a broadcast deauth (every associated STA).
 * `reason` is the IEEE 802.11 reason code; 7 ("Class 3 frame received from
 * nonassociated STA") is the conventional choice for handshake elicitation.
 *
 * Returns the number of frames actually sent.
 */
int inject_deauth(struct inject *i, const uint8_t bssid[6],
                  const uint8_t *sta, int count, int reason);

/*
 * Send a fresh Authentication (Open System) request followed immediately
 * by an Association Request advertising WPA2-PSK. Returns 0 on success.
 *
 * `ssid` may be NULL to send a wildcard SSID; the AP will likely reject.
 */
int inject_assoc(struct inject *i, const uint8_t bssid[6],
                 const char *ssid, uint8_t ssid_len);

#endif
