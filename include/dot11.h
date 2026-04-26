/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_DOT11_H
#define WIFICAPC_DOT11_H

#include <stddef.h>
#include <stdint.h>

/*
 * 802.11 frame classifier — only the bits the recon path needs.
 *
 * Reference: IEEE 802.11-2020, §9 (frame formats).
 */

#define DOT11_TYPE_MGMT  0
#define DOT11_TYPE_CTRL  1
#define DOT11_TYPE_DATA  2

#define DOT11_SUBTYPE_PROBE_REQ  4
#define DOT11_SUBTYPE_PROBE_RESP 5
#define DOT11_SUBTYPE_BEACON     8

enum dot11_frame_kind {
	DOT11_FRAME_OTHER = 0,
	DOT11_FRAME_BEACON,         /* mgmt 8: from AP */
	DOT11_FRAME_PROBE_RESP,     /* mgmt 5: from AP */
	DOT11_FRAME_PROBE_REQ,      /* mgmt 4: from STA */
	DOT11_FRAME_DATA,           /* any data subtype */
};

#define DOT11_SSID_MAX 32

struct dot11_info {
	enum dot11_frame_kind kind;
	uint8_t bssid[6];           /* AP — always set for FRAME_* above except OTHER */
	uint8_t sa[6];              /* source address (transmitter) */
	uint8_t da[6];              /* destination address */
	int     to_ds;
	int     from_ds;
	int     has_ssid;           /* set for beacon / probe_resp / probe_req w/ SSID IE */
	uint8_t ssid_len;
	char    ssid[DOT11_SSID_MAX + 1]; /* NUL-terminated; non-printable bytes → '?' */
	int     has_ds_chan;
	int     ds_chan;            /* channel from DS Parameter Set IE (mgmt frames) */
};

/* Parse the 802.11 frame at `frame` (length `len`, no radiotap header) and
 * populate *out. Returns 0 on success, -1 if the frame is too short or has
 * an unsupported MAC header layout we can't safely walk. */
int dot11_parse(const uint8_t *frame, size_t len, struct dot11_info *out);

/* Format a MAC into "aa:bb:cc:dd:ee:ff" in `out` (>= 18 bytes). */
void dot11_mac_str(const uint8_t mac[6], char out[18]);

#endif
