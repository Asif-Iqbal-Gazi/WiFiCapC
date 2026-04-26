/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "dot11.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/*
 * 802.11 MAC header layout for the frames we look at:
 *
 *   bytes 0..1  Frame Control (FC)     — bits 2..3 = type, 4..7 = subtype
 *   bytes 2..3  Duration / ID
 *   bytes 4..9  Address 1
 *   bytes 10..15 Address 2
 *   bytes 16..21 Address 3
 *   bytes 22..23 Sequence Control
 *   (bytes 24..29 Address 4 — only when ToDS=FromDS=1, i.e. wireless DS)
 *
 * For mgmt frames (beacon/probe_resp/probe_req):
 *   addr1 = DA, addr2 = SA, addr3 = BSSID
 *
 * For data frames the meaning of addr1..3 depends on ToDS/FromDS:
 *   ToDS=0 FromDS=0  IBSS:        addr1=DA addr2=SA   addr3=BSSID
 *   ToDS=0 FromDS=1  AP→STA:      addr1=DA addr2=BSSID addr3=SA
 *   ToDS=1 FromDS=0  STA→AP:      addr1=BSSID addr2=SA addr3=DA
 *   ToDS=1 FromDS=1  WDS (rare): addr1=RA addr2=TA addr3=DA addr4=SA
 *
 * We classify and extract BSSID/SA accordingly.
 *
 * Beacon/probe-resp body layout (after the MAC header):
 *   8 bytes  Timestamp
 *   2 bytes  Beacon Interval
 *   2 bytes  Capability Info
 *   then a sequence of Information Elements (id u8, len u8, data[len])
 *
 * Probe-req body layout: just IEs (no fixed fields).
 *
 * IE we read:
 *   id 0  SSID                (data = up to 32 bytes UTF-8)
 *   id 3  DS Parameter Set    (data = 1 byte channel)
 */

#define FC_VERSION_MASK 0x03
#define FC_TYPE_MASK    0x0c
#define FC_SUBTYPE_MASK 0xf0
#define FC_TODS         0x01
#define FC_FROMDS       0x02

#define IE_SSID         0
#define IE_DS_PARAM     3

static void mac_copy(uint8_t out[6], const uint8_t *src) { memcpy(out, src, 6); }

static int copy_ssid(struct dot11_info *out, const uint8_t *src, uint8_t len)
{
	if (len > DOT11_SSID_MAX) return -1;
	out->ssid_len = len;
	for (uint8_t i = 0; i < len; i++) {
		uint8_t c = src[i];
		out->ssid[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
	}
	out->ssid[len] = '\0';
	out->has_ssid  = 1;
	return 0;
}

static void parse_ies(struct dot11_info *out, const uint8_t *p, size_t len)
{
	size_t i = 0;
	while (i + 2 <= len) {
		uint8_t id = p[i];
		uint8_t l  = p[i + 1];
		if (i + 2 + l > len) return;
		const uint8_t *data = p + i + 2;
		switch (id) {
		case IE_SSID:
			copy_ssid(out, data, l);
			break;
		case IE_DS_PARAM:
			if (l >= 1) {
				out->has_ds_chan = 1;
				out->ds_chan     = (int)data[0];
			}
			break;
		default: break;
		}
		i += 2 + l;
	}
}

int dot11_parse(const uint8_t *frame, size_t len, struct dot11_info *out)
{
	if (!frame || !out || len < 24) return -1;

	memset(out, 0, sizeof *out);

	uint8_t fc0 = frame[0];
	uint8_t fc1 = frame[1];
	uint8_t type    = (fc0 & FC_TYPE_MASK)    >> 2;
	uint8_t subtype = (fc0 & FC_SUBTYPE_MASK) >> 4;

	out->to_ds   = !!(fc1 & FC_TODS);
	out->from_ds = !!(fc1 & FC_FROMDS);

	const uint8_t *addr1 = frame + 4;
	const uint8_t *addr2 = frame + 10;
	const uint8_t *addr3 = frame + 16;

	if (type == DOT11_TYPE_MGMT) {
		switch (subtype) {
		case DOT11_SUBTYPE_BEACON:     out->kind = DOT11_FRAME_BEACON;     break;
		case DOT11_SUBTYPE_PROBE_RESP: out->kind = DOT11_FRAME_PROBE_RESP; break;
		case DOT11_SUBTYPE_PROBE_REQ:  out->kind = DOT11_FRAME_PROBE_REQ;  break;
		default:                       out->kind = DOT11_FRAME_OTHER;      break;
		}
		mac_copy(out->da,    addr1);
		mac_copy(out->sa,    addr2);
		mac_copy(out->bssid, addr3);

		if (out->kind == DOT11_FRAME_BEACON ||
		    out->kind == DOT11_FRAME_PROBE_RESP) {
			/* skip 12-byte fixed body (timestamp + interval + caps) */
			if (len >= 24 + 12)
				parse_ies(out, frame + 24 + 12, len - (24 + 12));
		} else if (out->kind == DOT11_FRAME_PROBE_REQ) {
			parse_ies(out, frame + 24, len - 24);
		}
		return 0;
	}

	if (type == DOT11_TYPE_DATA) {
		out->kind = DOT11_FRAME_DATA;
		if (!out->to_ds && !out->from_ds) {
			mac_copy(out->da,    addr1);
			mac_copy(out->sa,    addr2);
			mac_copy(out->bssid, addr3);
		} else if (!out->to_ds && out->from_ds) {
			mac_copy(out->da,    addr1);
			mac_copy(out->bssid, addr2);
			mac_copy(out->sa,    addr3);
		} else if (out->to_ds && !out->from_ds) {
			mac_copy(out->bssid, addr1);
			mac_copy(out->sa,    addr2);
			mac_copy(out->da,    addr3);
		} else {
			/* WDS: addr4 needs to exist, ignore for recon */
			return -1;
		}
		return 0;
	}

	out->kind = DOT11_FRAME_OTHER;
	return 0;
}

void dot11_mac_str(const uint8_t mac[6], char out[18])
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
