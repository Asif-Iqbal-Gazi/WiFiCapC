/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "eapol.h"

#include <string.h>

/* ---- helpers ----------------------------------------------------------- */

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

/*
 * Compute the offset from the start of the 802.11 MAC frame to the byte
 * after the MAC header (i.e., to the LLC SNAP). Handles QoS data subtypes
 * (extra 2 bytes) and 4-address (WDS) frames (extra 6 bytes).
 *
 * Returns -1 if the input is impossible/too short.
 */
static int dot11_payload_off(const uint8_t *frame, size_t len)
{
	if (len < 24) return -1;
	uint8_t fc0    = frame[0];
	uint8_t fc1    = frame[1];
	uint8_t type   = (fc0 >> 2) & 0x3;
	uint8_t sub    = (fc0 >> 4) & 0xf;
	int     to_ds  = !!(fc1 & 0x01);
	int     fr_ds  = !!(fc1 & 0x02);

	if (type != 2) return -1;                /* not data */

	int off = 24;
	if (to_ds && fr_ds) off += 6;            /* WDS: 4-address */
	if (sub & 0x08)     off += 2;            /* QoS data subtype */
	if ((size_t)off > len) return -1;
	return off;
}

/* RFC 1042 LLC/SNAP for EtherType 0x888E (EAPOL). */
static int looks_like_eapol(const uint8_t *p, size_t left)
{
	if (left < 8) return 0;
	static const uint8_t LLC_EAPOL[8] = {
		0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E,
	};
	return memcmp(p, LLC_EAPOL, 8) == 0;
}

/* Walk EAPOL key-data KDEs looking for the PMKID KDE.
 * KDE format: 0xDD len 00 0F AC <type> <data>
 *  PMKID KDE: type 0x04, data is 16 bytes. */
static int find_pmkid(const uint8_t *kd, size_t kd_len, uint8_t out[16])
{
	size_t i = 0;
	while (i + 2 <= kd_len) {
		uint8_t tag = kd[i];
		uint8_t len = kd[i + 1];
		if (i + 2 + len > kd_len) return 0;
		if (tag == 0xDD && len >= 4 + 16 &&
		    kd[i + 2] == 0x00 && kd[i + 3] == 0x0F &&
		    kd[i + 4] == 0xAC && kd[i + 5] == 0x04) {
			memcpy(out, kd + i + 6, 16);
			return 1;
		}
		i += 2 + len;
	}
	return 0;
}

/* Classify based on the Key Info bit map plus a few sanity checks.
 *   M1: ACK=1, MIC=0, Install=0 (and Secure=0)
 *   M2: ACK=0, MIC=1, Install=0 (and Secure=0)
 *   M3: ACK=1, MIC=1                          (Install bit may or may not be 1)
 *   M4: ACK=0, MIC=1, Install=0, Secure=1
 *
 * key_data_len helps disambiguate M2 vs M4 when Secure bit isn't set by the
 * supplicant: M4 typically has key_data_len=0 (or a single GTK KDE in some
 * corner cases), M2 carries the supplicant's RSN IE.
 */
static enum eapol_msg classify(uint16_t ki, uint16_t key_data_len)
{
	int ack    = !!(ki & EAPOL_KI_ACK);
	int mic    = !!(ki & EAPOL_KI_MIC);
	int install= !!(ki & EAPOL_KI_INSTALL);
	int secure = !!(ki & EAPOL_KI_SECURE);
	int pair   = !!(ki & EAPOL_KI_PAIRWISE);
	if (!pair) return EAPOL_MSG_UNKNOWN;

	if ( ack && !mic && !install) return EAPOL_MSG_M1;
	if ( ack &&  mic)             return EAPOL_MSG_M3;
	if (!ack &&  mic &&  secure)  return EAPOL_MSG_M4;
	if (!ack &&  mic && !secure) {
		/* M2 carries the supplicant RSN IE → key_data_len > 0;
		 * M4 with Secure=0 is rare but exists. */
		return key_data_len > 0 ? EAPOL_MSG_M2 : EAPOL_MSG_M4;
	}
	return EAPOL_MSG_UNKNOWN;
}

int eapol_parse(const uint8_t *frame, size_t len,
                const struct dot11_info *d, struct eapol_info *out)
{
	if (!frame || !out || !d) return -1;
	memset(out, 0, sizeof *out);
	if (d->kind != DOT11_FRAME_DATA) return 0;

	int off = dot11_payload_off(frame, len);
	if (off < 0) return 0;

	const uint8_t *p    = frame + off;
	size_t         left = len   - (size_t)off;

	if (!looks_like_eapol(p, left)) return 0;
	p    += 8;
	left -= 8;

	/* EAPOL header: ver(1) type(1) length(BE u16) */
	if (left < 4) return 0;
	uint8_t  type   = p[1];
	uint16_t plen   = be16(p + 2);
	p    += 4;
	left -= 4;
	if (plen > left) plen = (uint16_t)left;
	if (type != 3) return 0;             /* only EAPOL-Key matters here */
	if (plen < 95) return 0;             /* fixed key descriptor is 95 bytes */

	out->is_eapol_key    = 1;
	out->descriptor_type = p[0];
	out->key_information = be16(p + 1);

	/* IEEE 802.11i Key Descriptor body offsets (within the EAPOL body):
	 *   0 desc_type     1 .. 2 key_info     3 .. 4 key_length
	 *   5 .. 12 replay_counter    13 .. 44 nonce
	 *  45 .. 60 IV    61 .. 68 rsc    69 .. 76 reserved
	 *  77 .. 92 MIC    93 .. 94 key_data_length    95 .. key_data
	 * Fixed prefix total = 95 bytes; key_data follows. */
	const uint8_t *nonce  = p + 13;
	uint16_t       kd_len = be16(p + 93);
	const uint8_t *kd     = p + 95;
	if (95 + kd_len > plen) kd_len = (uint16_t)(plen - 95);

	/* Nonces: ANonce (M1/M3) or SNonce (M2) — we don't disambiguate here,
	 * the consumer can match by msg + ACK direction. */
	out->has_nonce = 1;
	memcpy(out->nonce, nonce, 32);

	out->msg = classify(out->key_information, kd_len);

	/* PMKID is conventionally only in M1, but parse regardless. */
	if (kd_len)
		out->has_pmkid = find_pmkid(kd, kd_len, out->pmkid);

	return 0;
}

const char *eapol_msg_name(enum eapol_msg m)
{
	switch (m) {
	case EAPOL_MSG_M1: return "M1";
	case EAPOL_MSG_M2: return "M2";
	case EAPOL_MSG_M3: return "M3";
	case EAPOL_MSG_M4: return "M4";
	default:           return "?";
	}
}
