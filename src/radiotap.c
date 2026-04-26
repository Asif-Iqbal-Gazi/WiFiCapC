/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "radiotap.h"

#include <string.h>

/* Header fixed prefix:
 *   u8  it_version
 *   u8  it_pad
 *   u16 it_len      (total header length, host byte order? no — little-endian)
 *   u32 it_present  (more 32-bit words follow if MSB set; we honour that)
 */

#define RT_FIELD_TSFT        0
#define RT_FIELD_FLAGS       1
#define RT_FIELD_RATE        2
#define RT_FIELD_CHANNEL     3
#define RT_FIELD_FHSS        4
#define RT_FIELD_DBM_SIGNAL  5
#define RT_FIELD_DBM_NOISE   6
#define RT_FIELD_LOCK_Q      7
#define RT_FIELD_TX_ATTEN    8
#define RT_FIELD_DB_TX_ATTEN 9
#define RT_FIELD_DBM_TX_PWR  10
#define RT_FIELD_ANTENNA     11
#define RT_FIELD_DB_SIGNAL   12
#define RT_FIELD_DB_NOISE    13
#define RT_FIELD_RX_FLAGS    14

/* Field sizes and alignment (per radiotap.org).
 *   sz[i] == 0 means we don't know how to skip it; in that case parsing stops
 *   and we leave subsequent fields unset. */
struct field_meta { uint8_t size; uint8_t align; };

static const struct field_meta META[] = {
	[RT_FIELD_TSFT]        = { 8, 8 },
	[RT_FIELD_FLAGS]       = { 1, 1 },
	[RT_FIELD_RATE]        = { 1, 1 },
	[RT_FIELD_CHANNEL]     = { 4, 2 }, /* u16 freq + u16 flags */
	[RT_FIELD_FHSS]        = { 2, 1 },
	[RT_FIELD_DBM_SIGNAL]  = { 1, 1 },
	[RT_FIELD_DBM_NOISE]   = { 1, 1 },
	[RT_FIELD_LOCK_Q]      = { 2, 2 },
	[RT_FIELD_TX_ATTEN]    = { 2, 2 },
	[RT_FIELD_DB_TX_ATTEN] = { 2, 2 },
	[RT_FIELD_DBM_TX_PWR]  = { 1, 1 },
	[RT_FIELD_ANTENNA]     = { 1, 1 },
	[RT_FIELD_DB_SIGNAL]   = { 1, 1 },
	[RT_FIELD_DB_NOISE]    = { 1, 1 },
	[RT_FIELD_RX_FLAGS]    = { 2, 2 },
};

#define RT_FLAGS_FCS_AT_END 0x10
#define RT_FLAGS_BAD_FCS    0x40

static inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static size_t align_up(size_t off, size_t a)
{
	if (a <= 1) return off;
	return (off + (a - 1)) & ~(a - 1);
}

int radiotap_parse(const uint8_t *frame, size_t len, struct radiotap_info *out)
{
	if (!frame || !out || len < 8) return -1;

	memset(out, 0, sizeof *out);
	out->rssi_dbm = RT_RSSI_ABSENT;

	uint16_t it_len = le16(frame + 2);
	if (it_len < 8 || it_len > len) return -1;

	/* Walk extension words: bit 31 of each present-word means another follows. */
	const uint8_t *pres = frame + 4;
	size_t         nwords = 1;
	while ((le16(pres + 2) & 0x8000) && (4 + nwords * 4) <= it_len) {
		nwords++;
		pres += 4;
	}
	if (4 + nwords * 4 > it_len) return -1;

	uint32_t present = (uint32_t)frame[4]
	                 | ((uint32_t)frame[5] << 8)
	                 | ((uint32_t)frame[6] << 16)
	                 | ((uint32_t)frame[7] << 24);

	const uint8_t *body     = frame + 4 + nwords * 4;
	size_t         body_len = it_len - (4 + nwords * 4);
	size_t         off      = 0;

	for (int bit = 0; bit <= RT_FIELD_RX_FLAGS; bit++) {
		if (!(present & (1u << bit))) continue;
		if (META[bit].size == 0) break;     /* unknown — stop parsing */

		off = align_up(off, META[bit].align);
		if (off + META[bit].size > body_len) break;

		switch (bit) {
		case RT_FIELD_FLAGS: {
			uint8_t f = body[off];
			out->has_fcs = !!(f & RT_FLAGS_FCS_AT_END);
			out->bad_fcs = !!(f & RT_FLAGS_BAD_FCS);
			break;
		}
		case RT_FIELD_CHANNEL:
			out->freq_mhz = le16(body + off);
			break;
		case RT_FIELD_DBM_SIGNAL:
			out->rssi_dbm = (int)(int8_t)body[off];
			break;
		default:
			/* fields we don't care about — just consume their bytes */
			break;
		}
		off += META[bit].size;
	}

	out->payload     = frame + it_len;
	out->payload_len = len - it_len;
	if (out->has_fcs && out->payload_len >= 4)
		out->payload_len -= 4;
	return 0;
}
