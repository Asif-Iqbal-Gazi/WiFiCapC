/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Standalone unit tests for radiotap.c and dot11.c.
 *
 * Build:   make test_parsers   (added to Makefile)
 * Run:     ./test_parsers
 */
#include "dot11.h"
#include "radiotap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int n_pass = 0, n_fail = 0;

#define ASSERT(cond, label) do {                                      \
		if (cond) { printf("ok   %s\n", label); n_pass++; }           \
		else      { printf("FAIL %s\n", label); n_fail++; }           \
	} while (0)

/* A real beacon, captured into a hex blob for the test.
 * Layout: [radiotap header][802.11 mgmt beacon].
 *
 * Radiotap (12 bytes):
 *   00 00                version, pad
 *   0c 00                it_len = 12
 *   06 18 00 00          present = TSFT? no — we set bits 1 (Flags),
 *                                            2 (Rate), 11 (Antenna),
 *                                            12 (dB antenna sig) — and
 *                                            we also set bit 5 (DBm sig)
 *                                            and bit 3 (Channel)? Keep it
 *                                            simple: Flags(bit1), Channel(bit3),
 *                                            DBm sig(bit5).
 *
 *  Recompute: bit1|bit3|bit5 = 0x2A = 0b101010. Use that.
 *
 *  it_len = header(8) + 1 (Flags) + 1 pad to align Channel(2) → 2 bytes
 *           + 4 (Channel: u16 freq + u16 flags) + 1 (DBm sig)
 *         = 8 + 1 + 1 + 4 + 1 = 15 → use 15.
 *
 * 802.11 beacon (24 + 12 + IEs):
 *   FC=0x80 0x00 (mgmt, beacon)
 *   Duration 0x0000
 *   addr1 ff*6 (broadcast)
 *   addr2 02:11:22:33:44:55 (BSSID-ish)
 *   addr3 02:11:22:33:44:55
 *   seq   0x0000
 *   Timestamp 8 bytes
 *   Beacon Interval 0x6400 (100 TU)
 *   Cap info 0x0411
 *   IE SSID:  id=0  len=4  data="Test"
 *   IE DS:    id=3  len=1  data=06 (channel 6)
 */

static const uint8_t SAMPLE_BEACON[] = {
	/* radiotap */
	0x00, 0x00,          /* version, pad */
	0x0f, 0x00,          /* it_len = 15 */
	0x2a, 0x00, 0x00, 0x00, /* present = bit1|bit3|bit5 = 0x2A */
	0x00,                /* Flags (bit1, 1 byte) — no FCS, no bad-fcs */
	0x00,                /* alignment padding so Channel is at offset 2 */
	0x6c, 0x09,          /* Channel.freq = 0x096c = 2412 (channel 1) */
	0x00, 0x00,          /* Channel.flags */
	0xc4,                /* DBm signal = -60 (0xc4 == -60 as int8) */

	/* 802.11 beacon header */
	0x80, 0x00,          /* FC: mgmt(0), beacon(8) */
	0x00, 0x00,          /* duration */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,        /* addr1: broadcast */
	0x02, 0x11, 0x22, 0x33, 0x44, 0x55,        /* addr2: SA */
	0x02, 0x11, 0x22, 0x33, 0x44, 0x55,        /* addr3: BSSID */
	0x00, 0x00,          /* seq ctrl */

	/* fixed body */
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,    /* timestamp */
	0x64, 0x00,                                  /* beacon interval */
	0x11, 0x04,                                  /* cap info */

	/* IE: SSID = "Test" */
	0x00, 0x04, 'T', 'e', 's', 't',
	/* IE: DS Param = 6 */
	0x03, 0x01, 0x06,
};

static void test_radiotap(void)
{
	struct radiotap_info rt;
	int rc = radiotap_parse(SAMPLE_BEACON, sizeof SAMPLE_BEACON, &rt);
	ASSERT(rc == 0, "radiotap parses");
	ASSERT(rt.freq_mhz == 2412, "radiotap freq=2412");
	ASSERT(rt.rssi_dbm == -60,  "radiotap rssi=-60");
	ASSERT(rt.has_fcs == 0,     "radiotap has_fcs=0");
	ASSERT(rt.payload_len == sizeof SAMPLE_BEACON - 15,
	       "radiotap payload_len = total - 15");
}

static void test_dot11_beacon(void)
{
	struct radiotap_info rt;
	radiotap_parse(SAMPLE_BEACON, sizeof SAMPLE_BEACON, &rt);

	struct dot11_info d;
	int rc = dot11_parse(rt.payload, rt.payload_len, &d);
	ASSERT(rc == 0,                          "dot11 parses");
	ASSERT(d.kind == DOT11_FRAME_BEACON,     "dot11 kind=BEACON");
	ASSERT(d.has_ssid && d.ssid_len == 4,    "dot11 SSID len=4");
	ASSERT(memcmp(d.ssid, "Test", 4) == 0,   "dot11 SSID=\"Test\"");
	ASSERT(d.has_ds_chan && d.ds_chan == 6,  "dot11 DS channel=6");

	uint8_t want_bssid[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
	ASSERT(memcmp(d.bssid, want_bssid, 6) == 0, "dot11 BSSID matches");
}

static void test_dot11_data_to_ds(void)
{
	/* Minimum 24-byte data frame: STA→AP. ToDS=1, FromDS=0.
	 * addr1=BSSID addr2=STA addr3=DA */
	uint8_t frame[24] = {
		0x08, 0x01,                           /* FC: data, ToDS=1 */
		0x00, 0x00,                           /* duration */
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,        /* addr1 = BSSID */
		0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,        /* addr2 = STA */
		0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,        /* addr3 = DA */
		0x00, 0x00,                           /* seq */
	};
	struct dot11_info d;
	ASSERT(dot11_parse(frame, sizeof frame, &d) == 0, "data parses");
	ASSERT(d.kind == DOT11_FRAME_DATA,                "data kind=DATA");
	ASSERT(d.to_ds == 1 && d.from_ds == 0,            "ToDS=1 FromDS=0");
	ASSERT(d.bssid[0] == 0xaa,                        "BSSID = aa:..");
	ASSERT(d.sa[0]    == 0xbb,                        "SA = bb:..");
	ASSERT(d.da[0]    == 0xcc,                        "DA = cc:..");
}

static void test_radiotap_short(void)
{
	uint8_t too_short[4] = {0};
	struct radiotap_info rt;
	ASSERT(radiotap_parse(too_short, 4, &rt) < 0, "radiotap rejects short");

	uint8_t bad_len[8] = { 0,0, 0xff,0xff, 0,0,0,0 };  /* it_len > buf */
	ASSERT(radiotap_parse(bad_len, 8, &rt) < 0, "radiotap rejects bad it_len");
}

int main(void)
{
	test_radiotap();
	test_dot11_beacon();
	test_dot11_data_to_ds();
	test_radiotap_short();
	printf("\n%d passed, %d failed\n", n_pass, n_fail);
	return n_fail ? 1 : 0;
}
