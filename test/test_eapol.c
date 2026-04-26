/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Unit tests for the EAPOL parser. Hand-crafts each of M1, M2, M3, M4 plus
 * an M1 with a PMKID KDE, and verifies classification.
 */
#include "dot11.h"
#include "eapol.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int n_pass = 0, n_fail = 0;

#define ASSERT(cond, label) do {                                      \
		if (cond) { printf("ok   %s\n", label); n_pass++; }           \
		else      { printf("FAIL %s\n", label); n_fail++; }           \
	} while (0)

/* Build the static prefix shared by every EAPOL data frame: 24-byte 802.11
 * header + 8-byte LLC SNAP + 4-byte EAPOL header. The body that follows is
 * the variable EAPOL-Key descriptor. */
static size_t build_eapol_frame(uint8_t *buf, uint16_t key_info, int kd_len,
                                const uint8_t *kd, int from_ap)
{
	size_t  i = 0;
	uint8_t fc0 = 0x08;       /* type=data, subtype=0 (no QoS) */
	uint8_t fc1 = from_ap ? 0x02 : 0x01;  /* FromDS or ToDS */

	/* MAC header (24 bytes) */
	buf[i++] = fc0;
	buf[i++] = fc1;
	buf[i++] = 0; buf[i++] = 0;          /* duration */
	if (from_ap) {
		/* FromDS: addr1=DA(STA), addr2=BSSID, addr3=SA(BSSID) */
		uint8_t sta[6]  = {0xbb,0xbb,0xbb,0xbb,0xbb,0xbb};
		uint8_t ap[6]   = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
		memcpy(buf + i, sta, 6); i += 6;
		memcpy(buf + i, ap,  6); i += 6;
		memcpy(buf + i, ap,  6); i += 6;
	} else {
		/* ToDS: addr1=BSSID, addr2=STA, addr3=DA */
		uint8_t sta[6]  = {0xbb,0xbb,0xbb,0xbb,0xbb,0xbb};
		uint8_t ap[6]   = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
		memcpy(buf + i, ap,  6); i += 6;
		memcpy(buf + i, sta, 6); i += 6;
		memcpy(buf + i, ap,  6); i += 6;
	}
	buf[i++] = 0; buf[i++] = 0;          /* seq ctrl */

	/* LLC SNAP for EAPOL (0x888E) */
	uint8_t llc[8] = {0xAA,0xAA,0x03,0x00,0x00,0x00,0x88,0x8E};
	memcpy(buf + i, llc, 8); i += 8;

	/* EAPOL header */
	buf[i++] = 0x02;                     /* version 2 */
	buf[i++] = 0x03;                     /* type = Key */
	int eapol_body_len = 95 + kd_len;    /* fixed key descriptor + KDE */
	buf[i++] = (uint8_t)(eapol_body_len >> 8);
	buf[i++] = (uint8_t)(eapol_body_len & 0xff);

	/* Fixed key descriptor body (95 bytes) + key_data (kd_len bytes). */
	uint8_t *kd_start = buf + i;
	memset(kd_start, 0, 95 + kd_len);
	kd_start[0] = 0x02;                  /* descriptor type = WPA */
	kd_start[1] = (uint8_t)(key_info >> 8);
	kd_start[2] = (uint8_t)(key_info & 0xff);
	/* nonces & MICs left as zeroes — the parser doesn't validate them */

	kd_start[93] = (uint8_t)(kd_len >> 8);
	kd_start[94] = (uint8_t)(kd_len & 0xff);
	if (kd && kd_len > 0)
		memcpy(kd_start + 95, kd, (size_t)kd_len);

	i += 95 + kd_len;
	return i;
}

static void test_m1(void)
{
	uint8_t f[256];
	/* M1: ACK=1, MIC=0, Pairwise=1 */
	uint16_t ki = (1u << 7) | (1u << 3);
	size_t   n  = build_eapol_frame(f, ki, 0, NULL, 1 /* from_ap */);

	struct dot11_info d;
	ASSERT(dot11_parse(f, n, &d) == 0, "M1: dot11 parses");
	ASSERT(d.kind == DOT11_FRAME_DATA,  "M1: kind=DATA");

	struct eapol_info ek;
	eapol_parse(f, n, &d, &ek);
	ASSERT(ek.is_eapol_key == 1, "M1: detected as EAPOL-Key");
	ASSERT(ek.msg == EAPOL_MSG_M1, "M1: classified as M1");
	ASSERT(ek.has_pmkid == 0,    "M1: no PMKID present");
}

static void test_m1_with_pmkid(void)
{
	uint8_t kde[2 + 4 + 16] = {
		0xDD, 4 + 16,                   /* tag, length */
		0x00, 0x0F, 0xAC, 0x04,         /* OUI + type=PMKID */
		1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
	};
	uint8_t f[256];
	uint16_t ki = (1u << 7) | (1u << 3); /* M1 */

	/* The KDE is appended in-place after the fixed descriptor — the helper
	 * writes the entire descriptor body for us. We pass the KDE bytes via
	 * the kd argument — but our helper expects the *length* including the
	 * 2-byte length field. Pass kd_len = sizeof(kde). */
	size_t n = build_eapol_frame(f, ki, sizeof kde, kde, 1);

	struct dot11_info d; dot11_parse(f, n, &d);
	struct eapol_info ek;
	eapol_parse(f, n, &d, &ek);
	ASSERT(ek.is_eapol_key == 1, "M1+PMKID: EAPOL-Key");
	ASSERT(ek.msg == EAPOL_MSG_M1, "M1+PMKID: classified M1");
	ASSERT(ek.has_pmkid == 1, "M1+PMKID: PMKID present");
	ASSERT(ek.pmkid[0] == 1 && ek.pmkid[15] == 16, "M1+PMKID: bytes match");
}

static void test_m2(void)
{
	uint8_t f[256];
	/* M2: ACK=0, MIC=1, Install=0, Secure=0, Pairwise=1, w/ key data > 0 */
	uint16_t ki = (1u << 8) | (1u << 3);
	uint8_t kde[16] = {0};   /* RSN IE stand-in — only length matters here */
	size_t  n   = build_eapol_frame(f, ki, sizeof kde, kde, 0 /* to_ap */);

	struct dot11_info d; dot11_parse(f, n, &d);
	struct eapol_info ek;
	eapol_parse(f, n, &d, &ek);
	ASSERT(ek.msg == EAPOL_MSG_M2, "M2: classified as M2");
}

static void test_m3(void)
{
	uint8_t f[256];
	/* M3: ACK=1, MIC=1, Install=1, Pairwise=1 */
	uint16_t ki = (1u << 7) | (1u << 8) | (1u << 6) | (1u << 3);
	size_t   n  = build_eapol_frame(f, ki, 0, NULL, 1);

	struct dot11_info d; dot11_parse(f, n, &d);
	struct eapol_info ek; eapol_parse(f, n, &d, &ek);
	ASSERT(ek.msg == EAPOL_MSG_M3, "M3: classified as M3");
}

static void test_m4(void)
{
	uint8_t f[256];
	/* M4: ACK=0, MIC=1, Install=0, Secure=1, Pairwise=1, kd_len=0 */
	uint16_t ki = (1u << 8) | (1u << 9) | (1u << 3);
	size_t   n  = build_eapol_frame(f, ki, 0, NULL, 0);

	struct dot11_info d; dot11_parse(f, n, &d);
	struct eapol_info ek; eapol_parse(f, n, &d, &ek);
	ASSERT(ek.msg == EAPOL_MSG_M4, "M4: classified as M4");
}

static void test_non_eapol(void)
{
	/* Plain data frame with non-EAPOL EtherType (IPv4 = 0x0800). */
	uint8_t f[64] = {0};
	f[0] = 0x08;                /* data subtype 0 */
	f[1] = 0x01;                /* ToDS */
	/* MAC addresses: any */
	for (int i = 4; i < 24; i++) f[i] = (uint8_t)i;
	/* LLC: AA AA 03 00 00 00 08 00 (IPv4) */
	f[24]=0xAA; f[25]=0xAA; f[26]=0x03;
	f[27]=0; f[28]=0; f[29]=0;
	f[30]=0x08; f[31]=0x00;

	struct dot11_info d; dot11_parse(f, sizeof f, &d);
	struct eapol_info ek;
	eapol_parse(f, sizeof f, &d, &ek);
	ASSERT(ek.is_eapol_key == 0, "non-EAPOL: not flagged");
}

int main(void)
{
	test_m1();
	test_m1_with_pmkid();
	test_m2();
	test_m3();
	test_m4();
	test_non_eapol();
	printf("\n%d passed, %d failed\n", n_pass, n_fail);
	return n_fail ? 1 : 0;
}
