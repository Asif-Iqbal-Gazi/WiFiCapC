/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_EAPOL_H
#define WIFICAPC_EAPOL_H

#include "dot11.h"

#include <stddef.h>
#include <stdint.h>

/*
 * EAPOL-Key extractor for WPA/WPA2/WPA3 4-way handshake recognition.
 *
 * Layout above the 802.11 MAC header:
 *   LLC SNAP (8 bytes): AA AA 03 00 00 00 88 8E   (EtherType = 0x888E EAPOL)
 *   EAPOL header (4 bytes): version, type, length(BE u16)
 *   For EAPOL-Key (type=3):
 *     descriptor_type (1)        2 = WPA, 254 = RSN/802.11i, 0x18..0x19 = WPA3
 *     key_information (BE u16)
 *     key_length      (BE u16)
 *     replay_counter  (BE u64)
 *     key_nonce       (32)        ANonce (M1/M3) or SNonce (M2)
 *     key_iv          (16)
 *     key_rsc         (8)
 *     key_id_reserved (8)
 *     key_mic         (16)
 *     key_data_length (BE u16)
 *     key_data        (variable)  KDEs incl. PMKID, GTK
 *
 * Key Information bit map (per IEEE 802.11-2020 §12.7.2):
 *   0..2  Key Descriptor Version
 *   3     Key Type (1 = pairwise, 0 = group)
 *   4..5  Reserved/Key Index
 *   6     Install
 *   7     Key ACK
 *   8     Key MIC
 *   9     Secure
 *   10    Error
 *   11    Request
 *   12    Encrypted Key Data
 */

#define EAPOL_KI_PAIRWISE          (1u << 3)
#define EAPOL_KI_INSTALL           (1u << 6)
#define EAPOL_KI_ACK               (1u << 7)
#define EAPOL_KI_MIC               (1u << 8)
#define EAPOL_KI_SECURE            (1u << 9)
#define EAPOL_KI_ENCRYPTED_KD      (1u << 12)

enum eapol_msg {
	EAPOL_MSG_UNKNOWN = 0,
	EAPOL_MSG_M1,
	EAPOL_MSG_M2,
	EAPOL_MSG_M3,
	EAPOL_MSG_M4,
};

struct eapol_info {
	int            is_eapol_key;
	uint8_t        descriptor_type;
	uint16_t       key_information;
	enum eapol_msg msg;
	int            has_pmkid;
	uint8_t        pmkid[16];
	int            has_nonce;
	uint8_t        nonce[32];
};

/*
 * Inspect an 802.11 data frame and decide whether it carries EAPOL-Key.
 * `frame` must point to the full 802.11 MAC frame (no radiotap header) of
 * `len` bytes. `d` is the result of dot11_parse on the same frame and is
 * used to locate the MAC payload (LLC SNAP + EAPOL).
 *
 * Returns 0 in all cases; check `out->is_eapol_key` to see whether EAPOL
 * was actually present. Returns -1 only on bad arguments.
 */
int eapol_parse(const uint8_t *frame, size_t len,
                const struct dot11_info *d,
                struct eapol_info *out);

const char *eapol_msg_name(enum eapol_msg m);

#endif
