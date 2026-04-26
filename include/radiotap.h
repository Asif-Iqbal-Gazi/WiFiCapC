/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_RADIOTAP_H
#define WIFICAPC_RADIOTAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal radiotap parser. We only extract what the recon path needs:
 *   - the offset+length of the 802.11 payload that follows the header
 *   - the receive frequency (MHz) of the frame
 *   - the antenna signal in dBm (RSSI)
 *
 * Reference: https://www.radiotap.org/
 *
 * Bits of `it_present` we look at:
 *   0  TSFT                  u64
 *   1  Flags                 u8
 *   2  Rate                  u8
 *   3  Channel               u16 freq + u16 flags
 *   4  FHSS                  u8 + u8
 *   5  Antenna signal        s8   (this is the RSSI we want)
 *   6  Antenna noise         s8
 *   7  Lock quality          u16
 *   8  TX attenuation        u16
 *   9  dB TX attenuation     u16
 *  10  dBm TX power          s8
 *  11  Antenna               u8
 *  12  dB antenna signal     u8
 *  13  dB antenna noise      u8
 *  14  RX flags              u16
 *
 * Higher bits exist but we skip them — once we have RSSI and freq we stop.
 */

struct radiotap_info {
	const uint8_t *payload;     /* pointer into the original buffer */
	size_t         payload_len; /* bytes after the radiotap header */
	int            freq_mhz;    /* 0 if absent */
	int            rssi_dbm;    /* 127 if absent (clearly out of range) */
	int            has_fcs;     /* 1 if radiotap flags say a 4-byte FCS trails */
	int            bad_fcs;     /* 1 if radiotap flags say FCS is bad */
};

#define RT_RSSI_ABSENT 127

/* Parse the radiotap header at `frame` (length `len`). Returns 0 on success
 * and fills *out, or -1 on malformed/short input. */
int radiotap_parse(const uint8_t *frame, size_t len, struct radiotap_info *out);

#endif
