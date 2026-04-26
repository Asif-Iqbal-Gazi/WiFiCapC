/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_PCAP_H
#define WIFICAPC_PCAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal libpcap-format writer.
 *   - little-endian, microsecond precision (a2 b2 c3 d4 magic)
 *   - DLT_IEEE802_11_RADIOTAP = 127
 *   - one frame per write_frame call: timestamp + raw bytes
 *
 * Sized to write a single handshake's worth of frames (small overhead
 * per file; we keep many open at once during multi-handshake captures).
 */

#define PCAP_DLT_RADIOTAP 127

struct pcap_writer;

/* Open `path` for write, emit the file header. Returns NULL on error. */
struct pcap_writer *pcap_open(const char *path);

/* Close the file. Safe to pass NULL. */
void pcap_close(struct pcap_writer *w);

/* Append one frame. ts may be 0 to use the current wall clock. Returns 0
 * on success. */
int  pcap_write(struct pcap_writer *w, const uint8_t *frame, size_t len);

/* Return the path the writer was opened with (for event payloads). */
const char *pcap_path(const struct pcap_writer *w);

#endif
