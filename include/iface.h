/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_IFACE_H
#define WIFICAPC_IFACE_H

#include <stdint.h>

/*
 * iface: thin wrapper over rtnetlink (link up/down) + nl80211 (mode + channel).
 * One static instance per process; M2 only manages the configured monitor iface.
 */

enum iface_mode {
	IFACE_MODE_UNKNOWN = 0,
	IFACE_MODE_MANAGED,
	IFACE_MODE_MONITOR,
	IFACE_MODE_OTHER,
};

struct iface {
	char            name[16];   /* e.g. "wlx00c0cab79cb7" */
	int             ifindex;    /* netdevice index */
	uint32_t        wiphy;      /* nl80211 wiphy id (radio) */
	enum iface_mode mode;       /* last observed mode */
	int             channel;    /* last set channel (0 = unknown) */
	int             freq_mhz;   /* last set frequency */
	uint8_t         mac[6];     /* hardware MAC */

	/* Cached nl80211 session, opened lazily and reused across mode /
	 * channel / power-save calls so channel hopping doesn't re-resolve
	 * the genl family (a netlink round-trip) on every 250 ms tick.
	 * Opaque here (void*) to keep libnl out of the public header. */
	void           *nl;         /* struct nl_sock * */
	int             nl_family;  /* nl80211 genl family id */
};

/* Look up name → ifindex/wiphy and snapshot current mode. Returns 0 on success.
 * Caller-supplied iface struct is fully populated. */
int iface_open(struct iface *i, const char *name);

/* Release the cached nl80211 session. Call on shutdown; iface_open also
 * calls it internally before re-targeting a new interface. */
void iface_close(struct iface *i);

/* Bring link up or down via rtnetlink. */
int iface_link_up(struct iface *i);
int iface_link_down(struct iface *i);

/* Set monitor or managed mode via nl80211. Iface must be down for the kernel
 * to accept a mode change on most drivers; this function handles that. */
int iface_set_mode(struct iface *i, enum iface_mode mode);

/* Set the operating channel/frequency in monitor mode (NL80211_CMD_SET_CHANNEL,
 * 20 MHz NO_HT). Returns 0 on success. Updates i->channel and i->freq_mhz. */
int iface_set_channel(struct iface *i, int channel);

/* Helpers. */
int  iface_chan_to_freq(int channel);
int  iface_freq_to_chan(int freq_mhz);
const char *iface_mode_name(enum iface_mode mode);

#endif
