/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iface.h"
#include "log.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

/* ---------------------------------------------------------------------------
 * Tiny per-call netlink session. nl80211 calls are infrequent (mode/channel),
 * so we allocate-and-free the socket each time rather than holding one open.
 * Keeps state isolated and avoids re-entrancy concerns.
 * ------------------------------------------------------------------------- */

struct nl_session {
	struct nl_sock *sk;
	int             family_id;
};

static int nlsess_open(struct nl_session *s)
{
	s->sk = nl_socket_alloc();
	if (!s->sk) {
		log_err("nl_socket_alloc failed");
		return -1;
	}
	if (genl_connect(s->sk) < 0) {
		log_err("genl_connect failed");
		nl_socket_free(s->sk);
		s->sk = NULL;
		return -1;
	}
	s->family_id = genl_ctrl_resolve(s->sk, "nl80211");
	if (s->family_id < 0) {
		log_err("nl80211 family not found (wireless drivers loaded?)");
		nl_socket_free(s->sk);
		s->sk = NULL;
		return -1;
	}
	return 0;
}

static void nlsess_close(struct nl_session *s)
{
	if (s->sk) {
		nl_socket_free(s->sk);
		s->sk = NULL;
	}
}

/* libnl callback signaling termination of a multipart response. */
static int nl_finish_cb(struct nl_msg *msg, void *arg)
{
	(void)msg;
	int *done = arg;
	*done = 1;
	return NL_SKIP;
}

static int nl_ack_cb(struct nl_msg *msg, void *arg)
{
	(void)msg;
	int *done = arg;
	*done = 1;
	return NL_STOP;
}

static int nl_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	(void)nla;
	int *out = arg;
	*out = err->error;
	return NL_STOP;
}

/* Send msg, run the loop until the kernel acks (or errors). Returns 0 on
 * success, -errno on failure. */
static int nl_send_and_wait(struct nl_session *s, struct nl_msg *msg,
                            nl_recvmsg_msg_cb_t parse_cb, void *parse_arg)
{
	int err = 1;     /* sentinel: -1 result == kernel error */
	int done = 0;

	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	if (parse_cb)
		nl_cb_set(cb, NL_CB_VALID,  NL_CB_CUSTOM, parse_cb,    parse_arg);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_cb, &done);
	nl_cb_set(cb, NL_CB_ACK,    NL_CB_CUSTOM, nl_ack_cb,    &done);
	nl_cb_err(cb,             NL_CB_CUSTOM, nl_err_cb,    &err);

	int rc = nl_send_auto(s->sk, msg);
	nlmsg_free(msg);
	if (rc < 0) {
		log_err("nl_send_auto: %s", nl_geterror(rc));
		nl_cb_put(cb);
		return rc;
	}

	while (!done && err > 0) {
		int recv_rc = nl_recvmsgs(s->sk, cb);
		if (recv_rc < 0) {
			/* Treat any recv error as fatal for this transaction —
			 * the alternative is to spin forever. The next iface
			 * call opens a fresh socket, so transient kernel/driver
			 * glitches recover on the next attempt. */
			log_warn("nl_recvmsgs: %s", nl_geterror(recv_rc));
			err = recv_rc;
			break;
		}
	}

	nl_cb_put(cb);
	return err <= 0 ? err : 0;
}

/* ---------------------------------------------------------------------------
 * iface_open: resolve name → ifindex and fetch wiphy/mode via nl80211.
 * ------------------------------------------------------------------------- */

struct get_iface_ctx {
	uint32_t        wiphy;
	enum iface_mode mode;
	int             have_wiphy;
};

static enum iface_mode iftype_to_mode(uint32_t iftype)
{
	switch (iftype) {
	case NL80211_IFTYPE_STATION: return IFACE_MODE_MANAGED;
	case NL80211_IFTYPE_MONITOR: return IFACE_MODE_MONITOR;
	default:                     return IFACE_MODE_OTHER;
	}
}

static int parse_get_interface(struct nl_msg *msg, void *arg)
{
	struct get_iface_ctx *ctx = arg;
	struct nlattr        *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr    *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	          genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_WIPHY]) {
		ctx->wiphy      = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
		ctx->have_wiphy = 1;
	}
	if (tb[NL80211_ATTR_IFTYPE])
		ctx->mode = iftype_to_mode(nla_get_u32(tb[NL80211_ATTR_IFTYPE]));
	return NL_SKIP;
}

int iface_open(struct iface *i, const char *name)
{
	memset(i, 0, sizeof *i);

	if (!name || !*name || strlen(name) >= sizeof i->name) {
		log_err("iface_open: invalid name");
		return -1;
	}
	strcpy(i->name, name);

	i->ifindex = (int)if_nametoindex(name);
	if (i->ifindex == 0) {
		log_err("iface_open: %s: %s", name, strerror(errno));
		return -1;
	}

	struct nl_session s = {0};
	if (nlsess_open(&s) < 0) return -1;

	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) { nlsess_close(&s); return -1; }

	genlmsg_put(msg, 0, 0, s.family_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, (uint32_t)i->ifindex);

	struct get_iface_ctx ctx = { .mode = IFACE_MODE_UNKNOWN };
	int rc = nl_send_and_wait(&s, msg, parse_get_interface, &ctx);
	nlsess_close(&s);

	if (rc < 0) {
		log_err("nl80211 GET_INTERFACE on %s failed: %d", name, rc);
		return -1;
	}
	if (!ctx.have_wiphy) {
		log_err("nl80211 reply for %s lacked wiphy", name);
		return -1;
	}

	i->wiphy = ctx.wiphy;
	i->mode  = ctx.mode;

	/* Snapshot the hardware MAC via SIOCGIFHWADDR — needed for active
	 * association attacks where we use our own MAC as source address. */
	int sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk >= 0) {
		struct ifreq ifr = {0};
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
		if (ioctl(sk, SIOCGIFHWADDR, &ifr) == 0)
			memcpy(i->mac, ifr.ifr_hwaddr.sa_data, 6);
		close(sk);
	}

	log_info("iface %s: ifindex=%d wiphy=%u mode=%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
	         name, i->ifindex, i->wiphy, iface_mode_name(i->mode),
	         i->mac[0], i->mac[1], i->mac[2], i->mac[3], i->mac[4], i->mac[5]);
	return 0;
}

/* ---------------------------------------------------------------------------
 * iface_link_up / iface_link_down via SIOCSIFFLAGS.
 * ------------------------------------------------------------------------- */

static int set_link_flag(struct iface *i, int up)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		log_err("socket(AF_INET): %s", strerror(errno));
		return -1;
	}

	struct ifreq ifr = {0};
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", i->name);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		log_err("SIOCGIFFLAGS %s: %s", i->name, strerror(errno));
		close(fd);
		return -1;
	}
	if (up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		log_err("SIOCSIFFLAGS %s %s: %s", i->name,
		        up ? "up" : "down", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int iface_link_up(struct iface *i)   { return set_link_flag(i, 1); }
int iface_link_down(struct iface *i) { return set_link_flag(i, 0); }

/* ---------------------------------------------------------------------------
 * iface_set_mode via NL80211_CMD_SET_INTERFACE.
 * Most drivers reject mode change while the link is up, so we cycle it.
 * ------------------------------------------------------------------------- */

int iface_set_mode(struct iface *i, enum iface_mode mode)
{
	uint32_t iftype;
	switch (mode) {
	case IFACE_MODE_MONITOR: iftype = NL80211_IFTYPE_MONITOR; break;
	case IFACE_MODE_MANAGED: iftype = NL80211_IFTYPE_STATION; break;
	default:
		log_err("iface_set_mode: unsupported mode %d", mode);
		return -1;
	}

	if (mode == i->mode) {
		log_debug("iface %s already in mode %s", i->name,
		          iface_mode_name(mode));
		return 0;
	}

	if (iface_link_down(i) < 0)
		return -1;

	struct nl_session s = {0};
	if (nlsess_open(&s) < 0) return -1;

	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) { nlsess_close(&s); return -1; }

	genlmsg_put(msg, 0, 0, s.family_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, (uint32_t)i->ifindex);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE,  iftype);

	int rc = nl_send_and_wait(&s, msg, NULL, NULL);
	nlsess_close(&s);

	if (rc < 0) {
		log_err("nl80211 SET_INTERFACE on %s -> %s failed: %d",
		        i->name, iface_mode_name(mode), rc);
		return -1;
	}

	if (iface_link_up(i) < 0)
		return -1;

	i->mode = mode;
	log_info("iface %s: mode -> %s", i->name, iface_mode_name(mode));
	return 0;
}

/* ---------------------------------------------------------------------------
 * iface_set_channel via NL80211_CMD_SET_WIPHY (20 MHz NO_HT).
 * ------------------------------------------------------------------------- */

int iface_set_channel(struct iface *i, int channel)
{
	int freq = iface_chan_to_freq(channel);
	if (freq <= 0) {
		log_err("iface_set_channel: invalid channel %d", channel);
		return -1;
	}

	struct nl_session s = {0};
	if (nlsess_open(&s) < 0) return -1;

	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) { nlsess_close(&s); return -1; }

	genlmsg_put(msg, 0, 0, s.family_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX,            (uint32_t)i->ifindex);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ,         (uint32_t)freq);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);

	int rc = nl_send_and_wait(&s, msg, NULL, NULL);
	nlsess_close(&s);

	if (rc < 0) {
		log_err("nl80211 SET_WIPHY freq=%d on %s failed: %d",
		        freq, i->name, rc);
		return -1;
	}

	i->channel  = channel;
	i->freq_mhz = freq;
	log_debug("iface %s: channel=%d freq=%d", i->name, channel, freq);
	return 0;
}

/* ---------------------------------------------------------------------------
 * Channel/frequency helpers — covers 2.4 GHz, 5 GHz, and 6 GHz Wi-Fi.
 * Sourced from IEEE 802.11-2020 / 802.11ax channel plans.
 * ------------------------------------------------------------------------- */

int iface_chan_to_freq(int ch)
{
	if (ch >= 1 && ch <= 13) return 2407 + ch * 5;
	if (ch == 14)            return 2484;
	if (ch >= 36 && ch <= 177 && (ch % 4) == 0) return 5000 + ch * 5;
	if (ch == 149 || ch == 153 || ch == 157 ||
	    ch == 161 || ch == 165 || ch == 169 ||
	    ch == 173 || ch == 177)
		return 5000 + ch * 5;
	/* 6 GHz Wi-Fi (PSC channels): 1 → 5955, step 5 MHz */
	if (ch >= 1 && ch <= 233) return 5950 + ch * 5;
	return -1;
}

int iface_freq_to_chan(int f)
{
	if (f >= 2412 && f <= 2472) return (f - 2407) / 5;
	if (f == 2484)              return 14;
	if (f >= 5180 && f <= 5885) return (f - 5000) / 5;
	if (f >= 5955 && f <= 7115) return (f - 5950) / 5;
	return -1;
}

const char *iface_mode_name(enum iface_mode m)
{
	switch (m) {
	case IFACE_MODE_MANAGED: return "managed";
	case IFACE_MODE_MONITOR: return "monitor";
	case IFACE_MODE_OTHER:   return "other";
	default:                 return "unknown";
	}
}
