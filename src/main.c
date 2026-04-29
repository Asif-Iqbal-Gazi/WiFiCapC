/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "capture.h"
#include "chanhop.h"
#include "dot11.h"
#include "handshake.h"
#include "iface.h"
#include "inject.h"
#include "ipc.h"
#include "log.h"
#include "proc.h"
#include "proto.h"
#include "table.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SOCK     "/run/wificapc.sock"
#define DEFAULT_HS_DIR   "/etc/pwnagotchi/handshakes"
#define WIFICAPC_VER     "0.6.2"

#define DEFAULT_AP_TTL_SEC      120
#define DEFAULT_STA_TTL_SEC     300
#define DEFAULT_HS_STALE_SEC     30
#define DEFAULT_HOP_INTERVAL_MS 250
#define DEFAULT_ATTACK_INTERVAL_MS 5000

static const int DEFAULT_CHANNELS[]   = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static const int DEFAULT_N_CHANNELS   = 13;

struct app {
	struct ipc        *ipc;
	struct iface       iface;
	int                iface_open;
	struct chanhop    *hopper;
	struct table      *table;
	struct capture    *capture;
	struct handshake  *hs;
	struct proc       *proc;   /* kept for future use; currently unused */
	struct inject     *inject;
	int                attack_fd;
	time_t             started;
};

static struct app  *g_app;

/* forward decls — used before their definitions appear */
static int ensure_table(struct app *a);
static int ensure_handshake(struct app *a);
static int ensure_inject(struct app *a);
static int ensure_hopper(struct app *a);

/* ---- signals -------------------------------------------------------------- */

static void on_signal(int signo)
{
	(void)signo;
	if (g_app && g_app->ipc)
		ipc_stop(g_app->ipc);
}

static void install_signals(void)
{
	struct sigaction sa = { .sa_handler = on_signal };
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

/* ---- emit helpers --------------------------------------------------------- */

static int emit_event_iface_channel(struct app *a, int channel, int freq)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_event_begin(buf, sizeof buf, pos, "iface.channel")) < 0)
		return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "iface", a->iface.name)) < 0)
		return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", channel)) < 0)
		return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "freq", freq)) < 0)
		return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_broadcast(a->ipc, buf, pos);
}

static int emit_event_iface_mode(struct app *a, enum iface_mode mode)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_event_begin(buf, sizeof buf, pos, "iface.mode")) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "iface", a->iface.name)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "mode", iface_mode_name(mode))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_broadcast(a->ipc, buf, pos);
}

static int reply_ok_empty(struct ipc *s, int fd, int64_t id)
{
	char  buf[64];
	ssize_t r = proto_reply_ok_begin(buf, sizeof buf, 0, id);
	if (r < 0) return -1;
	r = proto_reply_end(buf, sizeof buf, (size_t)r);
	if (r < 0) return -1;
	return ipc_send_to(s, fd, buf, (size_t)r);
}

static int reply_error(struct ipc *s, int fd, int64_t id, const char *err)
{
	char  buf[256];
	ssize_t r = proto_reply_err(buf, sizeof buf, 0, id, err);
	if (r < 0) return -1;
	return ipc_send_to(s, fd, buf, (size_t)r);
}

/* ---- on_tick: chanhop fires this on every successful channel set ---------- */

static void on_chanhop_tick(int channel, int freq, void *user)
{
	emit_event_iface_channel(user, channel, freq);
}

/* ---- timerfd glue: dispatch chanhop's fd into chanhop_on_timer ------------ */

static void on_chanhop_fd(int fd, uint32_t events, void *user)
{
	(void)fd; (void)events;
	chanhop_on_timer(user);
}

/* ---- command handlers ----------------------------------------------------- */

static int handle_ping(struct app *a, int fd, int64_t id)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "pong", "yes")) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int handle_version(struct app *a, int fd, int64_t id)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "name", "wificapc")) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "version", WIFICAPC_VER)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int handle_uptime(struct app *a, int fd, int64_t id)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	int64_t up = (int64_t)(time(NULL) - a->started);

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "uptime", up)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int handle_iface_set(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'name'");

	/* large scratch so we can distinguish 'missing' from 'too long' below */
	char name[64];
	if (proto_args_get_str(args, "name", name, sizeof name) < 0)
		return reply_error(a->ipc, fd, id, "missing or oversize 'name'");
	if (strlen(name) >= sizeof a->iface.name)
		return reply_error(a->ipc, fd, id, "iface name too long");

	/* Re-targeting the iface invalidates everything bound to the previous
	 * one: the AF_PACKET socket (capture) is bound by ifindex, inject
	 * holds a pointer into a->iface and a tx fd from capture, and the
	 * hopper holds a pointer into a->iface. Tear them down so the next
	 * recon_start rebuilds them against the new iface. The handshake
	 * tracker and recon table are iface-agnostic and can survive. */
	if (a->attack_fd >= 0) {
		ipc_remove_fd(a->ipc, a->attack_fd);
		close(a->attack_fd);
		a->attack_fd = -1;
	}
	if (a->inject) {
		inject_destroy(a->inject);
		a->inject = NULL;
	}
	if (a->capture) {
		capture_destroy(a->capture);
		a->capture = NULL;
	}
	if (a->hopper) {
		chanhop_destroy(a->hopper);
		a->hopper = NULL;
	}

	if (iface_open(&a->iface, name) < 0) {
		a->iface_open = 0;
		return reply_error(a->ipc, fd, id, "iface_open failed");
	}

	a->iface_open = 1;
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_iface_info(struct app *a, int fd, int64_t id)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");

	char  buf[512];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "iface", a->iface.name)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "ifindex", a->iface.ifindex)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "wiphy", a->iface.wiphy)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "mode", iface_mode_name(a->iface.mode))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", a->iface.channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "freq", a->iface.freq_mhz)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "hopping", chanhop_is_running(a->hopper))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int ensure_hopper(struct app *a)
{
	if (a->hopper) return 0;
	a->hopper = chanhop_create(&a->iface, a->ipc);
	if (!a->hopper) return -1;
	chanhop_set_on_tick(a->hopper, on_chanhop_tick, a);
	if (ipc_add_fd(a->ipc, chanhop_fd(a->hopper),
	               EPOLLIN, on_chanhop_fd, a->hopper) < 0) {
		chanhop_destroy(a->hopper);
		a->hopper = NULL;
		return -1;
	}
	return 0;
}

static int handle_monitor_on(struct app *a, int fd, int64_t id)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");
	if (iface_set_mode(&a->iface, IFACE_MODE_MONITOR) < 0)
		return reply_error(a->ipc, fd, id, "iface_set_mode failed");
	emit_event_iface_mode(a, IFACE_MODE_MONITOR);
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_monitor_off(struct app *a, int fd, int64_t id)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");
	if (a->hopper && chanhop_is_running(a->hopper))
		chanhop_stop(a->hopper);
	if (iface_set_mode(&a->iface, IFACE_MODE_MANAGED) < 0)
		return reply_error(a->ipc, fd, id, "iface_set_mode failed");
	emit_event_iface_mode(a, IFACE_MODE_MANAGED);
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_set_channel(struct app *a, int fd, int64_t id, const char *args)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");
	int64_t ch;
	if (!args || proto_args_get_int(args, "channel", &ch) < 0)
		return reply_error(a->ipc, fd, id, "missing 'channel'");
	if (ensure_hopper(a) < 0)
		return reply_error(a->ipc, fd, id, "hopper init failed");
	if (chanhop_pin(a->hopper, (int)ch) < 0)
		return reply_error(a->ipc, fd, id, "set_channel failed");
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_hop_start(struct app *a, int fd, int64_t id, const char *args)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");

	int     channels[CHANHOP_MAX_CHANNELS];
	int     n = 0;
	int64_t interval = 250;

	if (!args || proto_args_get_int_array(args, "channels", channels,
	                                      CHANHOP_MAX_CHANNELS, &n) < 0 || n == 0)
		return reply_error(a->ipc, fd, id, "missing 'channels' (non-empty array)");
	(void)proto_args_get_int(args, "interval_ms", &interval);
	if (interval < 50 || interval > 10000)
		return reply_error(a->ipc, fd, id, "interval_ms out of range (50..10000)");

	if (ensure_hopper(a) < 0)
		return reply_error(a->ipc, fd, id, "hopper init failed");
	if (chanhop_start(a->hopper, channels, n, (int)interval) < 0)
		return reply_error(a->ipc, fd, id, "hop_start failed");
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_hop_stop(struct app *a, int fd, int64_t id)
{
	if (a->hopper)
		chanhop_stop(a->hopper);
	return reply_ok_empty(a->ipc, fd, id);
}

/* ---- table emit hook → IPC events ---------------------------------------- */

static int emit_ap_event(struct app *a, const char *tag, const struct ap_record *ap)
{
	char  buf[512];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	char   bssid[18];
	dot11_mac_str(ap->bssid, bssid);

	if ((r = proto_event_begin(buf, sizeof buf, pos, tag)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "bssid", bssid)) < 0) return -1;
	pos = (size_t)r;
	if (ap->ssid_len) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "ssid", ap->ssid)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", ap->channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "rssi", ap->rssi)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast(a->ipc, buf, pos);
}

static int emit_sta_event(struct app *a, const char *tag, const struct sta_record *sta)
{
	char  buf[512];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	char   mac[18], ap[18];
	dot11_mac_str(sta->mac, mac);

	if ((r = proto_event_begin(buf, sizeof buf, pos, tag)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "mac", mac)) < 0) return -1;
	pos = (size_t)r;
	if (sta->have_ap) {
		dot11_mac_str(sta->ap_bssid, ap);
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "ap_bssid", ap)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", sta->channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "rssi", sta->rssi)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast(a->ipc, buf, pos);
}

static void on_table_event(enum table_event evt,
                           const struct ap_record  *ap,
                           const struct sta_record *sta,
                           void *user)
{
	struct app *a = user;
	switch (evt) {
	case TABLE_EVT_AP_NEW:   emit_ap_event (a, "ap.new",   ap);  break;
	case TABLE_EVT_AP_LOST:  emit_ap_event (a, "ap.lost",  ap);  break;
	case TABLE_EVT_STA_NEW:  emit_sta_event(a, "sta.new",  sta); break;
	case TABLE_EVT_STA_LOST: emit_sta_event(a, "sta.lost", sta); break;
	}
}

/* ---- recon commands ------------------------------------------------------- */

static int ensure_table(struct app *a)
{
	if (a->table) return 0;
	a->table = table_create(DEFAULT_AP_TTL_SEC, DEFAULT_STA_TTL_SEC,
	                        on_table_event, a);
	return a->table ? 0 : -1;
}

static int handle_recon_start(struct app *a, int fd, int64_t id)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");
	if (a->iface.mode != IFACE_MODE_MONITOR)
		return reply_error(a->ipc, fd, id, "iface not in monitor mode");
	if (ensure_table(a) < 0)
		return reply_error(a->ipc, fd, id, "table init failed");
	if (ensure_handshake(a) < 0)
		return reply_error(a->ipc, fd, id, "handshake init failed");

	if (!a->capture) {
		a->capture = capture_create(&a->iface, a->table, a->hs, a->ipc);
		if (!a->capture)
			return reply_error(a->ipc, fd, id, "capture init failed");
	}
	if (capture_start(a->capture) < 0)
		return reply_error(a->ipc, fd, id, "capture_start failed");

	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_recon_stop(struct app *a, int fd, int64_t id)
{
	if (a->capture) capture_stop(a->capture);
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_clear(struct app *a, int fd, int64_t id)
{
	if (a->table) table_clear(a->table);
	return reply_ok_empty(a->ipc, fd, id);
}

/*
 * Reply layout:
 *   {"id":N,"ok":true,"data":{"count":K,"items":[ {…}, {…}, … ],
 *                              "truncated":true}}
 *
 * Each item is encoded into the same buffer. If an item would push us past
 * the cap, we roll back to the previous good position, set truncated=true,
 * and stop adding items.
 */

#define EMIT_OR_TRUNC(E) do { ssize_t _r = (E); \
	if (_r < 0) { truncated = 1; pos = snap_pos; goto truncated_out; } \
	pos = (size_t)_r; } while (0)

static int handle_list_aps(struct app *a, int fd, int64_t id)
{
	if (!a->table)
		return reply_error(a->ipc, fd, id, "no table (recon never started)");

	struct ap_record snap[TABLE_MAX_APS];
	int n = table_snapshot_aps(a->table, snap, TABLE_MAX_APS);

	char    buf[16 * 1024];
	size_t  pos       = 0;
	int     first_top = 1;
	int     truncated = 0;
	size_t  snap_pos  = 0;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first_top, "count", n)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_append(buf, sizeof buf, pos, ",\"items\":[")) < 0) return -1;
	pos = (size_t)r;

	for (int i = 0; i < n; i++) {
		snap_pos = pos;
		char bssid[18];
		dot11_mac_str(snap[i].bssid, bssid);
		int  first = 1;

		if (i > 0) EMIT_OR_TRUNC(proto_append(buf, sizeof buf, pos, ","));
		EMIT_OR_TRUNC(proto_append(buf, sizeof buf, pos, "{"));
		EMIT_OR_TRUNC(proto_field_str (buf, sizeof buf, pos, &first, "bssid", bssid));
		if (snap[i].ssid_len)
			EMIT_OR_TRUNC(proto_field_str(buf, sizeof buf, pos, &first, "ssid", snap[i].ssid));
		EMIT_OR_TRUNC(proto_field_int (buf, sizeof buf, pos, &first, "channel",    snap[i].channel));
		EMIT_OR_TRUNC(proto_field_int (buf, sizeof buf, pos, &first, "rssi",       snap[i].rssi));
		EMIT_OR_TRUNC(proto_field_int (buf, sizeof buf, pos, &first, "frames",     (int64_t)snap[i].frames));
		EMIT_OR_TRUNC(proto_field_int (buf, sizeof buf, pos, &first, "first_seen", (int64_t)snap[i].first_seen));
		EMIT_OR_TRUNC(proto_field_int (buf, sizeof buf, pos, &first, "last_seen",  (int64_t)snap[i].last_seen));
		EMIT_OR_TRUNC(proto_append    (buf, sizeof buf, pos, "}"));
	}
truncated_out:
	if ((r = proto_append(buf, sizeof buf, pos, "]")) < 0) return -1;
	pos = (size_t)r;
	if (truncated) {
		if ((r = proto_field_bool(buf, sizeof buf, pos, &first_top, "truncated", 1)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int handle_list_stas(struct app *a, int fd, int64_t id)
{
	if (!a->table)
		return reply_error(a->ipc, fd, id, "no table (recon never started)");

	struct sta_record snap[TABLE_MAX_STAS];
	int n = table_snapshot_stas(a->table, snap, TABLE_MAX_STAS);

	char    buf[64 * 1024];
	size_t  pos       = 0;
	int     first_top = 1;
	int     truncated = 0;
	size_t  snap_pos  = 0;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first_top, "count", n)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_append(buf, sizeof buf, pos, ",\"items\":[")) < 0) return -1;
	pos = (size_t)r;

	for (int i = 0; i < n; i++) {
		snap_pos = pos;
		char mac[18], apb[18];
		dot11_mac_str(snap[i].mac, mac);
		int  first = 1;

		if (i > 0) EMIT_OR_TRUNC(proto_append(buf, sizeof buf, pos, ","));
		EMIT_OR_TRUNC(proto_append(buf, sizeof buf, pos, "{"));
		EMIT_OR_TRUNC(proto_field_str(buf, sizeof buf, pos, &first, "mac", mac));
		if (snap[i].have_ap) {
			dot11_mac_str(snap[i].ap_bssid, apb);
			EMIT_OR_TRUNC(proto_field_str(buf, sizeof buf, pos, &first, "ap_bssid", apb));
		}
		EMIT_OR_TRUNC(proto_field_int(buf, sizeof buf, pos, &first, "channel",    snap[i].channel));
		EMIT_OR_TRUNC(proto_field_int(buf, sizeof buf, pos, &first, "rssi",       snap[i].rssi));
		EMIT_OR_TRUNC(proto_field_int(buf, sizeof buf, pos, &first, "frames",     (int64_t)snap[i].frames));
		EMIT_OR_TRUNC(proto_field_int(buf, sizeof buf, pos, &first, "first_seen", (int64_t)snap[i].first_seen));
		EMIT_OR_TRUNC(proto_field_int(buf, sizeof buf, pos, &first, "last_seen",  (int64_t)snap[i].last_seen));
		EMIT_OR_TRUNC(proto_append   (buf, sizeof buf, pos, "}"));
	}
truncated_out:
	if ((r = proto_append(buf, sizeof buf, pos, "]")) < 0) return -1;
	pos = (size_t)r;
	if (truncated) {
		if ((r = proto_field_bool(buf, sizeof buf, pos, &first_top, "truncated", 1)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_send_to(a->ipc, fd, buf, pos);
}

/* Parse "aa:bb:cc:dd:ee:ff" into 6 bytes. Returns 0 on success. */
static int parse_mac(const char *s, uint8_t out[6])
{
	if (!s) return -1;
	unsigned v[6];
	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
	           &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (v[i] > 0xff) return -1;
		out[i] = (uint8_t)v[i];
	}
	return 0;
}

/* ---- handshake / proc plumbing ------------------------------------------- */

static int emit_hs_event(struct app *a, const char *tag,
                         const struct hs_emit_payload *pl,
                         const char *hash22000_path)
{
	char  buf[1024];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	char   ap[18], sta[18];
	dot11_mac_str(pl->ap_bssid, ap);
	dot11_mac_str(pl->sta_mac,  sta);

	if ((r = proto_event_begin(buf, sizeof buf, pos, tag)) < 0) return -1;
	pos = (size_t)r;
	if (pl->pcap_path) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "file", pl->pcap_path)) < 0) return -1;
		pos = (size_t)r;
	}
	if (hash22000_path) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "hash22000", hash22000_path)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "ap_bssid", ap)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "sta_mac", sta)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", pl->channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "rssi", pl->rssi)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "msg_seen", pl->msg_seen_bitmap)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "pmkid", pl->have_pmkid)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_broadcast(a->ipc, buf, pos);
}

/* Called by handshake.c on every state-machine transition we report. */
static void on_handshake_event(enum hs_event evt,
                               const struct hs_emit_payload *pl,
                               void *user)
{
	struct app *a = user;
	switch (evt) {
	case HS_EVT_HANDSHAKE:
		emit_hs_event(a, "handshake.captured", pl, NULL);
		break;
	case HS_EVT_PMKID:
		emit_hs_event(a, "pmkid.captured", pl, NULL);
		break;
	case HS_EVT_DONE:
		/* hash22000_path is already NULL when no .22000 was written
		 * (handshake.c sets it from p->hash22000_path[0] ? ptr : NULL). */
		emit_hs_event(a, "handshake.done", pl, pl->hash22000_path);
		break;
	}
}

static int ensure_handshake(struct app *a)
{
	if (a->hs) return 0;
	/* handshake module dereferences the table on every captured pair, so
	 * the table MUST exist first — callers can invoke this in any order. */
	if (ensure_table(a) < 0) return -1;
	a->hs = handshake_create(a->table, DEFAULT_HS_DIR, DEFAULT_HS_STALE_SEC,
	                         on_handshake_event, a);
	return a->hs ? 0 : -1;
}

static int handle_set_handshake_dir(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'path'");
	char path[256];
	if (proto_args_get_str(args, "path", path, sizeof path) < 0)
		return reply_error(a->ipc, fd, id, "missing or oversize 'path'");
	if (ensure_handshake(a) < 0)
		return reply_error(a->ipc, fd, id, "handshake init failed");
	if (handshake_set_dir(a->hs, path) < 0)
		return reply_error(a->ipc, fd, id, "set_dir failed");
	return reply_ok_empty(a->ipc, fd, id);
}

/* ---- autonomous attack engine --------------------------------------------- */

static void on_attack_timer(int fd, uint32_t events, void *user)
{
	(void)events;
	struct app *a = user;
	uint64_t exp;
	if (read(fd, &exp, sizeof exp) != (ssize_t)sizeof exp) return;

	if (!a->table || !a->capture || !capture_is_running(a->capture)) return;
	if (ensure_inject(a) < 0) return;

	struct ap_record aps[TABLE_MAX_APS];
	int n_aps = table_snapshot_aps(a->table, aps, TABLE_MAX_APS);
	for (int i = 0; i < n_aps; i++) {
		const char *ssid     = aps[i].ssid_len ? aps[i].ssid : NULL;
		uint8_t     ssid_len = aps[i].ssid_len;
		inject_assoc(a->inject, aps[i].bssid, ssid, ssid_len);
	}

	struct sta_record stas[TABLE_MAX_STAS];
	int n_stas = table_snapshot_stas(a->table, stas, TABLE_MAX_STAS);
	for (int i = 0; i < n_stas; i++) {
		if (stas[i].have_ap)
			inject_deauth(a->inject, stas[i].ap_bssid, stas[i].mac, 2, 7);
	}

	if (n_aps + n_stas > 0)
		log_debug("attack: %d assoc + %d deauth sent", n_aps, n_stas);
}

static int start_attack_timer(struct app *a, int interval_ms)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) { log_err("timerfd_create: %s", strerror(errno)); return -1; }
	struct itimerspec its = {
		.it_interval = { .tv_sec  =  interval_ms / 1000,
		                 .tv_nsec = (long)(interval_ms % 1000) * 1000000L },
		.it_value    = { .tv_sec  =  interval_ms / 1000,
		                 .tv_nsec = (long)(interval_ms % 1000) * 1000000L },
	};
	timerfd_settime(fd, 0, &its, NULL);
	if (ipc_add_fd(a->ipc, fd, EPOLLIN, on_attack_timer, a) < 0) {
		log_err("start_attack_timer: ipc_add_fd failed");
		close(fd);
		return -1;
	}
	return fd;
}

/* ---- auto-start: bring up monitor mode + recon + hopping at launch -------- */

static int parse_channels(const char *s, int *out, int max)
{
	char buf[256];
	snprintf(buf, sizeof buf, "%s", s);
	int n = 0;
	char *tok = strtok(buf, ",");
	while (tok && n < max) {
		int ch = atoi(tok);
		if (ch > 0) out[n++] = ch;
		tok = strtok(NULL, ",");
	}
	return n;
}

struct autostart_opts {
	const char *iface;
	const char *hs_dir;
	const int  *channels;
	int         n_channels;
	int         hop_interval_ms;
	int         attack;
	int         attack_interval_ms;
};

static int autostart(struct app *a, const struct autostart_opts *o)
{
	if (iface_open(&a->iface, o->iface) < 0) {
		log_err("autostart: iface_open(%s) failed", o->iface);
		return -1;
	}
	a->iface_open = 1;
	emit_event_iface_mode(a, a->iface.mode);

	/* NL80211_CMD_SET_INTERFACE requires the interface to be DOWN. */
	iface_link_down(&a->iface);
	if (iface_set_mode(&a->iface, IFACE_MODE_MONITOR) < 0) {
		log_err("autostart: set monitor mode on %s failed", o->iface);
		return -1;
	}
	if (iface_link_up(&a->iface) < 0) {
		log_err("autostart: bring up %s failed", o->iface);
		return -1;
	}
	emit_event_iface_mode(a, IFACE_MODE_MONITOR);
	log_info("autostart: %s in monitor mode", o->iface);

	if (ensure_table(a) < 0 || ensure_handshake(a) < 0) {
		log_err("autostart: table/handshake init failed");
		return -1;
	}
	if (o->hs_dir) {
		handshake_set_dir(a->hs, o->hs_dir);
		log_info("autostart: handshakes → %s", o->hs_dir);
	}

	a->capture = capture_create(&a->iface, a->table, a->hs, a->ipc);
	if (!a->capture || capture_start(a->capture) < 0) {
		log_err("autostart: capture init/start failed");
		return -1;
	}
	log_info("autostart: capturing on %s", o->iface);

	if (o->n_channels > 0) {
		if (ensure_hopper(a) < 0) {
			log_err("autostart: hopper init failed");
			return -1;
		}
		if (chanhop_start(a->hopper, o->channels, o->n_channels,
		                  o->hop_interval_ms) < 0) {
			log_err("autostart: chanhop_start failed");
			return -1;
		}
		log_info("autostart: hopping %d channels at %dms",
		         o->n_channels, o->hop_interval_ms);
	}

	if (o->attack) {
		a->attack_fd = start_attack_timer(a, o->attack_interval_ms);
		if (a->attack_fd < 0)
			log_warn("autostart: attack timer failed — attacks disabled");
		else
			log_info("autostart: autonomous attacks enabled (%dms interval)",
			         o->attack_interval_ms);
	}

	return 0;
}

static int handle_set_wpasec(struct app *a, int fd, int64_t id, const char *args)
{
	int64_t en = 0;
	if (args) (void)proto_args_get_int(args, "enabled", &en);
	(void)a;
	return reply_ok_empty(a->ipc, fd, id);
}

/* ---- runtime tuning ------------------------------------------------------ */

static int handle_set_ttls(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing args");
	int64_t ap_ttl = 0, sta_ttl = 0, min_rssi = 127;
	(void)proto_args_get_int(args, "ap_ttl",   &ap_ttl);
	(void)proto_args_get_int(args, "sta_ttl",  &sta_ttl);
	(void)proto_args_get_int(args, "min_rssi", &min_rssi);

	if (ensure_table(a) < 0)
		return reply_error(a->ipc, fd, id, "table init failed");
	table_set_ttls(a->table, (int)ap_ttl, (int)sta_ttl);

	if (a->capture && min_rssi != 127)
		capture_set_min_rssi(a->capture, (int)min_rssi);

	return reply_ok_empty(a->ipc, fd, id);
}

/* ---- frame injection (deauth / assoc) ------------------------------------ */

static int ensure_inject(struct app *a)
{
	if (a->inject) return 0;
	if (!a->capture || !capture_is_running(a->capture))
		return -1;
	int sock_fd = capture_sock_fd(a->capture);
	if (sock_fd < 0) return -1;
	a->inject = inject_create(sock_fd, &a->iface);
	return a->inject ? 0 : -1;
}

static int handle_deauth(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'bssid'");

	char     bssid_s[32];
	if (proto_args_get_str(args, "bssid", bssid_s, sizeof bssid_s) < 0)
		return reply_error(a->ipc, fd, id, "missing 'bssid'");

	uint8_t  bssid[6];
	if (parse_mac(bssid_s, bssid) < 0)
		return reply_error(a->ipc, fd, id, "bssid is not a MAC");

	uint8_t  sta[6];
	int      have_sta = 0;
	char     sta_s[32];
	if (proto_args_get_str(args, "sta", sta_s, sizeof sta_s) == 0) {
		if (parse_mac(sta_s, sta) < 0)
			return reply_error(a->ipc, fd, id, "sta is not a MAC");
		have_sta = 1;
	}

	int64_t count_64 = 5;
	(void)proto_args_get_int(args, "count", &count_64);
	if (count_64 < 1 || count_64 > 256)
		return reply_error(a->ipc, fd, id, "count must be 1..256");

	int64_t reason_64 = 7;
	(void)proto_args_get_int(args, "reason", &reason_64);

	if (ensure_inject(a) < 0)
		return reply_error(a->ipc, fd, id, "inject requires recon_start first");

	int sent = inject_deauth(a->inject, bssid, have_sta ? sta : NULL,
	                         (int)count_64, (int)reason_64);

	char  buf[128];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "sent", sent)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_send_to(a->ipc, fd, buf, pos);
}

static int handle_assoc(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'bssid'");

	char    bssid_s[32];
	if (proto_args_get_str(args, "bssid", bssid_s, sizeof bssid_s) < 0)
		return reply_error(a->ipc, fd, id, "missing 'bssid'");

	uint8_t bssid[6];
	if (parse_mac(bssid_s, bssid) < 0)
		return reply_error(a->ipc, fd, id, "bssid is not a MAC");

	if (ensure_inject(a) < 0)
		return reply_error(a->ipc, fd, id, "inject requires recon_start first");

	/* If we know the BSSID, look up its SSID from the recon table; otherwise
	 * fall through with a wildcard. */
	const char *ssid     = NULL;
	uint8_t     ssid_len = 0;
	if (a->table) {
		const struct ap_record *ap = table_find_ap(a->table, bssid);
		if (ap && ap->ssid_len > 0) {
			ssid     = ap->ssid;
			ssid_len = ap->ssid_len;
		}
	}

	if (inject_assoc(a->inject, bssid, ssid, ssid_len) < 0)
		return reply_error(a->ipc, fd, id, "assoc send failed");
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_stats(struct app *a, int fd, int64_t id)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "n_aps",
	                         a->table ? table_n_aps(a->table) : 0)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "n_stas",
	                         a->table ? table_n_stas(a->table) : 0)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "frames_total",
	                         (int64_t)capture_frames_total(a->capture))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "frames_dropped",
	                         (int64_t)capture_frames_dropped(a->capture))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "capturing",
	                          capture_is_running(a->capture))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_send_to(a->ipc, fd, buf, pos);
}

/* ---- top-level dispatch --------------------------------------------------- */

static int on_line(int fd, char *line, size_t len, void *user)
{
	struct app *a = user;

	struct proto_request req;
	const char *err = NULL;
	if (proto_parse_request(line, len, &req, &err) < 0) {
		log_warn("client fd=%d parse error: %s", fd, err);
		return reply_error(a->ipc, fd, -1, err ? err : "parse error");
	}

	log_debug("client fd=%d cmd='%s' id=%lld", fd, req.cmd, (long long)req.id);

	if (strcmp(req.cmd, "ping")        == 0) return handle_ping(a, fd, req.id);
	if (strcmp(req.cmd, "version")     == 0) return handle_version(a, fd, req.id);
	if (strcmp(req.cmd, "uptime")      == 0) return handle_uptime(a, fd, req.id);
	if (strcmp(req.cmd, "iface_set")   == 0) return handle_iface_set(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "iface_info")  == 0) return handle_iface_info(a, fd, req.id);
	if (strcmp(req.cmd, "monitor_on")  == 0) return handle_monitor_on(a, fd, req.id);
	if (strcmp(req.cmd, "monitor_off") == 0) return handle_monitor_off(a, fd, req.id);
	if (strcmp(req.cmd, "set_channel") == 0) return handle_set_channel(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "hop_start")   == 0) return handle_hop_start(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "hop_stop")    == 0) return handle_hop_stop(a, fd, req.id);
	if (strcmp(req.cmd, "recon_start") == 0) return handle_recon_start(a, fd, req.id);
	if (strcmp(req.cmd, "recon_stop")  == 0) return handle_recon_stop(a, fd, req.id);
	if (strcmp(req.cmd, "list_aps")    == 0) return handle_list_aps(a, fd, req.id);
	if (strcmp(req.cmd, "list_stas")   == 0) return handle_list_stas(a, fd, req.id);
	if (strcmp(req.cmd, "stats")       == 0) return handle_stats(a, fd, req.id);
	if (strcmp(req.cmd, "clear")       == 0) return handle_clear(a, fd, req.id);
	if (strcmp(req.cmd, "set_handshake_dir") == 0) return handle_set_handshake_dir(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_wpasec")  == 0) return handle_set_wpasec(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "deauth")      == 0) return handle_deauth(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "assoc")       == 0) return handle_assoc(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_ttls")    == 0) return handle_set_ttls(a, fd, req.id, req.args_raw);

	return reply_error(a->ipc, fd, req.id, "unknown command");
}

/* ---- options & boot ------------------------------------------------------- */

struct opts {
	const char *sock_path;
	mode_t      sock_mode;
	int         foreground;
	int         debug;
	/* auto-start */
	const char *iface;
	const char *hs_dir;
	int         channels[CHANHOP_MAX_CHANNELS];
	int         n_channels;
	int         hop_interval_ms;
	int         attack;
	int         attack_interval_ms;
};

static void usage(FILE *f, const char *argv0)
{
	fprintf(f,
	    "wificapc " WIFICAPC_VER " — native 802.11 capture daemon\n"
	    "\n"
	    "Usage: %s [options]\n"
	    "  -s, --socket   PATH    Unix socket path (default: " DEFAULT_SOCK ")\n"
	    "  -m, --mode     OCTAL   Socket file mode (default: 0660)\n"
	    "  -f, --foreground       Stay in foreground, log to stderr\n"
	    "  -d, --debug            Enable debug logging\n"
	    "  -h, --help             Show this help\n"
	    "  -V, --version          Print version and exit\n"
	    "\n"
	    "Auto-start (all required when using -i):\n"
	    "  -i, --iface      IFACE   Monitor-mode interface (e.g. wlan0)\n"
	    "  -H, --hs-dir     PATH    Handshake .22000 output directory\n"
	    "                           (default: " DEFAULT_HS_DIR ")\n"
	    "  -C, --channels   LIST    Comma-separated channels to hop\n"
	    "                           (default: 1-13)\n"
	    "      --hop-interval MS    Channel dwell time ms (default: %d)\n"
	    "  -A, --attack             Enable autonomous deauth+assoc attacks\n"
	    "      --attack-interval MS Attack period ms (default: %d)\n",
	    argv0, DEFAULT_HOP_INTERVAL_MS, DEFAULT_ATTACK_INTERVAL_MS);
}

static int parse_opts(int argc, char **argv, struct opts *o)
{
	enum {
		OPT_HOP_INTERVAL = 256,
		OPT_ATTACK_INTERVAL,
	};
	static const struct option longopts[] = {
		{ "socket",           required_argument, NULL, 's' },
		{ "mode",             required_argument, NULL, 'm' },
		{ "foreground",       no_argument,       NULL, 'f' },
		{ "debug",            no_argument,       NULL, 'd' },
		{ "help",             no_argument,       NULL, 'h' },
		{ "version",          no_argument,       NULL, 'V' },
		{ "iface",            required_argument, NULL, 'i' },
		{ "hs-dir",           required_argument, NULL, 'H' },
		{ "channels",         required_argument, NULL, 'C' },
		{ "attack",           no_argument,       NULL, 'A' },
		{ "hop-interval",     required_argument, NULL, OPT_HOP_INTERVAL },
		{ "attack-interval",  required_argument, NULL, OPT_ATTACK_INTERVAL },
		{ 0 },
	};
	int c;
	while ((c = getopt_long(argc, argv, "s:m:fdhVi:H:C:A", longopts, NULL)) != -1) {
		switch (c) {
		case 's': o->sock_path = optarg; break;
		case 'm': o->sock_mode = (mode_t)strtol(optarg, NULL, 8); break;
		case 'f': o->foreground = 1; break;
		case 'd': o->debug = 1; break;
		case 'h': usage(stdout, argv[0]); return 1;
		case 'V': printf("wificapc %s\n", WIFICAPC_VER); return 1;
		case 'i': o->iface = optarg; break;
		case 'H': o->hs_dir = optarg; break;
		case 'C':
			o->n_channels = parse_channels(optarg, o->channels,
			                               CHANHOP_MAX_CHANNELS);
			break;
		case 'A': o->attack = 1; break;
		case OPT_HOP_INTERVAL:    o->hop_interval_ms    = atoi(optarg); break;
		case OPT_ATTACK_INTERVAL: o->attack_interval_ms = atoi(optarg); break;
		default:  usage(stderr, argv[0]); return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct opts o = {
		.sock_path           = DEFAULT_SOCK,
		.sock_mode           = 0660,
		.foreground          = 1,
		.debug               = 0,
		.hs_dir              = DEFAULT_HS_DIR,
		.hop_interval_ms     = DEFAULT_HOP_INTERVAL_MS,
		.attack_interval_ms  = DEFAULT_ATTACK_INTERVAL_MS,
	};

	int rc = parse_opts(argc, argv, &o);
	if (rc != 0) return rc < 0 ? 1 : 0;

	/* If --iface was given but no --channels, use the default 2.4 GHz list. */
	if (o.iface && o.n_channels == 0) {
		for (int i = 0; i < DEFAULT_N_CHANNELS; i++)
			o.channels[i] = DEFAULT_CHANNELS[i];
		o.n_channels = DEFAULT_N_CHANNELS;
	}

	log_init(o.debug ? LL_DEBUG : LL_INFO, !o.foreground);
	log_info("wificapc %s starting", WIFICAPC_VER);
	log_info("listening on %s (mode 0%o)", o.sock_path, (unsigned)o.sock_mode);

	install_signals();

	struct app a = {0};
	a.started    = time(NULL);
	a.attack_fd  = -1;

	a.ipc = ipc_create(o.sock_path, o.sock_mode);
	if (!a.ipc) {
		log_err("failed to start ipc");
		return 1;
	}
	g_app = &a;
	ipc_set_on_line(a.ipc, on_line, &a);

	if (o.iface) {
		struct autostart_opts ao = {
			.iface              = o.iface,
			.hs_dir             = o.hs_dir,
			.channels           = o.channels,
			.n_channels         = o.n_channels,
			.hop_interval_ms    = o.hop_interval_ms,
			.attack             = o.attack,
			.attack_interval_ms = o.attack_interval_ms,
		};
		if (autostart(&a, &ao) < 0) {
			log_err("autostart failed — continuing in command-only mode");
		}
	}

	int run_rc = ipc_run(a.ipc);

	log_info("shutting down");
	if (a.attack_fd >= 0) { ipc_remove_fd(a.ipc, a.attack_fd); close(a.attack_fd); }
	if (a.inject)  inject_destroy(a.inject);
	if (a.capture) capture_destroy(a.capture);
	if (a.hopper)  chanhop_destroy(a.hopper);
	if (a.hs)      handshake_destroy(a.hs);
	if (a.proc)    proc_destroy(a.proc);
	if (a.table)   table_destroy(a.table);
	ipc_destroy(a.ipc);
	g_app = NULL;
	log_close();
	return run_rc < 0 ? 1 : 0;
}
