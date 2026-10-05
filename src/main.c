/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "capture.h"
#include "chanhop.h"
#include "dot11.h"
#include "handshake.h"
#include "iface.h"
#include "inject.h"
#include "ipc.h"
#include "log.h"
#include "proto.h"
#include "state.h"
#include "table.h"

#include <errno.h>
#include <getopt.h>
#include <net/if.h>    /* if_nametoindex */
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
#define WIFICAPC_VER     "0.8.5"

#define DEFAULT_AP_TTL_SEC      120
#define DEFAULT_STA_TTL_SEC     300
#define DEFAULT_HS_STALE_SEC     30
#define DEFAULT_HOP_INTERVAL_MS 250
#define DEFAULT_ATTACK_INTERVAL_MS 5000
#define DEFAULT_STATE_FILE        "/tmp/wificapc/state.bin"
#define DEFAULT_STATE_MAX_AGE_SEC 600

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
	struct inject     *inject;
	int                attack_fd;
	int                health_fd;        /* rx-silence watchdog timer */
	uint64_t           health_frames;    /* capture frames_total at last check */
	time_t             health_progress;  /* last time frames advanced / hop was off */
	int                mac_rand;   /* --mac-rand applied to inject when created */
	int                pmkid_only; /* S2: autonomous attack does assoc only, no deauth */
	int                auto_mode;  /* AU3: self-driving --auto mode (hop+attack by daemon) */
	int                attack_enabled; /* --auto: gate the per-channel attack (set_attack) */
	/* AU7: channels/interval captured at autostart so auto_start can resume
	 * the self-hop after an auto_stop handed channel control to a client. */
	int                auto_channels[CHANHOP_MAX_CHANNELS];
	int                auto_n_channels;
	int                auto_hop_ms;
	char               auto_vif[16]; /* AU2: monitor vif we created ("" = none) */
	time_t             status_last;  /* AU5: last periodic --auto status log */
	const char        *state_file; /* R1: recon-table persistence path ("" disables) */
	int                state_max_age; /* R1: ignore persisted state older than this (s) */
	time_t             started;
};

static struct app  *g_app;

/* forward decls — used before their definitions appear */
static int ensure_table(struct app *a);
static int ensure_handshake(struct app *a);
static void attack_on_channel(struct app *a, int channel);
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

/* Map an event tag (what we emit) or a subscription token (what a client
 * names in subscribe/unsubscribe) to its IPC_EVT_* bit(s). Unknown emit
 * tags fall back to IPC_EVT_ALL so a new event is never silently hidden;
 * unknown subscription tokens return 0 so the caller can reject them. */
static uint32_t ipc_evt_for_token(const char *t, int for_emit)
{
	if (!strcmp(t, "ap.new"))        return IPC_EVT_AP_NEW;
	if (!strcmp(t, "ap.lost"))       return IPC_EVT_AP_LOST;
	if (!strcmp(t, "sta.new"))       return IPC_EVT_STA_NEW;
	if (!strcmp(t, "sta.lost"))      return IPC_EVT_STA_LOST;
	if (!strcmp(t, "iface.channel")) return IPC_EVT_IFACE;
	if (!strcmp(t, "iface.mode"))    return IPC_EVT_IFACE;
	if (!strcmp(t, "iface"))         return IPC_EVT_IFACE;
	if (!strcmp(t, "handshake") || !strncmp(t, "handshake.", 10) ||
	    !strcmp(t, "pmkid.captured")) return IPC_EVT_HANDSHAKE;
	if (!strcmp(t, "attack") || !strncmp(t, "attack.", 7)) return IPC_EVT_ATTACK;
	if (!strcmp(t, "all") || !strcmp(t, "*")) return IPC_EVT_ALL;
	return for_emit ? IPC_EVT_ALL : 0u;
}

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

	return ipc_broadcast_event(a->ipc, IPC_EVT_IFACE, buf, pos);
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

	return ipc_broadcast_event(a->ipc, IPC_EVT_IFACE, buf, pos);
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
	struct app *a = user;
	emit_event_iface_channel(a, channel, freq);
	/* AU4: in --auto, couple the attack to the dwell — inject at the APs on
	 * the channel we just tuned to (off-channel frames never reach them).
	 * Gated by attack_enabled so the agent can run capture-only (manual
	 * mode) without any active attack, per set_attack. */
	if (a->auto_mode && a->attack_enabled)
		attack_on_channel(a, channel);
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

/* AU1: report the regdomain-allowed channels this radio can use. */
static int handle_iface_channels(struct app *a, int fd, int64_t id)
{
	if (!a->iface_open)
		return reply_error(a->ipc, fd, id, "no iface set");

	int chans[CHANHOP_MAX_CHANNELS];
	int n = iface_supported_channels(&a->iface, chans, CHANHOP_MAX_CHANNELS);
	if (n < 0)
		return reply_error(a->ipc, fd, id, "channel enumeration failed");

	char   buf[1024];
	size_t pos   = 0;
	int    first = 1;
	ssize_t r;
	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "count", n)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_append(buf, sizeof buf, pos, ",\"channels\":[")) < 0) return -1;
	pos = (size_t)r;
	for (int i = 0; i < n; i++) {
		char num[16];
		snprintf(num, sizeof num, "%s%d", i ? "," : "", chans[i]);
		if ((r = proto_append(buf, sizeof buf, pos, num)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_append(buf, sizeof buf, pos, "]")) < 0) return -1;
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
	if (ap->vendor[0]) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "vendor", ap->vendor)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", ap->channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "rssi", ap->rssi)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast_event(a->ipc, ipc_evt_for_token(tag, 1), buf, pos);
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
	if (sta->vendor[0]) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "vendor", sta->vendor)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", sta->channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "rssi", sta->rssi)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast_event(a->ipc, ipc_evt_for_token(tag, 1), buf, pos);
}

/* Emit a lightweight attack event so a UI client (the agent) can show what
 * the --auto engine is attacking. One representative event per channel round
 * (see attack_on_channel) keeps the IPC light. `ssid` is the AP SSID (NUL-
 * terminated) or NULL; `sta_mac` is set for deauth, NULL for assoc; `vendor`
 * is the AP vendor (assoc) or STA vendor (deauth). */
static int emit_attack_event(struct app *a, const char *tag,
                             const uint8_t ap_bssid[6], const char *ssid,
                             const uint8_t *sta_mac, const char *vendor,
                             int channel)
{
	char   buf[512];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	char   bssid_s[18], sta_s[18];
	dot11_mac_str(ap_bssid, bssid_s);

	if ((r = proto_event_begin(buf, sizeof buf, pos, tag)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "ap_bssid", bssid_s)) < 0) return -1;
	pos = (size_t)r;
	if (ssid && *ssid) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "ssid", ssid)) < 0) return -1;
		pos = (size_t)r;
	}
	if (sta_mac) {
		dot11_mac_str(sta_mac, sta_s);
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "sta_mac", sta_s)) < 0) return -1;
		pos = (size_t)r;
	}
	if (vendor && *vendor) {
		if ((r = proto_field_str(buf, sizeof buf, pos, &first, "vendor", vendor)) < 0) return -1;
		pos = (size_t)r;
	}
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "channel", channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_broadcast_event(a->ipc, IPC_EVT_ATTACK, buf, pos);
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
	if (!a->table) return -1;
	/* R1: reload the airspace we persisted at the last shutdown, so a
	 * respawn (watchdog/brcmfmac recovery) comes back aware instead of
	 * blind. Restored records emit no events; the daemon's own attack
	 * engine + handshake collector benefit immediately. Stale entries
	 * age out on the first eviction tick. */
	if (a->state_file && *a->state_file)
		state_load(a->table, a->state_file, a->state_max_age);
	return 0;
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
	/* Q7: computed WPA*02 messagepair — low 3 bits = pair type, bit 7 set
	 * when the replay counter couldn't be verified. 0 = no usable EAPOL. */
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "messagepair", pl->messagepair)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_event_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_broadcast_event(a->ipc, IPC_EVT_HANDSHAKE, buf, pos);
}

/* Called by handshake.c on every state-machine transition we report. */
static void on_handshake_event(enum hs_event evt,
                               const struct hs_emit_payload *pl,
                               void *user)
{
	struct app *a = user;
	/* Once we hold any handshake material for this AP, stop the autonomous
	 * engine from re-attacking it (see on_attack_timer). */
	if (a->table)
		table_mark_ap_captured(a->table, pl->ap_bssid);
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

static int handle_delete_handshake(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'ap_bssid' / 'sta_mac'");
	if (!a->hs)
		return reply_error(a->ipc, fd, id, "no handshake module");

	char ap_s[32], sta_s[32];
	if (proto_args_get_str(args, "ap_bssid", ap_s, sizeof ap_s) < 0)
		return reply_error(a->ipc, fd, id, "missing 'ap_bssid'");
	if (proto_args_get_str(args, "sta_mac",  sta_s, sizeof sta_s) < 0)
		return reply_error(a->ipc, fd, id, "missing 'sta_mac'");

	uint8_t ap[6], sta[6];
	if (parse_mac(ap_s,  ap)  < 0)
		return reply_error(a->ipc, fd, id, "ap_bssid is not a MAC");
	if (parse_mac(sta_s, sta) < 0)
		return reply_error(a->ipc, fd, id, "sta_mac is not a MAC");

	int removed = handshake_delete_pair(a->hs, ap, sta);

	char  buf[128];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;
	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "removed", removed)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;
	return ipc_send_to(a->ipc, fd, buf, pos);
}

/* ---- autonomous attack engine --------------------------------------------- */

/* Autonomous-attack scheduling knobs. The old engine hit every AP + STA
 * every tick: on a dense channel that meant dozens of auth/assoc/deauth
 * frames (each with a driver gap) stalling the event loop, flooding the
 * air, and burning log volume — all while re-attacking APs already cracked.
 * Now each tick skips captured APs, honours a per-target cooldown, gives up
 * on targets that won't yield, and caps how many frames launch per tick. */
#define ATTACK_COOLDOWN_SEC   30   /* don't re-hit the same target within this */
#define ATTACK_MAX_ATTEMPTS   10   /* give up on a target that won't yield */
#define ATTACK_PER_TICK        8   /* cap assoc (and deauth) launched per tick */

/* AU4: attack the uncaptured APs on `channel`. Called from the chanhop hook
 * in --auto so injection always lands on the tuned channel. PMKID-first
 * (directed assoc elicits the M1 PMKID, clientless); deauth associated
 * clients to force the 4-way unless pmkid_only. Honours the P2 captured-skip,
 * per-target cooldown, and attempt cap. */
static void attack_on_channel(struct app *a, int channel)
{
	if (!a->table || !a->capture || !capture_is_running(a->capture)) return;
	if (ensure_inject(a) < 0) return;
	time_t now = time(NULL);

	struct ap_record aps[TABLE_MAX_APS];
	int n_aps = table_snapshot_aps(a->table, aps, TABLE_MAX_APS);
	int assoc_sent = 0, deauth_sent = 0;

	for (int i = 0; i < n_aps && assoc_sent < ATTACK_PER_TICK; i++) {
		if (aps[i].channel != channel) continue;    /* on-channel only */
		if (aps[i].captured) continue;
		if (aps[i].attack_count >= ATTACK_MAX_ATTEMPTS) continue;
		if (aps[i].last_attack && now - aps[i].last_attack < ATTACK_COOLDOWN_SEC)
			continue;
		const char *ssid = aps[i].ssid_len ? aps[i].ssid : NULL;
		inject_assoc(a->inject, aps[i].bssid, ssid, aps[i].ssid_len);
		if (assoc_sent == 0)   /* one representative event per round (UI) */
			emit_attack_event(a, "attack.assoc", aps[i].bssid, ssid,
			                  NULL, aps[i].vendor, channel);
		table_note_ap_attacked(a->table, aps[i].bssid, now);
		assoc_sent++;
	}

	if (!a->pmkid_only) {
		struct sta_record stas[TABLE_MAX_STAS];
		int n_stas = table_snapshot_stas(a->table, stas, TABLE_MAX_STAS);
		for (int i = 0; i < n_stas && deauth_sent < ATTACK_PER_TICK; i++) {
			if (stas[i].channel != channel) continue;   /* on-channel only */
			if (!stas[i].have_ap) continue;
			if (table_ap_is_captured(a->table, stas[i].ap_bssid)) continue;
			if (stas[i].attack_count >= ATTACK_MAX_ATTEMPTS) continue;
			if (stas[i].last_attack && now - stas[i].last_attack < ATTACK_COOLDOWN_SEC)
				continue;
			inject_deauth(a->inject, stas[i].ap_bssid, stas[i].mac, 2, 7);
			if (deauth_sent == 0)   /* one representative event per round (UI) */
				emit_attack_event(a, "attack.deauth", stas[i].ap_bssid, NULL,
				                  stas[i].mac, stas[i].vendor, channel);
			table_note_sta_attacked(a->table, stas[i].mac, now);
			deauth_sent++;
		}
	}

	if (assoc_sent + deauth_sent > 0)
		log_debug("auto: ch %d - %d assoc + %d deauth", channel, assoc_sent, deauth_sent);
}

static void on_attack_timer(int fd, uint32_t events, void *user)
{
	(void)events;
	struct app *a = user;
	uint64_t exp;
	if (read(fd, &exp, sizeof exp) != (ssize_t)sizeof exp) return;

	if (!a->table || !a->capture || !capture_is_running(a->capture)) return;
	if (ensure_inject(a) < 0) return;

	time_t now = time(NULL);

	/* --- assoc (PMKID elicitation), up to the per-tick budget --- */
	struct ap_record aps[TABLE_MAX_APS];
	int n_aps = table_snapshot_aps(a->table, aps, TABLE_MAX_APS);
	int assoc_sent = 0;
	for (int i = 0; i < n_aps && assoc_sent < ATTACK_PER_TICK; i++) {
		if (aps[i].captured) continue;
		if (aps[i].attack_count >= ATTACK_MAX_ATTEMPTS) continue;
		if (aps[i].last_attack && now - aps[i].last_attack < ATTACK_COOLDOWN_SEC)
			continue;
		const char *ssid     = aps[i].ssid_len ? aps[i].ssid : NULL;
		uint8_t     ssid_len = aps[i].ssid_len;
		inject_assoc(a->inject, aps[i].bssid, ssid, ssid_len);
		table_note_ap_attacked(a->table, aps[i].bssid, now);
		assoc_sent++;
	}

	/* --- deauth associated STAs, skipping cracked APs, up to the budget ---
	 * In PMKID-only mode (S2) we never deauth: assoc alone elicits the M1
	 * PMKID, and skipping deauth cycles targets faster and is far quieter
	 * (no client disruption, no 4-way chase). */
	int deauth_sent = 0;
	struct sta_record stas[TABLE_MAX_STAS];
	int n_stas = a->pmkid_only ? 0 : table_snapshot_stas(a->table, stas, TABLE_MAX_STAS);
	for (int i = 0; i < n_stas && deauth_sent < ATTACK_PER_TICK; i++) {
		if (!stas[i].have_ap) continue;
		if (table_ap_is_captured(a->table, stas[i].ap_bssid)) continue;
		if (stas[i].attack_count >= ATTACK_MAX_ATTEMPTS) continue;
		if (stas[i].last_attack && now - stas[i].last_attack < ATTACK_COOLDOWN_SEC)
			continue;
		inject_deauth(a->inject, stas[i].ap_bssid, stas[i].mac, 2, 7);
		table_note_sta_attacked(a->table, stas[i].mac, now);
		deauth_sent++;
	}

	if (assoc_sent + deauth_sent > 0)
		log_info("attack: %d assoc + %d deauth sent", assoc_sent, deauth_sent);
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
	int         auto_mode;     /* AU3: self-driving --auto (hop-coupled attack) */
};

/* AU2/AU3: create a monitor vif on `base`'s wiphy and leave the base
 * (managed) netdev down — the brcmfmac invariant. Fills `mon_out` with the
 * vif name ("<base>mon") and records it in a->auto_vif for cleanup only when
 * we actually created it. */
static int auto_prepare_vif(struct app *a, const char *base,
                            char *mon_out, size_t cap)
{
	snprintf(mon_out, cap, "%smon", base);

	/* If a monitor vif already exists, the environment prepped it (e.g. the
	 * pwnagotchi launcher after its brcmfmac reload). Reuse it as-is and do
	 * NOT touch the base's up/down state — bringing the base up would disturb
	 * the already-tuned monitor vif. We didn't create it, so we won't delete
	 * it on exit. */
	if (if_nametoindex(mon_out) != 0) {
		log_info("auto: reusing existing monitor vif %s", mon_out);
		return 0;
	}

	struct iface tmp = {0};   /* iface_open() calls iface_close() first, which
	                           * frees tmp.nl — must be zeroed or it frees garbage. */
	if (iface_open(&tmp, base) < 0) {
		log_err("auto: iface_open(%s) failed — not a wifi interface?", base);
		return -1;
	}

	/* brcmfmac quirk (matches the proven launcher sequence): the managed
	 * netdev must be UP, and settled, when the monitor vif is created —
	 * creating it with the base down fails with -10. We then bring the base
	 * DOWN so the monitor vif can tune the radio (the -25 invariant). */
	iface_link_up(&tmp);
	sleep(2);
	int rc = iface_add_monitor_vif(&tmp, mon_out);
	if (rc >= 0) {
		sleep(1);
		iface_link_down(&tmp);
	}
	iface_close(&tmp);
	if (rc < 0) return -1;
	if (rc == 1)   /* we created it -> we remove it on exit */
		snprintf(a->auto_vif, sizeof a->auto_vif, "%s", mon_out);
	return 0;
}

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

	/* Channels: use the given list, else (auto mode) ask the regdomain,
	 * else fall back to the 2.4 GHz default. */
	int        auto_ch[CHANHOP_MAX_CHANNELS];
	const int *channels   = o->channels;
	int        n_channels = o->n_channels;
	if (n_channels == 0 && o->auto_mode) {
		int n = iface_supported_channels(&a->iface, auto_ch, CHANHOP_MAX_CHANNELS);
		if (n > 0) {
			channels   = auto_ch;
			n_channels = n;
			log_info("autostart: auto-detected %d channels", n);
		} else {
			channels   = DEFAULT_CHANNELS;
			n_channels = DEFAULT_N_CHANNELS;
			log_warn("autostart: channel auto-detect returned none, using default 1-%d",
			         DEFAULT_N_CHANNELS);
		}
	}

	if (n_channels > 0) {
		if (ensure_hopper(a) < 0) {
			log_err("autostart: hopper init failed");
			return -1;
		}
		if (chanhop_start(a->hopper, channels, n_channels,
		                  o->hop_interval_ms) < 0) {
			log_err("autostart: chanhop_start failed");
			return -1;
		}
		/* AU7: remember for auto_start (resume after an auto_stop). */
		int nkeep = n_channels < CHANHOP_MAX_CHANNELS ? n_channels : CHANHOP_MAX_CHANNELS;
		for (int i = 0; i < nkeep; i++) a->auto_channels[i] = channels[i];
		a->auto_n_channels = nkeep;
		a->auto_hop_ms     = o->hop_interval_ms;
		log_info("autostart: hopping %d channels at %dms",
		         n_channels, o->hop_interval_ms);
	}

	if (o->attack) {
		if (o->auto_mode) {
			/* AU4: attacks are driven per-dwell from on_chanhop_tick, so
			 * injection lands on the tuned channel. No separate timer.
			 * Default on for a standalone engine; a client (the agent) can
			 * flip it off for capture-only via set_attack. */
			a->auto_mode = 1;
			a->attack_enabled = 1;
			log_info("autostart: autonomous attacks enabled (per-channel, --auto)");
		} else {
			a->attack_fd = start_attack_timer(a, o->attack_interval_ms);
			if (a->attack_fd < 0)
				log_warn("autostart: attack timer failed — attacks disabled");
			else
				log_info("autostart: autonomous attacks enabled (%dms interval)",
				         o->attack_interval_ms);
		}
	}

	return 0;
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

static int handle_set_mac_rand(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");
	int64_t en = 0;
	if (proto_args_get_int(args, "enabled", &en) < 0)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");

	a->mac_rand = !!en;
	/* If the inject struct already exists (recon was started before this
	 * call), apply the toggle to it now. Otherwise ensure_inject will
	 * pick up a->mac_rand the next time it's created. */
	if (a->inject)
		inject_set_mac_rand(a->inject, a->mac_rand);
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_set_pmkid_only(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");
	int64_t en = 0;
	if (proto_args_get_int(args, "enabled", &en) < 0)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");

	/* S2: toggle the autonomous attacker between full (assoc+deauth) and
	 * PMKID-only (assoc, no deauth). Takes effect on the next attack tick;
	 * harmless when --attack is off. */
	a->pmkid_only = !!en;
	return reply_ok_empty(a->ipc, fd, id);
}

static int handle_set_attack(struct app *a, int fd, int64_t id, const char *args)
{
	if (!args)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");
	int64_t en = 0;
	if (proto_args_get_int(args, "enabled", &en) < 0)
		return reply_error(a->ipc, fd, id, "missing 'enabled'");

	/* Gate the --auto per-channel attack at runtime. Capture + hopping are
	 * unaffected — this only turns the active assoc/deauth on or off, so a
	 * client can run capture-only (e.g. pwnagotchi manual mode) and flip
	 * attacks on when it switches to auto. */
	a->attack_enabled = !!en;
	log_info("set_attack: autonomous attack %s", a->attack_enabled ? "on" : "off");
	return reply_ok_empty(a->ipc, fd, id);
}

/* AU7: stop the --auto self-driving (hop + per-channel attack) WITHOUT
 * dropping monitor/capture, handing channel control to a client (pwnagotc
 * "Agent" mode, where the agent drives recon/hop/attack itself). */
static int handle_auto_stop(struct app *a, int fd, int64_t id)
{
	if (a->hopper && chanhop_is_running(a->hopper))
		chanhop_stop(a->hopper);
	a->auto_mode = 0;                 /* on_chanhop_tick no longer attacks */
	log_info("auto_stop: self-driving off (capture stays up; client drives)");
	return reply_ok_empty(a->ipc, fd, id);
}

/* AU7: resume the --auto self-driving (re-hop the channels detected at
 * startup; attack per set_attack). */
static int handle_auto_start(struct app *a, int fd, int64_t id)
{
	if (a->auto_n_channels <= 0)
		return reply_error(a->ipc, fd, id, "auto not available (daemon not started with --auto)");
	if (ensure_hopper(a) < 0)
		return reply_error(a->ipc, fd, id, "hopper init failed");
	if (!chanhop_is_running(a->hopper) &&
	    chanhop_start(a->hopper, a->auto_channels, a->auto_n_channels,
	                  a->auto_hop_ms) < 0)
		return reply_error(a->ipc, fd, id, "chanhop_start failed");
	a->auto_mode = 1;
	log_info("auto_start: self-driving on (%d channels, attack %s)",
	         a->auto_n_channels, a->attack_enabled ? "on" : "off");
	return reply_ok_empty(a->ipc, fd, id);
}

/* X4: parse the comma/space-separated `events` arg into an IPC_EVT_* mask.
 * `*any_unknown` is set if a token didn't resolve. */
static uint32_t parse_event_list(const char *csv, int *any_unknown)
{
	char      tmp[256];
	uint32_t  mask = 0;
	snprintf(tmp, sizeof tmp, "%s", csv);
	for (char *tok = strtok(tmp, ", \t"); tok; tok = strtok(NULL, ", \t")) {
		uint32_t b = ipc_evt_for_token(tok, 0);
		if (b) mask |= b;
		else if (any_unknown) *any_unknown = 1;
	}
	return mask;
}

static int handle_subscribe(struct app *a, int fd, int64_t id,
                            const char *args, int add)
{
	char ev[256];
	if (!args || proto_args_get_str(args, "events", ev, sizeof ev) < 0)
		return reply_error(a->ipc, fd, id, "missing 'events'");
	int unknown = 0;
	uint32_t mask = parse_event_list(ev, &unknown);
	if (!mask)
		return reply_error(a->ipc, fd, id, "no known events");
	if (add) ipc_client_subscribe(a->ipc, fd, mask);
	else     ipc_client_unsubscribe(a->ipc, fd, mask);
	(void)unknown; /* unknown-but-some-known is tolerated */
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
	if (!a->inject) return -1;
	if (a->mac_rand)
		inject_set_mac_rand(a->inject, 1);
	return 0;
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
	char  buf[512];
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
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "n_handshake_pairs",
	                         a->hs ? handshake_n_pairs(a->hs) : 0)) < 0) return -1;
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
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "hopping",
	                          chanhop_is_running(a->hopper))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "current_channel",
	                         chanhop_current(a->hopper) ? chanhop_current(a->hopper)
	                                                    : a->iface.channel)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "attack_active",
	                          a->attack_fd >= 0 || (a->auto_mode && a->attack_enabled))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "pmkid_only",
	                          a->pmkid_only)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_bool(buf, sizeof buf, pos, &first, "auto",
	                          a->auto_mode)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "iface_mode",
	                         iface_mode_name(a->iface.mode))) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "uptime",
	                         (int64_t)(time(NULL) - a->started))) < 0) return -1;
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
	if (strcmp(req.cmd, "iface_channels") == 0) return handle_iface_channels(a, fd, req.id);
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
	if (strcmp(req.cmd, "delete_handshake")  == 0) return handle_delete_handshake(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "deauth")      == 0) return handle_deauth(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "assoc")       == 0) return handle_assoc(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_ttls")    == 0) return handle_set_ttls(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_mac_rand") == 0) return handle_set_mac_rand(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_pmkid_only") == 0) return handle_set_pmkid_only(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "set_attack")   == 0) return handle_set_attack(a, fd, req.id, req.args_raw);
	if (strcmp(req.cmd, "auto_start")   == 0) return handle_auto_start(a, fd, req.id);
	if (strcmp(req.cmd, "auto_stop")    == 0) return handle_auto_stop(a, fd, req.id);
	if (strcmp(req.cmd, "subscribe")    == 0) return handle_subscribe(a, fd, req.id, req.args_raw, 1);
	if (strcmp(req.cmd, "unsubscribe")  == 0) return handle_subscribe(a, fd, req.id, req.args_raw, 0);

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
	int         mac_rand;
	int         pmkid_only;
	const char *state_file;
	int         state_max_age;
	const char *log_format;
	int         auto_mode;     /* --auto: self-driving standalone capture */
};

static void usage(FILE *f, const char *argv0)
{
	fprintf(f,
	    "wificapc " WIFICAPC_VER " — native 802.11 capture daemon\n"
	    "\n"
	    "Usage: %s [options]\n"
	    "  -c, --config   PATH    Read options from a key=value config file\n"
	    "                         (CLI flags override the file)\n"
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
	    "      --attack-interval MS Attack period ms (default: %d)\n"
	    "      --mac-rand           Use a fresh random MAC for every assoc\n"
	    "                           (locally-administered, unicast)\n"
	    "      --pmkid-only         Autonomous attack sends assoc only (no\n"
	    "                           deauth): PMKID elicitation, quieter, faster\n"
	    "      --state-file PATH    Recon-table persistence file\n"
	    "                           (default: " DEFAULT_STATE_FILE "; \"\" disables)\n"
	    "      --state-max-age S    Ignore persisted state older than S seconds\n"
	    "      --log-format FMT     Log format: text (default) or json\n"
	    "      --auto               Self-driving mode: create the monitor vif,\n"
	    "                           auto-detect channels, sniff + attack, and\n"
	    "                           write handshakes with no external driver\n"
	    "                           (base iface via -i, default wlan0)\n",
	    argv0, DEFAULT_HOP_INTERVAL_MS, DEFAULT_ATTACK_INTERVAL_MS);
}

/* Trim leading/trailing ASCII whitespace in place; returns the start. */
static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t') s++;
	char *end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
	                   end[-1] == '\n' || end[-1] == '\r'))
		*--end = '\0';
	return s;
}

static int cfg_bool(const char *v)
{
	return (!strcmp(v, "1") || !strcasecmp(v, "true") ||
	        !strcasecmp(v, "yes") || !strcasecmp(v, "on"));
}

/*
 * X3: load `key = value` lines into `o` (defaults < config < CLI, since the
 * caller applies this before getopt). Blank lines and `#` comments are
 * ignored. Unknown keys warn but don't abort. String values are strdup'd
 * (freed only at process exit, which is fine for a once-loaded config).
 * Returns 0 on success, -1 if the file can't be opened.
 */
static int load_config(const char *path, struct opts *o)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		log_err("config: open %s: %s", path, strerror(errno));
		return -1;
	}
	char line[512];
	int lineno = 0;
	while (fgets(line, sizeof line, f)) {
		lineno++;
		char *s = trim(line);
		if (!*s || *s == '#') continue;
		char *eq = strchr(s, '=');
		if (!eq) {
			log_warn("config: %s:%d: no '=', ignoring", path, lineno);
			continue;
		}
		*eq = '\0';
		char *k = trim(s);
		char *v = trim(eq + 1);

		if      (!strcmp(k, "socket"))          o->sock_path = strdup(v);
		else if (!strcmp(k, "mode"))            o->sock_mode = (mode_t)strtol(v, NULL, 8);
		else if (!strcmp(k, "foreground"))      o->foreground = cfg_bool(v);
		else if (!strcmp(k, "debug"))           o->debug = cfg_bool(v);
		else if (!strcmp(k, "iface"))           o->iface = strdup(v);
		else if (!strcmp(k, "hs_dir"))          o->hs_dir = strdup(v);
		else if (!strcmp(k, "channels"))        o->n_channels = parse_channels(v, o->channels, CHANHOP_MAX_CHANNELS);
		else if (!strcmp(k, "hop_interval"))    o->hop_interval_ms = atoi(v);
		else if (!strcmp(k, "attack"))          o->attack = cfg_bool(v);
		else if (!strcmp(k, "attack_interval")) o->attack_interval_ms = atoi(v);
		else if (!strcmp(k, "mac_rand"))        o->mac_rand = cfg_bool(v);
		else if (!strcmp(k, "pmkid_only"))      o->pmkid_only = cfg_bool(v);
		else if (!strcmp(k, "state_file"))      o->state_file = strdup(v);
		else if (!strcmp(k, "state_max_age"))   o->state_max_age = atoi(v);
		else if (!strcmp(k, "log_format"))      o->log_format = strdup(v);
		else if (!strcmp(k, "auto"))            o->auto_mode = cfg_bool(v);
		else log_warn("config: %s:%d: unknown key '%s', ignoring", path, lineno, k);
	}
	fclose(f);
	return 0;
}

static int parse_opts(int argc, char **argv, struct opts *o)
{
	enum {
		OPT_HOP_INTERVAL = 256,
		OPT_ATTACK_INTERVAL,
		OPT_MAC_RAND,
		OPT_PMKID_ONLY,
		OPT_STATE_FILE,
		OPT_STATE_MAX_AGE,
		OPT_LOG_FORMAT,
		OPT_AUTO,
	};
	static const struct option longopts[] = {
		{ "config",           required_argument, NULL, 'c' },
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
		{ "mac-rand",         no_argument,       NULL, OPT_MAC_RAND },
		{ "pmkid-only",       no_argument,       NULL, OPT_PMKID_ONLY },
		{ "state-file",       required_argument, NULL, OPT_STATE_FILE },
		{ "state-max-age",    required_argument, NULL, OPT_STATE_MAX_AGE },
		{ "log-format",       required_argument, NULL, OPT_LOG_FORMAT },
		{ "auto",             no_argument,       NULL, OPT_AUTO },
		{ 0 },
	};
	int c;
	while ((c = getopt_long(argc, argv, "c:s:m:fdhVi:H:C:A", longopts, NULL)) != -1) {
		switch (c) {
		case 'c': break;  /* handled by the pre-scan in main() */
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
		case OPT_MAC_RAND:        o->mac_rand = 1; break;
		case OPT_PMKID_ONLY:      o->pmkid_only = 1; break;
		case OPT_STATE_FILE:      o->state_file = optarg; break;
		case OPT_STATE_MAX_AGE:   o->state_max_age = atoi(optarg); break;
		case OPT_LOG_FORMAT:      o->log_format = optarg; break;
		case OPT_AUTO:            o->auto_mode = 1; break;
		default:  usage(stderr, argv[0]); return -1;
		}
	}
	return 0;
}

/* Capture-health watchdog. On brcmfmac the radio can come up (or wedge) in a
 * state where channel-sets fail and AF_PACKET delivers nothing, and it does
 * not recover without a driver re-init — which is the launcher's job, not the
 * daemon's. If we are actively hopping+capturing yet see zero new frames for
 * RX_SILENCE_SEC, the radio is not receiving. Exit so systemd re-runs
 * wificapc-launcher (modprobe cycle + monitor bring-up). In any populated
 * 2.4 GHz area a healthy radio sees beacons within a second, so this length of
 * silence is a wedge, not a quiet channel. */
#define RX_SILENCE_SEC     45
#define HEALTH_CHECK_SEC    5
#define AUTO_STATUS_SEC    15   /* AU5: --auto status-line cadence */

static void on_health_timer(int fd, uint32_t events, void *user)
{
	(void)events;
	struct app *a = user;
	uint64_t exp;
	if (read(fd, &exp, sizeof exp) != (ssize_t)sizeof exp) return;

	time_t now = time(NULL);
	int hopping   = a->hopper  && chanhop_is_running(a->hopper);
	int capturing = a->capture && capture_is_running(a->capture);

	/* AU5: periodic standalone status line (--auto only; in agent mode the
	 * agent renders status). Piggybacks this timer to avoid another fd. */
	if (a->auto_mode && a->table && now - a->status_last >= AUTO_STATUS_SEC) {
		a->status_last = now;
		int ch = (a->hopper && chanhop_current(a->hopper))
		         ? chanhop_current(a->hopper) : a->iface.channel;
		log_info("auto: ch=%d aps=%d stas=%d handshakes=%d frames=%llu dropped=%llu",
		         ch, table_n_aps(a->table), table_n_stas(a->table),
		         a->hs ? handshake_n_pairs(a->hs) : 0,
		         (unsigned long long)(a->capture ? capture_frames_total(a->capture) : 0),
		         (unsigned long long)(a->capture ? capture_frames_dropped(a->capture) : 0));
	}

	/* Only meaningful while actively hopping+capturing; otherwise keep the
	 * silence window reset so it starts fresh once hopping resumes. */
	if (!hopping || !capturing) {
		a->health_frames   = a->capture ? capture_frames_total(a->capture) : 0;
		a->health_progress = now;
		return;
	}

	uint64_t cur = capture_frames_total(a->capture);
	if (cur != a->health_frames) {           /* frames advancing → healthy */
		a->health_frames   = cur;
		a->health_progress = now;
		return;
	}

	if (now - a->health_progress >= RX_SILENCE_SEC) {
		log_err("capture-health: hopping but 0 frames for %llds — radio wedged; "
		        "exiting for supervisor to re-init the interface",
		        (long long)(now - a->health_progress));
		exit(3);
	}
}

static int start_health_timer(struct app *a)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) { log_err("timerfd_create(health): %s", strerror(errno)); return -1; }
	struct itimerspec its = {
		.it_interval = { .tv_sec = HEALTH_CHECK_SEC },
		.it_value    = { .tv_sec = HEALTH_CHECK_SEC },
	};
	timerfd_settime(fd, 0, &its, NULL);
	if (ipc_add_fd(a->ipc, fd, EPOLLIN, on_health_timer, a) < 0) {
		log_err("start_health_timer: ipc_add_fd failed");
		close(fd);
		return -1;
	}
	a->health_frames   = 0;
	a->health_progress = time(NULL);
	return fd;
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
		.state_file          = DEFAULT_STATE_FILE,
		.state_max_age       = DEFAULT_STATE_MAX_AGE_SEC,
	};

	/* X3: load --config first so CLI flags (parsed next) override it,
	 * regardless of flag order. */
	for (int i = 1; i < argc; i++) {
		const char *cfg = NULL;
		if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc)
			cfg = argv[i + 1];
		else if (!strncmp(argv[i], "--config=", 9))
			cfg = argv[i] + 9;
		if (cfg) { load_config(cfg, &o); break; }
	}

	int rc = parse_opts(argc, argv, &o);
	if (rc != 0) return rc < 0 ? 1 : 0;

	/* If --iface was given but no --channels, use the default 2.4 GHz list.
	 * --auto detects channels itself, so don't pre-fill there. */
	if (o.iface && o.n_channels == 0 && !o.auto_mode) {
		for (int i = 0; i < DEFAULT_N_CHANNELS; i++)
			o.channels[i] = DEFAULT_CHANNELS[i];
		o.n_channels = DEFAULT_N_CHANNELS;
	}

	log_init(o.debug ? LL_DEBUG : LL_INFO, !o.foreground);
	if (o.log_format && strcmp(o.log_format, "json") == 0)
		log_set_format(LOG_FMT_JSON);
	log_info("wificapc %s starting", WIFICAPC_VER);
	log_info("listening on %s (mode 0%o)", o.sock_path, (unsigned)o.sock_mode);

	install_signals();

	struct app a = {0};
	a.started    = time(NULL);
	a.attack_fd  = -1;
	a.health_fd  = -1;
	a.mac_rand   = o.mac_rand;
	a.pmkid_only = o.pmkid_only;
	a.state_file = o.state_file;
	a.state_max_age = o.state_max_age;

	a.ipc = ipc_create(o.sock_path, o.sock_mode);
	if (!a.ipc) {
		log_err("failed to start ipc");
		return 1;
	}
	g_app = &a;
	ipc_set_on_line(a.ipc, on_line, &a);

	if (o.auto_mode) {
		/* AU3: self-driving. Create our own monitor vif on the base iface's
		 * wiphy (base left down), then bring up capture + hop (auto channels)
		 * + per-channel attack with no external driver. */
		const char *base = o.iface ? o.iface : "wlan0";
		char mon[16];
		if (auto_prepare_vif(&a, base, mon, sizeof mon) < 0) {
			log_err("--auto: could not bring up a monitor vif on %s.", base);
			log_err("--auto: the radio must present monitor support. On brcmfmac "
			        "(Pi) the driver needs a fresh modprobe cycle first — that is "
			        "the environment's job (the image's prep/launcher), not the "
			        "daemon's. Prep the radio (or pre-create the monitor vif) and "
			        "retry; on a normal adapter check that it supports monitor mode.");
		} else {
			struct autostart_opts ao = {
				.iface           = mon,
				.hs_dir          = o.hs_dir,
				.channels        = NULL,   /* auto-detect */
				.n_channels      = 0,
				.hop_interval_ms = o.hop_interval_ms,
				.attack          = 1,
				.auto_mode       = 1,
			};
			if (autostart(&a, &ao) < 0)
				log_err("--auto: autostart failed");
			else
				log_info("--auto: self-driving capture on %s", mon);
		}
	} else if (o.iface) {
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

	a.health_fd = start_health_timer(&a);

	int run_rc = ipc_run(a.ipc);

	log_info("shutting down");
	if (a.health_fd >= 0) { ipc_remove_fd(a.ipc, a.health_fd); close(a.health_fd); }
	if (a.attack_fd >= 0) { ipc_remove_fd(a.ipc, a.attack_fd); close(a.attack_fd); }
	if (a.inject)  inject_destroy(a.inject);
	if (a.capture) capture_destroy(a.capture);
	if (a.hopper)  chanhop_destroy(a.hopper);
	if (a.hs)      handshake_destroy(a.hs);
	if (a.table && a.state_file && *a.state_file)
		state_save(a.table, a.state_file);   /* R1: persist for the next respawn */
	if (a.table)   table_destroy(a.table);
	if (a.auto_vif[0])              /* AU2: remove the monitor vif we created */
		iface_del_vif(&a.iface, a.auto_vif);
	iface_close(&a.iface);
	ipc_destroy(a.ipc);
	g_app = NULL;
	log_close();
	return run_rc < 0 ? 1 : 0;
}
