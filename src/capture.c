/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "capture.h"
#include "dot11.h"
#include "ipc.h"
#include "log.h"
#include "radiotap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define RX_BUF_SIZE     (1 << 16)   /* 64 KB — typical 802.11 frame is 200..2300 */
#define SO_RCVBUF_BYTES (4 << 20)   /* 4 MB kernel rx buffer */
#define EVICT_TICK_MS   2000        /* call table_evict_expired every 2s */

struct capture {
	struct iface     *iface;
	struct table     *table;
	struct handshake *hs;
	struct ipc       *ipc;

	int            sock_fd;
	int            evict_fd;
	int            running;

	uint8_t        rx[RX_BUF_SIZE];
	uint64_t       frames_total;
	uint64_t       frames_dropped;
};

struct capture *capture_create(struct iface *iface, struct table *table,
                               struct handshake *hs, struct ipc *ipc)
{
	struct capture *c = calloc(1, sizeof *c);
	if (!c) return NULL;
	c->iface    = iface;
	c->table    = table;
	c->hs       = hs;
	c->ipc      = ipc;
	c->sock_fd  = -1;
	c->evict_fd = -1;
	return c;
}

void capture_destroy(struct capture *c)
{
	if (!c) return;
	capture_stop(c);
	free(c);
}

/* Classify a single received frame: parse radiotap, parse 802.11, route to
 * the table. Bad/unsupported frames bump frames_dropped. */
static void process_frame(struct capture *c, size_t n)
{
	struct radiotap_info rt;
	if (radiotap_parse(c->rx, n, &rt) < 0 ||
	    rt.bad_fcs || rt.payload_len < 24) {
		c->frames_dropped++;
		return;
	}

	struct dot11_info d;
	if (dot11_parse(rt.payload, rt.payload_len, &d) < 0) {
		c->frames_dropped++;
		return;
	}

	int    channel = rt.freq_mhz ? iface_freq_to_chan(rt.freq_mhz)
	                             : c->iface->channel;
	time_t now     = time(NULL);

	switch (d.kind) {
	case DOT11_FRAME_BEACON:
		table_observe_ap   (c->table, &d, channel, rt.rssi_dbm, now);
		/* cache the raw radiotap+802.11 frame so handshake module can
		 * prepend it to the per-pair pcap when needed. */
		table_cache_beacon (c->table, d.bssid, c->rx, n);
		break;
	case DOT11_FRAME_PROBE_RESP:
		table_observe_ap(c->table, &d, channel, rt.rssi_dbm, now);
		break;
	case DOT11_FRAME_PROBE_REQ:
		/* SA is the probing STA; no associated AP. */
		table_observe_sta(c->table, &d, channel, rt.rssi_dbm, now, NULL);
		break;
	case DOT11_FRAME_DATA:
		/* SA is the STA, BSSID is its AP. */
		table_observe_sta(c->table, &d, channel, rt.rssi_dbm, now, d.bssid);
		/* Hand the data frame to the handshake collector — it filters
		 * for EAPOL-Key internally and only acts on those. */
		if (c->hs)
			handshake_observe(c->hs, c->rx, n,
			                  rt.payload, rt.payload_len,
			                  &d, channel, rt.rssi_dbm);
		break;
	default:
		/* control frames, IBSS, etc. — ignored for recon */
		break;
	}
}

static void on_socket_readable(int fd, uint32_t events, void *user)
{
	(void)events;
	struct capture *c = user;

	for (;;) {
		ssize_t n = recv(fd, c->rx, sizeof c->rx, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			if (errno == EINTR) continue;
			log_warn("capture recv: %s", strerror(errno));
			return;
		}
		if (n == 0) return;
		c->frames_total++;
		process_frame(c, (size_t)n);
	}
}

static void on_evict_tick(int fd, uint32_t events, void *user)
{
	(void)events;
	struct capture *c = user;

	uint64_t exp;
	ssize_t  n = read(fd, &exp, sizeof exp);
	(void)n;

	time_t now = time(NULL);
	table_evict_expired(c->table, now);
	if (c->hs) handshake_tick(c->hs, now);
}

int capture_start(struct capture *c)
{
	if (!c) return -1;
	if (c->running) return 0;

	if (c->iface->mode != IFACE_MODE_MONITOR) {
		log_err("capture: iface %s not in monitor mode", c->iface->name);
		return -1;
	}

	c->sock_fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
	                    htons(ETH_P_ALL));
	if (c->sock_fd < 0) {
		log_err("capture: socket(AF_PACKET): %s", strerror(errno));
		return -1;
	}

	int rcvbuf = SO_RCVBUF_BYTES;
	(void)setsockopt(c->sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
	                 &rcvbuf, sizeof rcvbuf);
	(void)setsockopt(c->sock_fd, SOL_SOCKET, SO_RCVBUF,
	                 &rcvbuf, sizeof rcvbuf);

	struct sockaddr_ll sll = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex  = c->iface->ifindex,
	};
	if (bind(c->sock_fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
		log_err("capture: bind ifindex=%d: %s",
		        c->iface->ifindex, strerror(errno));
		close(c->sock_fd); c->sock_fd = -1;
		return -1;
	}

	if (ipc_add_fd(c->ipc, c->sock_fd, EPOLLIN, on_socket_readable, c) < 0) {
		log_err("capture: ipc_add_fd(socket) failed");
		close(c->sock_fd); c->sock_fd = -1;
		return -1;
	}

	c->evict_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (c->evict_fd < 0) {
		log_err("capture: timerfd_create: %s", strerror(errno));
		ipc_remove_fd(c->ipc, c->sock_fd);
		close(c->sock_fd); c->sock_fd = -1;
		return -1;
	}
	struct itimerspec its = {
		.it_value    = { .tv_sec = EVICT_TICK_MS / 1000,
		                 .tv_nsec = (long)(EVICT_TICK_MS % 1000) * 1000000L },
		.it_interval = { .tv_sec = EVICT_TICK_MS / 1000,
		                 .tv_nsec = (long)(EVICT_TICK_MS % 1000) * 1000000L },
	};
	if (timerfd_settime(c->evict_fd, 0, &its, NULL) < 0) {
		log_err("capture: timerfd_settime: %s", strerror(errno));
		close(c->evict_fd); c->evict_fd = -1;
		ipc_remove_fd(c->ipc, c->sock_fd);
		close(c->sock_fd); c->sock_fd = -1;
		return -1;
	}
	if (ipc_add_fd(c->ipc, c->evict_fd, EPOLLIN, on_evict_tick, c) < 0) {
		log_err("capture: ipc_add_fd(timerfd) failed");
		close(c->evict_fd); c->evict_fd = -1;
		ipc_remove_fd(c->ipc, c->sock_fd);
		close(c->sock_fd); c->sock_fd = -1;
		return -1;
	}

	c->running = 1;
	c->frames_total = 0;
	c->frames_dropped = 0;
	log_info("capture started on %s (ifindex=%d)",
	         c->iface->name, c->iface->ifindex);
	return 0;
}

int capture_stop(struct capture *c)
{
	if (!c) return -1;
	if (c->sock_fd >= 0) {
		ipc_remove_fd(c->ipc, c->sock_fd);
		close(c->sock_fd);
		c->sock_fd = -1;
	}
	if (c->evict_fd >= 0) {
		ipc_remove_fd(c->ipc, c->evict_fd);
		close(c->evict_fd);
		c->evict_fd = -1;
	}
	if (c->running) {
		log_info("capture stopped (frames=%llu dropped=%llu)",
		         (unsigned long long)c->frames_total,
		         (unsigned long long)c->frames_dropped);
		c->running = 0;
	}
	return 0;
}

int      capture_is_running   (const struct capture *c) { return c && c->running; }
uint64_t capture_frames_total (const struct capture *c) { return c ? c->frames_total   : 0; }
uint64_t capture_frames_dropped(const struct capture *c){ return c ? c->frames_dropped : 0; }
