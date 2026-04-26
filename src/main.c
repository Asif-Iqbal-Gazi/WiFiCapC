/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ipc.h"
#include "log.h"
#include "proto.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SOCK "/tmp/wificapc.sock"
#define WIFICAPC_VER "0.1.0-dev"

static struct ipc *g_ipc;

struct opts {
	const char *sock_path;
	mode_t      sock_mode;
	int         foreground;
	int         debug;
};

static void on_signal(int signo)
{
	(void)signo;
	if (g_ipc)
		ipc_stop(g_ipc);
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

static int handle_ping(int fd, int64_t id)
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

	return ipc_send_to(g_ipc, fd, buf, pos);
}

static int handle_version(int fd, int64_t id)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "name",    "wificapc")) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_str(buf, sizeof buf, pos, &first, "version", WIFICAPC_VER)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(g_ipc, fd, buf, pos);
}

static int handle_uptime(int fd, int64_t id, time_t started)
{
	char  buf[256];
	size_t pos = 0;
	int    first = 1;
	ssize_t r;

	int64_t up = (int64_t)(time(NULL) - started);

	if ((r = proto_reply_ok_begin(buf, sizeof buf, pos, id)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_field_int(buf, sizeof buf, pos, &first, "uptime", up)) < 0) return -1;
	pos = (size_t)r;
	if ((r = proto_reply_end(buf, sizeof buf, pos)) < 0) return -1;
	pos = (size_t)r;

	return ipc_send_to(g_ipc, fd, buf, pos);
}

static int reply_error(int fd, int64_t id, const char *err)
{
	char  buf[256];
	ssize_t r = proto_reply_err(buf, sizeof buf, 0, id, err);
	if (r < 0) return -1;
	return ipc_send_to(g_ipc, fd, buf, (size_t)r);
}

static int on_line(int fd, char *line, size_t len, void *user)
{
	time_t              *started = user;
	struct proto_request req;
	const char          *err = NULL;

	if (proto_parse_request(line, len, &req, &err) < 0) {
		log_warn("client fd=%d parse error: %s", fd, err);
		return reply_error(fd, -1, err ? err : "parse error");
	}

	log_debug("client fd=%d cmd='%s' id=%lld", fd, req.cmd, (long long)req.id);

	if (strcmp(req.cmd, "ping") == 0)
		return handle_ping(fd, req.id);
	if (strcmp(req.cmd, "version") == 0)
		return handle_version(fd, req.id);
	if (strcmp(req.cmd, "uptime") == 0)
		return handle_uptime(fd, req.id, *started);

	return reply_error(fd, req.id, "unknown command");
}

static void usage(FILE *f, const char *argv0)
{
	fprintf(f,
	    "wificapc " WIFICAPC_VER " — native 802.11 capture daemon\n"
	    "\n"
	    "Usage: %s [options]\n"
	    "  -s, --socket PATH   Unix socket path (default: " DEFAULT_SOCK ")\n"
	    "  -m, --mode  OCTAL   Socket file mode (default: 0660)\n"
	    "  -f, --foreground    Stay in foreground, log to stderr\n"
	    "  -d, --debug         Enable debug logging\n"
	    "  -h, --help          Show this help\n"
	    "  -V, --version       Print version and exit\n",
	    argv0);
}

static int parse_opts(int argc, char **argv, struct opts *o)
{
	static const struct option longopts[] = {
		{ "socket",     required_argument, NULL, 's' },
		{ "mode",       required_argument, NULL, 'm' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "debug",      no_argument,       NULL, 'd' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'V' },
		{ 0 },
	};
	int c;
	while ((c = getopt_long(argc, argv, "s:m:fdhV", longopts, NULL)) != -1) {
		switch (c) {
		case 's': o->sock_path = optarg; break;
		case 'm': o->sock_mode = (mode_t)strtol(optarg, NULL, 8); break;
		case 'f': o->foreground = 1; break;
		case 'd': o->debug = 1; break;
		case 'h': usage(stdout, argv[0]); return 1;
		case 'V': printf("wificapc %s\n", WIFICAPC_VER); return 1;
		default:  usage(stderr, argv[0]); return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct opts o = {
		.sock_path  = DEFAULT_SOCK,
		.sock_mode  = 0660,
		.foreground = 1,    /* M1: foreground only */
		.debug      = 0,
	};

	int rc = parse_opts(argc, argv, &o);
	if (rc != 0) return rc < 0 ? 1 : 0;

	log_init(o.debug ? LL_DEBUG : LL_INFO, !o.foreground);
	log_info("wificapc %s starting", WIFICAPC_VER);
	log_info("listening on %s (mode 0%o)", o.sock_path, (unsigned)o.sock_mode);

	install_signals();

	g_ipc = ipc_create(o.sock_path, o.sock_mode);
	if (!g_ipc) {
		log_err("failed to start ipc");
		return 1;
	}

	time_t started = time(NULL);
	ipc_set_on_line(g_ipc, on_line, &started);

	int run_rc = ipc_run(g_ipc);

	log_info("shutting down");
	ipc_destroy(g_ipc);
	g_ipc = NULL;
	log_close();
	return run_rc < 0 ? 1 : 0;
}
