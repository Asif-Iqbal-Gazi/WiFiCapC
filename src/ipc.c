/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ipc.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_CLIENTS    16
#define MAX_EXTRA_FDS  8
#define IN_BUF_CAP     8192
#define OUT_BUF_CAP    65536
#define EPOLL_BACKLOG  32

struct client {
	int      fd;
	char     in[IN_BUF_CAP];
	size_t   in_len;
	char    *out;          /* malloc'd ring */
	size_t   out_cap;
	size_t   out_head;     /* read offset */
	size_t   out_tail;     /* write offset */
	int      want_write;
};

struct extra_fd {
	int           fd;
	ipc_on_fd_fn  cb;
	void         *user;
};

struct ipc {
	int                     listen_fd;
	int                     epoll_fd;
	volatile sig_atomic_t   stop;        /* set from signal handler */
	struct client           clients[MAX_CLIENTS];
	struct extra_fd         extras[MAX_EXTRA_FDS];
	ipc_on_line_fn          on_line;
	void                   *on_line_user;
	char                    sock_path[108];
};

static struct extra_fd *extra_find(struct ipc *s, int fd)
{
	for (size_t i = 0; i < MAX_EXTRA_FDS; i++) {
		if (s->extras[i].fd == fd)
			return &s->extras[i];
	}
	return NULL;
}

static struct extra_fd *extra_alloc(struct ipc *s)
{
	for (size_t i = 0; i < MAX_EXTRA_FDS; i++) {
		if (s->extras[i].fd < 0)
			return &s->extras[i];
	}
	return NULL;
}

static struct client *client_alloc(struct ipc *s)
{
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (s->clients[i].fd < 0)
			return &s->clients[i];
	}
	return NULL;
}

static struct client *client_find(struct ipc *s, int fd)
{
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (s->clients[i].fd == fd)
			return &s->clients[i];
	}
	return NULL;
}

static void client_close(struct ipc *s, struct client *c)
{
	if (c->fd < 0) return;
	log_debug("client fd=%d closed", c->fd);
	epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
	close(c->fd);
	c->fd         = -1;
	c->in_len     = 0;
	c->out_head   = 0;
	c->out_tail   = 0;
	c->want_write = 0;
	free(c->out);
	c->out     = NULL;
	c->out_cap = 0;
}

static int client_outbox_push(struct ipc *s, struct client *c,
                              const char *data, size_t n)
{
	if (c->out_cap == 0) {
		c->out_cap = OUT_BUF_CAP;
		c->out = malloc(c->out_cap);
		if (!c->out) {
			log_err("oom in outbox alloc");
			return -1;
		}
	}

	size_t used = c->out_tail - c->out_head;
	if (used + n > c->out_cap) {
		log_warn("client fd=%d outbox overflow, dropping %zu bytes", c->fd, n);
		return -1;
	}

	if (c->out_tail + n > c->out_cap) {
		/* compact */
		memmove(c->out, c->out + c->out_head, used);
		c->out_head = 0;
		c->out_tail = used;
	}

	memcpy(c->out + c->out_tail, data, n);
	c->out_tail += n;

	if (!c->want_write) {
		struct epoll_event ev = {
			.events   = EPOLLIN | EPOLLOUT | EPOLLRDHUP,
			.data.fd  = c->fd,
		};
		if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
			log_err("epoll_ctl mod (write): %s", strerror(errno));
			return -1;
		}
		c->want_write = 1;
	}
	return 0;
}

static void client_drain_outbox(struct ipc *s, struct client *c)
{
	while (c->out_head < c->out_tail) {
		ssize_t n = write(c->fd, c->out + c->out_head,
		                  c->out_tail - c->out_head);
		if (n > 0) {
			c->out_head += (size_t)n;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		} else {
			client_close(s, c);
			return;
		}
	}
	if (c->out_head == c->out_tail) {
		c->out_head = c->out_tail = 0;
		struct epoll_event ev = {
			.events  = EPOLLIN | EPOLLRDHUP,
			.data.fd = c->fd,
		};
		epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
		c->want_write = 0;
	}
}

static void client_consume_lines(struct ipc *s, struct client *c)
{
	for (;;) {
		char *nl = memchr(c->in, '\n', c->in_len);
		if (!nl) break;
		size_t line_len = (size_t)(nl - c->in);
		*nl = '\0';

		if (s->on_line)
			s->on_line(c->fd, c->in, line_len, s->on_line_user);

		size_t consumed = line_len + 1;
		size_t leftover = c->in_len - consumed;
		memmove(c->in, c->in + consumed, leftover);
		c->in_len = leftover;
	}
}

static void on_listen_readable(struct ipc *s)
{
	for (;;) {
		struct sockaddr_un addr;
		socklen_t          alen = sizeof addr;
		int fd = accept4(s->listen_fd, (struct sockaddr *)&addr, &alen,
		                 SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			log_err("accept4: %s", strerror(errno));
			return;
		}
		struct client *c = client_alloc(s);
		if (!c) {
			log_warn("max clients reached, rejecting fd=%d", fd);
			close(fd);
			continue;
		}
		c->fd     = fd;
		c->in_len = 0;
		struct epoll_event ev = {
			.events  = EPOLLIN | EPOLLRDHUP,
			.data.fd = fd,
		};
		if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
			log_err("epoll_ctl add: %s", strerror(errno));
			close(fd);
			c->fd = -1;
			continue;
		}
		log_debug("client fd=%d accepted", fd);
	}
}

static void on_client_event(struct ipc *s, int fd, uint32_t events)
{
	struct client *c = client_find(s, fd);
	if (!c) return;

	if (events & EPOLLIN) {
		for (;;) {
			if (c->in_len >= sizeof c->in) {
				log_warn("client fd=%d line too long, closing", fd);
				client_close(s, c);
				return;
			}
			ssize_t n = read(fd, c->in + c->in_len,
			                 sizeof c->in - c->in_len);
			if (n > 0) {
				c->in_len += (size_t)n;
			} else if (n == 0) {
				client_consume_lines(s, c);
				client_close(s, c);
				return;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			} else {
				client_close(s, c);
				return;
			}
		}
		client_consume_lines(s, c);
	}

	if (events & EPOLLOUT)
		client_drain_outbox(s, c);

	/* If the peer half-closed or the kernel reported an error, drop the fd
	 * now. Without this, EPOLLERR/EPOLLHUP without an accompanying EPOLLIN
	 * would re-fire forever (level-triggered) and slowly exhaust the fd
	 * table on a long-running daemon. */
	if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
		client_close(s, c);
	}
}

struct ipc *ipc_create(const char *sock_path, mode_t mode)
{
	struct ipc *s = calloc(1, sizeof *s);
	if (!s) return NULL;

	s->listen_fd = -1;
	s->epoll_fd  = -1;
	for (size_t i = 0; i < MAX_CLIENTS; i++)
		s->clients[i].fd = -1;
	for (size_t i = 0; i < MAX_EXTRA_FDS; i++)
		s->extras[i].fd = -1;

	if (strlen(sock_path) >= sizeof s->sock_path) {
		log_err("socket path too long");
		goto fail;
	}
	strcpy(s->sock_path, sock_path);

	s->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (s->listen_fd < 0) {
		log_err("socket: %s", strerror(errno));
		goto fail;
	}

	(void)unlink(sock_path);

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, sock_path, sizeof addr.sun_path - 1);

	if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		log_err("bind %s: %s", sock_path, strerror(errno));
		goto fail;
	}
	if (chmod(sock_path, mode) < 0)
		log_warn("chmod %s: %s", sock_path, strerror(errno));

	if (listen(s->listen_fd, EPOLL_BACKLOG) < 0) {
		log_err("listen: %s", strerror(errno));
		goto fail;
	}

	s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (s->epoll_fd < 0) {
		log_err("epoll_create1: %s", strerror(errno));
		goto fail;
	}

	struct epoll_event ev = {
		.events  = EPOLLIN,
		.data.fd = s->listen_fd,
	};
	if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->listen_fd, &ev) < 0) {
		log_err("epoll_ctl add listen: %s", strerror(errno));
		goto fail;
	}
	return s;

fail:
	ipc_destroy(s);
	return NULL;
}

void ipc_destroy(struct ipc *s)
{
	if (!s) return;
	for (size_t i = 0; i < MAX_CLIENTS; i++)
		if (s->clients[i].fd >= 0)
			client_close(s, &s->clients[i]);
	if (s->epoll_fd  >= 0) close(s->epoll_fd);
	if (s->listen_fd >= 0) close(s->listen_fd);
	if (s->sock_path[0])   unlink(s->sock_path);
	free(s);
}

void ipc_set_on_line(struct ipc *s, ipc_on_line_fn cb, void *user)
{
	s->on_line      = cb;
	s->on_line_user = user;
}

void ipc_stop(struct ipc *s)
{
	s->stop = 1;
}

int ipc_run(struct ipc *s)
{
	while (!s->stop) {
		struct epoll_event evs[EPOLL_BACKLOG];
		int n = epoll_wait(s->epoll_fd, evs, EPOLL_BACKLOG, 1000);
		if (n < 0) {
			if (errno == EINTR) continue;
			log_err("epoll_wait: %s", strerror(errno));
			return -1;
		}
		for (int i = 0; i < n; i++) {
			int fd = evs[i].data.fd;
			if (fd == s->listen_fd) {
				on_listen_readable(s);
				continue;
			}
			struct extra_fd *e = extra_find(s, fd);
			if (e) {
				e->cb(fd, evs[i].events, e->user);
				continue;
			}
			on_client_event(s, fd, evs[i].events);
		}
	}
	return 0;
}

int ipc_send_to(struct ipc *s, int client_fd, const char *line, size_t len)
{
	struct client *c = client_find(s, client_fd);
	if (!c) return -1;
	int rc = client_outbox_push(s, c, line, len);
	if (rc == 0)
		client_drain_outbox(s, c);
	return rc;
}

int ipc_broadcast(struct ipc *s, const char *line, size_t len)
{
	int sent = 0;
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (s->clients[i].fd < 0) continue;
		if (client_outbox_push(s, &s->clients[i], line, len) == 0) {
			client_drain_outbox(s, &s->clients[i]);
			sent++;
		}
	}
	return sent;
}

int ipc_add_fd(struct ipc *s, int fd, uint32_t events,
               ipc_on_fd_fn cb, void *user)
{
	if (fd < 0 || !cb) return -1;
	if (extra_find(s, fd)) {
		log_warn("ipc_add_fd: fd=%d already registered", fd);
		return -1;
	}
	struct extra_fd *e = extra_alloc(s);
	if (!e) {
		log_err("ipc_add_fd: extras table full");
		return -1;
	}
	struct epoll_event ev = { .events = events, .data.fd = fd };
	if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		log_err("epoll_ctl add fd=%d: %s", fd, strerror(errno));
		return -1;
	}
	e->fd   = fd;
	e->cb   = cb;
	e->user = user;
	return 0;
}

int ipc_remove_fd(struct ipc *s, int fd)
{
	struct extra_fd *e = extra_find(s, fd);
	if (!e) return -1;
	epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	e->fd   = -1;
	e->cb   = NULL;
	e->user = NULL;
	return 0;
}
