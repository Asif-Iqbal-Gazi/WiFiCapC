/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "proc.h"
#include "ipc.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_JOBS 16

enum proc_kind {
	PROC_HCXPCAPNGTOOL = 0,
	PROC_WLANCAP2WPASEC,
};

struct job {
	int             in_use;
	pid_t           pid;
	enum proc_kind  kind;
	char            pcap_path[256];
	char            hash_path[256];
	proc_done_fn    cb;
	void           *user;
};

struct proc {
	struct ipc *ipc;
	int         signalfd;
	struct job  jobs[MAX_JOBS];
};

static struct job *job_alloc(struct proc *p)
{
	for (int i = 0; i < MAX_JOBS; i++)
		if (!p->jobs[i].in_use) return &p->jobs[i];
	return NULL;
}

static struct job *job_find(struct proc *p, pid_t pid)
{
	for (int i = 0; i < MAX_JOBS; i++)
		if (p->jobs[i].in_use && p->jobs[i].pid == pid) return &p->jobs[i];
	return NULL;
}

static void on_sigchld(int fd, uint32_t events, void *user)
{
	(void)events;
	struct proc *p = user;

	for (;;) {
		struct signalfd_siginfo si;
		ssize_t n = read(fd, &si, sizeof si);
		if (n != (ssize_t)sizeof si) return;
		/* Drain every reapable child — signalfd coalesces SIGCHLDs. */
		for (;;) {
			int   status;
			pid_t pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0) break;
			struct job *j = job_find(p, pid);
			if (!j) continue;

			int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
			const char *hash = (exit_code == 0 && j->kind == PROC_HCXPCAPNGTOOL &&
			                    j->hash_path[0]) ? j->hash_path : NULL;
			if (j->cb)
				j->cb(j->pcap_path[0] ? j->pcap_path : NULL, hash, exit_code, j->user);
			j->in_use = 0;
		}
	}
}

struct proc *proc_create(struct ipc *ipc)
{
	struct proc *p = calloc(1, sizeof *p);
	if (!p) return NULL;
	p->ipc      = ipc;
	p->signalfd = -1;

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		log_err("sigprocmask: %s", strerror(errno));
		free(p);
		return NULL;
	}

	p->signalfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (p->signalfd < 0) {
		log_err("signalfd: %s", strerror(errno));
		free(p);
		return NULL;
	}
	if (ipc_add_fd(ipc, p->signalfd, EPOLLIN, on_sigchld, p) < 0) {
		log_err("proc: ipc_add_fd failed");
		close(p->signalfd);
		free(p);
		return NULL;
	}
	return p;
}

void proc_destroy(struct proc *p)
{
	if (!p) return;
	if (p->signalfd >= 0) {
		ipc_remove_fd(p->ipc, p->signalfd);
		close(p->signalfd);
	}
	free(p);
}

static int spawn(struct proc *p, struct job *j, char *const argv[])
{
	pid_t pid = fork();
	if (pid < 0) {
		log_err("fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* child */
		signal(SIGCHLD, SIG_DFL);
		sigset_t empty;
		sigemptyset(&empty);
		sigprocmask(SIG_SETMASK, &empty, NULL);

		/* Redirect stdout/stderr to /dev/null — the converters are chatty. */
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			dup2(devnull, 0);
			dup2(devnull, 1);
			dup2(devnull, 2);
			if (devnull > 2) close(devnull);
		}
		execvp(argv[0], argv);
		_exit(127);
	}
	j->pid    = pid;
	j->in_use = 1;
	(void)p;
	return 0;
}

int proc_run_hcxpcapngtool(struct proc *p, const char *pcap_path,
                           proc_done_fn cb, void *user)
{
	if (!p || !pcap_path) return -1;
	struct job *j = job_alloc(p);
	if (!j) {
		log_warn("proc: jobs table full");
		return -1;
	}
	memset(j, 0, sizeof *j);
	j->kind = PROC_HCXPCAPNGTOOL;
	j->cb   = cb;
	j->user = user;
	snprintf(j->pcap_path, sizeof j->pcap_path, "%s", pcap_path);
	snprintf(j->hash_path, sizeof j->hash_path, "%s.22000", pcap_path);

	char *argv[] = {
		(char *)"hcxpcapngtool",
		(char *)"-o", j->hash_path,
		(char *)pcap_path,
		NULL,
	};
	return spawn(p, j, argv);
}

int proc_run_wpasec(struct proc *p, const char *pcap_path,
                    proc_done_fn cb, void *user)
{
	if (!p || !pcap_path) return -1;
	struct job *j = job_alloc(p);
	if (!j) return -1;
	memset(j, 0, sizeof *j);
	j->kind = PROC_WLANCAP2WPASEC;
	j->cb   = cb;
	j->user = user;
	snprintf(j->pcap_path, sizeof j->pcap_path, "%s", pcap_path);

	char *argv[] = {
		(char *)"wlancap2wpasec",
		(char *)pcap_path,
		NULL,
	};
	return spawn(p, j, argv);
}
