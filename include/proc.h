/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_PROC_H
#define WIFICAPC_PROC_H

#include <stddef.h>

struct ipc;

/*
 * Async child-process runner.
 *
 * Spawns external converters (hcxpcapngtool, wlancap2wpasec) and harvests
 * exit status via signalfd hooked into the IPC epoll loop.
 *
 * Single global instance because SIGCHLD is process-wide.
 */

struct proc;

struct proc *proc_create(struct ipc *ipc);
void         proc_destroy(struct proc *p);

/*
 * Run hcxpcapngtool against `pcap_path`, producing `<pcap_path>.22000`.
 * Callback fires with hash22000_path == NULL on failure; with a heap-allocated
 * path string on success (caller takes ownership). user is forwarded to cb.
 */
typedef void (*proc_done_fn)(const char *pcap_path,
                             const char *hash22000_path,
                             int exit_code, void *user);

int  proc_run_hcxpcapngtool(struct proc *p,
                            const char *pcap_path,
                            proc_done_fn cb, void *user);

/* Optional wpa-sec upload chain: invokes wlancap2wpasec on `pcap_path`. */
int  proc_run_wpasec(struct proc *p,
                     const char *pcap_path,
                     proc_done_fn cb, void *user);

#endif
