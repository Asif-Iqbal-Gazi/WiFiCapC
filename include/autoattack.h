/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_AUTOATTACK_H
#define WIFICAPC_AUTOATTACK_H

#include "table.h"
#include "inject.h"
#include "ipc.h"

struct autoattack;

struct autoattack *autoattack_create(struct table *t, struct inject *inj, struct ipc *ipc);
void autoattack_destroy(struct autoattack *aa);

/* Returns the timer fd for epoll registration */
int autoattack_fd(const struct autoattack *aa);

/* Epoll callback to fire periodic attacks */
void autoattack_on_timer(void *user);

/* Start / Stop */
int autoattack_start(struct autoattack *aa, int interval_ms);
int autoattack_stop(struct autoattack *aa);

#endif
