/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WIFICAPC_STATE_H
#define WIFICAPC_STATE_H

#include "table.h"

/*
 * Recon-table persistence (R1).
 *
 * The daemon can exit and be respawned by systemd (the R7 rx-silence
 * watchdog, the brcmfmac modprobe recovery, a crash). Dumping the AP/STA
 * tables on shutdown and reloading them on startup lets it come back
 * already aware of the airspace instead of blind until recon refills.
 *
 * Format is a small binary blob (magic + struct sizes + timestamp + the
 * raw records) written atomically. It is self-describing enough to reject
 * an incompatible layout after a daemon upgrade, in which case the stale
 * file is simply ignored. It is only ever read back by the same binary on
 * the same device, so raw records are fine.
 */

/* Serialize the table to `path` (atomic rename). Returns 0 on success,
 * negative on error. Infrequent (shutdown only), so SD wear is a non-issue. */
int state_save(const struct table *t, const char *path);

/*
 * Load a previously saved table from `path` into `t`.
 *   - returns the number of (ap+sta) records restored (>=0),
 *   - returns 0 if the file is missing, too old (saved more than
 *     `max_age_sec` ago), or from an incompatible layout,
 *   - returns negative only on an unexpected error.
 * Records are restored verbatim; stale ones age out on the first eviction
 * tick, so a long downtime self-heals.
 */
int state_load(struct table *t, const char *path, int max_age_sec);

#endif
