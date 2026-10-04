/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "state.h"
#include "log.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STATE_MAGIC "WCAPST\x01\x00"   /* 8 bytes, bumped if the layout changes */

struct state_header {
	char     magic[8];
	uint32_t ap_rec_size;    /* sizeof(struct ap_record) guard */
	uint32_t sta_rec_size;   /* sizeof(struct sta_record) guard */
	int64_t  saved_at;       /* time_t at save, widened for a stable file */
	uint32_t n_aps;
	uint32_t n_stas;
};

int state_save(const struct table *t, const char *path)
{
	if (!t || !path || !*path) return -1;

	/* Snapshot under the public API (records come back in_use==1). */
	struct ap_record  *aps  = calloc(TABLE_MAX_APS,  sizeof *aps);
	struct sta_record *stas = calloc(TABLE_MAX_STAS, sizeof *stas);
	if (!aps || !stas) { free(aps); free(stas); return -1; }

	int n_aps  = table_snapshot_aps (t, aps,  TABLE_MAX_APS);
	int n_stas = table_snapshot_stas(t, stas, TABLE_MAX_STAS);

	struct state_header h;
	memset(&h, 0, sizeof h);
	memcpy(h.magic, STATE_MAGIC, sizeof h.magic);
	h.ap_rec_size  = (uint32_t)sizeof(struct ap_record);
	h.sta_rec_size = (uint32_t)sizeof(struct sta_record);
	h.saved_at     = (int64_t)time(NULL);
	h.n_aps        = (uint32_t)n_aps;
	h.n_stas       = (uint32_t)n_stas;

	/* Best-effort: create the immediate parent dir (e.g. /tmp/wificapc). */
	char dir[512];
	snprintf(dir, sizeof dir, "%s", path);
	char *slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		if (mkdir(dir, 0700) != 0 && errno != EEXIST)
			log_debug("state: mkdir %s: %s", dir, strerror(errno));
	}

	char tmp[512];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);

	int rc = -1;
	FILE *f = fopen(tmp, "wb");
	if (!f) {
		log_warn("state: open %s: %s", tmp, strerror(errno));
		goto out;
	}
	if (fwrite(&h, sizeof h, 1, f) != 1) goto wrfail;
	if (n_aps  && fwrite(aps,  sizeof *aps,  (size_t)n_aps,  f) != (size_t)n_aps)  goto wrfail;
	if (n_stas && fwrite(stas, sizeof *stas, (size_t)n_stas, f) != (size_t)n_stas) goto wrfail;
	if (fflush(f) != 0) goto wrfail;
	fclose(f);
	f = NULL;

	if (rename(tmp, path) != 0) {
		log_warn("state: rename %s -> %s: %s", tmp, path, strerror(errno));
		unlink(tmp);
		goto out;
	}
	log_info("state: saved %d APs + %d STAs to %s", n_aps, n_stas, path);
	rc = 0;
	goto out;

wrfail:
	log_warn("state: write %s: %s", tmp, strerror(errno));
	if (f) fclose(f);
	unlink(tmp);
out:
	free(aps);
	free(stas);
	return rc;
}

int state_load(struct table *t, const char *path, int max_age_sec)
{
	if (!t || !path || !*path) return -1;

	FILE *f = fopen(path, "rb");
	if (!f) {
		if (errno != ENOENT)
			log_warn("state: open %s: %s", path, strerror(errno));
		return 0;  /* no state is not an error */
	}

	struct state_header h;
	if (fread(&h, sizeof h, 1, f) != 1) {
		log_warn("state: %s too short, ignoring", path);
		fclose(f);
		return 0;
	}

	if (memcmp(h.magic, STATE_MAGIC, sizeof h.magic) != 0 ||
	    h.ap_rec_size  != sizeof(struct ap_record) ||
	    h.sta_rec_size != sizeof(struct sta_record)) {
		log_info("state: %s layout mismatch (daemon upgraded?), ignoring", path);
		fclose(f);
		return 0;
	}

	int64_t age = (int64_t)time(NULL) - h.saved_at;
	if (max_age_sec > 0 && (age < 0 || age > max_age_sec)) {
		log_info("state: %s is %lld s old (> %d), ignoring",
		         path, (long long)age, max_age_sec);
		fclose(f);
		return 0;
	}

	int restored = 0;
	struct ap_record  ap;
	for (uint32_t i = 0; i < h.n_aps; i++) {
		if (fread(&ap, sizeof ap, 1, f) != 1) goto truncated;
		table_restore_ap(t, &ap);
		restored++;
	}
	struct sta_record sta;
	for (uint32_t i = 0; i < h.n_stas; i++) {
		if (fread(&sta, sizeof sta, 1, f) != 1) goto truncated;
		table_restore_sta(t, &sta);
		restored++;
	}

	fclose(f);
	log_info("state: restored %u APs + %u STAs from %s (%lld s old)",
	         h.n_aps, h.n_stas, path, (long long)age);
	return restored;

truncated:
	log_warn("state: %s truncated after %d records, partial restore", path, restored);
	fclose(f);
	return restored;
}
