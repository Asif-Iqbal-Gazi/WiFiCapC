/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pcap.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

struct pcap_writer {
	FILE *fp;
	char *path;
};

#pragma pack(push, 1)
struct pcap_global_header {
	uint32_t magic;          /* 0xa1b2c3d4 (microsecond precision, little-endian) */
	uint16_t version_major;  /* 2 */
	uint16_t version_minor;  /* 4 */
	int32_t  thiszone;       /* 0 */
	uint32_t sigfigs;        /* 0 */
	uint32_t snaplen;        /* max bytes per packet */
	uint32_t network;        /* DLT_* */
};

struct pcap_record_header {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
};
#pragma pack(pop)

struct pcap_writer *pcap_open(const char *path)
{
	struct pcap_writer *w = calloc(1, sizeof *w);
	if (!w) return NULL;

	w->fp = fopen(path, "wb");
	if (!w->fp) {
		log_err("pcap_open(%s): %s", path, strerror(errno));
		free(w);
		return NULL;
	}
	w->path = strdup(path);
	if (!w->path) {
		fclose(w->fp);
		free(w);
		return NULL;
	}

	struct pcap_global_header gh = {
		.magic         = 0xa1b2c3d4,
		.version_major = 2,
		.version_minor = 4,
		.thiszone      = 0,
		.sigfigs       = 0,
		.snaplen       = 65535,
		.network       = PCAP_DLT_RADIOTAP,
	};
	if (fwrite(&gh, sizeof gh, 1, w->fp) != 1) {
		log_err("pcap_open(%s): writing header: %s", path, strerror(errno));
		pcap_close(w);
		return NULL;
	}
	fflush(w->fp);
	return w;
}

void pcap_close(struct pcap_writer *w)
{
	if (!w) return;
	if (w->fp) fclose(w->fp);
	free(w->path);
	free(w);
}

int pcap_write(struct pcap_writer *w, const uint8_t *frame, size_t len)
{
	if (!w || !w->fp || !frame || len == 0) return -1;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct pcap_record_header rh = {
		.ts_sec   = (uint32_t)tv.tv_sec,
		.ts_usec  = (uint32_t)tv.tv_usec,
		.incl_len = (uint32_t)len,
		.orig_len = (uint32_t)len,
	};

	if (fwrite(&rh, sizeof rh, 1, w->fp) != 1) return -1;
	if (fwrite(frame, 1, len, w->fp) != len) return -1;
	fflush(w->fp);
	return 0;
}

const char *pcap_path(const struct pcap_writer *w)
{
	return w ? w->path : NULL;
}
