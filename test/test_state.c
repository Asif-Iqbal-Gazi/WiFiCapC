/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "state.h"
#include "table.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg) do {                     \
	if (cond) printf("ok   %s\n", msg);           \
	else { printf("FAIL %s\n", msg); fails++; }   \
} while (0)

static void no_emit(enum table_event e, const struct ap_record *a,
                    const struct sta_record *s, void *u)
{ (void)e; (void)a; (void)s; (void)u; }

int main(void)
{
	const char *path = "/tmp/wificapc-test-state.bin";
	unlink(path);

	struct table *t = table_create(120, 300, no_emit, NULL);

	struct ap_record ap;
	memset(&ap, 0, sizeof ap);
	ap.in_use = 1;
	const uint8_t bssid[6] = {0xaa,0xbb,0xcc,0x11,0x22,0x33};
	memcpy(ap.bssid, bssid, 6);
	snprintf(ap.ssid, sizeof ap.ssid, "TestNet");
	ap.ssid_len = 7;
	ap.channel = 6; ap.rssi = -42; ap.frames = 99;
	ap.captured = 1; ap.attack_count = 3;
	table_restore_ap(t, &ap);

	struct sta_record sta;
	memset(&sta, 0, sizeof sta);
	sta.in_use = 1;
	const uint8_t mac[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
	memcpy(sta.mac, mac, 6);
	memcpy(sta.ap_bssid, bssid, 6);
	sta.have_ap = 1; sta.channel = 6; sta.rssi = -55; sta.frames = 7;
	table_restore_sta(t, &sta);

	CHECK(table_n_aps(t) == 1 && table_n_stas(t) == 1, "seeded 1 AP + 1 STA");

	CHECK(state_save(t, path) == 0, "state_save succeeds");

	/* Fresh table, reload. */
	struct table *t2 = table_create(120, 300, no_emit, NULL);
	int n = state_load(t2, path, 3600);
	CHECK(n == 2, "state_load restored 2 records");
	CHECK(table_n_aps(t2) == 1 && table_n_stas(t2) == 1, "counts match after load");

	const struct ap_record *got = table_find_ap(t2, bssid);
	CHECK(got != NULL, "restored AP found by bssid");
	CHECK(got && strcmp(got->ssid, "TestNet") == 0, "ssid preserved");
	CHECK(got && got->channel == 6 && got->rssi == -42, "channel/rssi preserved");
	CHECK(got && got->frames == 99 && got->captured == 1 && got->attack_count == 3,
	      "frames/captured/attack_count preserved");

	/* max_age <= 0 disables the age gate (still loads). */
	struct table *t3 = table_create(120, 300, no_emit, NULL);
	CHECK(state_load(t3, path, 0) == 2, "max_age 0 disables age gate");

	/* Missing file is not an error. */
	struct table *t4 = table_create(120, 300, no_emit, NULL);
	CHECK(state_load(t4, "/tmp/wificapc-nope.bin", 3600) == 0, "missing file -> 0");

	unlink(path);
	table_destroy(t); table_destroy(t2); table_destroy(t3); table_destroy(t4);
	printf("%s\n", fails ? "STATE TESTS FAILED" : "all good");
	return fails ? 1 : 0;
}
