/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "oui.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do {                     \
	if (cond) printf("ok   %s\n", msg);           \
	else { printf("FAIL %s\n", msg); fails++; }   \
} while (0)

int main(void)
{
	const uint8_t cisco[6] = {0x00, 0x00, 0x0c, 0x11, 0x22, 0x33};
	const uint8_t rpi[6]   = {0xb8, 0x27, 0xeb, 0xaa, 0xbb, 0xcc};
	const uint8_t la[6]    = {0x02, 0x00, 0x00, 0x01, 0x02, 0x03}; /* U/L bit */
	const uint8_t mcast[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
	const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	const char *v;
	v = oui_lookup(cisco);
	CHECK(v && strcmp(v, "Cisco Systems") == 0, "00:00:0c -> Cisco Systems");
	v = oui_lookup(rpi);
	CHECK(v && strstr(v, "Raspberry Pi") != NULL, "b8:27:eb -> Raspberry Pi");
	CHECK(oui_lookup(la)    == NULL, "locally-administered MAC -> NULL");
	CHECK(oui_lookup(mcast) == NULL, "multicast MAC -> NULL");
	CHECK(oui_lookup(bcast) == NULL, "broadcast MAC -> NULL");

	printf("%s\n", fails ? "OUI TESTS FAILED" : "all good");
	return fails ? 1 : 0;
}
