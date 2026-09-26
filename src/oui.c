/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "oui.h"
#include "oui_table.h"   /* generated: OUI_TABLE[], OUI_VENDORS[], *_LEN */

#include <stddef.h>      /* NULL */

const char *oui_lookup(const uint8_t mac[6])
{
	/* A locally-administered address (U/L bit, 0x02 in the first octet) is
	 * a randomized/private MAC — its high 24 bits are not a real OUI, so a
	 * table hit would be a coincidence, not a manufacturer. Group/multicast
	 * (0x01) is never a device. Reject both. */
	if (mac[0] & 0x03)
		return NULL;

	uint32_t oui = ((uint32_t)mac[0] << 16) |
	               ((uint32_t)mac[1] << 8)  |
	                (uint32_t)mac[2];

	int lo = 0, hi = OUI_TABLE_LEN - 1;
	while (lo <= hi) {
		int      mid = lo + (hi - lo) / 2;
		uint32_t key = OUI_TABLE[mid].oui;
		if (key == oui)
			return OUI_VENDORS[OUI_TABLE[mid].vidx];
		if (key < oui)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return NULL;
}
