/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __RP5_MEASURE_H
#define __RP5_MEASURE_H
#include <linux/types.h>
/* canonical devicetree digest of this boot (boot/bootm.c), 32 bytes */
extern u8 rp5_dt_digest[32];
extern bool rp5_dt_digest_valid;
#endif
