/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum bpf_prog_aux */
#include <linux/filter.h> /* bpf_prog */
#include <linux/refcount.h> /* refcount_t */
#include <uapi/linux/landlock.h> /* enum landlock_hook_type */

#define LANDLOCK_NAME "landlock"

/* UAPI bounds and bitmasks */

#define _LANDLOCK_HOOK_LAST LANDLOCK_HOOK_FS_WALK

#define _LANDLOCK_TRIGGER_FS_PICK_LAST	LANDLOCK_TRIGGER_FS_PICK_WRITE
#define _LANDLOCK_TRIGGER_FS_PICK_MASK	((_LANDLOCK_TRIGGER_FS_PICK_LAST << 1ULL) - 1)

#endif /* _SECURITY_LANDLOCK_COMMON_H */
