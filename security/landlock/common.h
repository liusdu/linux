/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum bpf_prog_aux */
#include <linux/filter.h> /* bpf_prog */
#include <linux/refcount.h> /* refcount_t */
#include <uapi/linux/landlock.h> /* enum landlock_hook_type */

#define LANDLOCK_NAME "landlock"

/* UAPI bounds and bitmasks */

#define _LANDLOCK_HOOK_LAST LANDLOCK_HOOK_FS_GET

#define _LANDLOCK_OPTION_LAST		LANDLOCK_OPTION_PREVIOUS
#define _LANDLOCK_OPTION_MASK		((_LANDLOCK_OPTION_LAST << 1ULL) - 1)

#define _LANDLOCK_TRIGGER_FS_PICK_LAST	LANDLOCK_TRIGGER_FS_PICK_WRITE
#define _LANDLOCK_TRIGGER_FS_PICK_MASK	((_LANDLOCK_TRIGGER_FS_PICK_LAST << 1ULL) - 1)

#endif /* _SECURITY_LANDLOCK_COMMON_H */
