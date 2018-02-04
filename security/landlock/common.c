/*
 * Landlock LSM - common helpers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/filter.h> /* bpf_prog */
#include <linux/slab.h> /* *alloc(), kfree() */
#include <linux/types.h> /* gfp_t */

#include "common.h"
#include "hooks_fs.h" /* struct landlock_walk_list */

void landlock_free_task_security(struct landlock_task_security *tsec)
{
	if (!tsec)
		return;
	landlock_free_walk_list(tsec->walk_list);
	kfree(tsec);
}

struct landlock_task_security *landlock_new_task_security(gfp_t gfp)
{
	return kzalloc(sizeof(struct landlock_task_security), gfp);
}

void landlock_put_chain(struct landlock_chain *chain)
{
	if (!chain)
		return;
	if (refcount_dec_and_test(&chain->usage))
		kfree(chain);
}

/*
 * If a program type is able to fork, this means that there is one amongst
 * multiple programs (types) that may be called after, depending on the action
 * type. This means that if a (sub)type has a "triggers" field (e.g. fs_pick),
 * then it is forkable.
 *
 * Keep in sync with init.c:good_previous_prog().
 */
bool landlock_is_forkable(enum landlock_hook_type hook_type)
{
	switch (hook_type) {
	case LANDLOCK_HOOK_FS_WALK:
		return false;
	case LANDLOCK_HOOK_FS_PICK:
		/* can fork to fs_get or fs_ioctl... */
		return true;
	case LANDLOCK_HOOK_FS_GET:
		return false;
	}
	WARN_ON(1);
	return false;
}
