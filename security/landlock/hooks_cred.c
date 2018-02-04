/*
 * Landlock LSM - private headers
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h> /* alloc(), kfree() */

#include "common.h"

static void hook_cred_free(struct cred *cred)
{
	struct landlock_task_security *tsec = cred->security;

	if (!tsec)
		return;
	cred->security = NULL;
	landlock_free_task_security(tsec);
}

/* FIXME: make Landlock exclusive until the LSM stacking infrastructure */
static int hook_cred_prepare(struct cred *new, const struct cred *old,
		gfp_t gfp)
{
	struct landlock_task_security *tsec;

	/* TODO: only allocate if the current task is landlocked */
	tsec = landlock_new_task_security(gfp);
	if (!tsec)
		return -ENOMEM;
	new->security = tsec;
	return 0;
}

// TODO: free tsec->walk_list when the task end or when reaching a final hook (e.g. open, access, rename)

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
};

__init void landlock_add_hooks_cred(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
