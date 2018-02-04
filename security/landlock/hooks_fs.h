/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */

#include "common.h" /* struct landlock_chain */

/* needed for struct landlock_task_security */
struct landlock_walk_list;

void landlock_free_walk_list(struct landlock_walk_list *);

__init void landlock_add_hooks_fs(void);

/* fs_pick */

struct landlock_hook_ctx_fs_pick;

bool landlock_is_valid_access_fs_pick(int, enum bpf_access_type,
		enum bpf_reg_type *, int *);

struct landlock_ctx_fs_pick *landlock_update_ctx_fs_pick(
		struct landlock_hook_ctx_fs_pick *,
		const struct landlock_chain *);

int landlock_save_ctx_fs_pick(struct landlock_hook_ctx_fs_pick *,
		struct landlock_chain *);

/* fs_walk */

struct landlock_hook_ctx_fs_walk;

bool landlock_is_valid_access_fs_walk(int, enum bpf_access_type,
		enum bpf_reg_type *, int *);

struct landlock_ctx_fs_walk *landlock_update_ctx_fs_walk(
		struct landlock_hook_ctx_fs_walk *,
		const struct landlock_chain *);

int landlock_save_ctx_fs_walk(struct landlock_hook_ctx_fs_walk *,
		struct landlock_chain *);

/* fs_get */

struct landlock_hook_ctx_fs_get;

bool landlock_is_valid_access_fs_get(int, enum bpf_access_type,
		enum bpf_reg_type *, int *);

struct landlock_ctx_fs_get *landlock_update_ctx_fs_get(
		struct landlock_hook_ctx_fs_get *,
		const struct landlock_chain *);

int landlock_save_ctx_fs_get(struct landlock_hook_ctx_fs_get *,
		struct landlock_chain *);
