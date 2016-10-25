/*
 * Landlock LSM
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_reg_type, struct landlock_data */
#include <linux/cred.h>
#include <linux/err.h> /* MAX_ERRNO */
#include <linux/filter.h> /* struct bpf_prog, BPF_PROG_RUN() */
#include <linux/kernel.h> /* FIELD_SIZEOF() */
#include <linux/landlock.h>
#include <linux/lsm_hooks.h>

#include "common.h"

/**
 * landlock_run_prog - run Landlock program for a syscall
 *
 * @hook_idx: hook index in the rules array
 * @ctx: non-NULL eBPF context
 * @hooks: Landlock hooks pointer
 */
static u32 landlock_run_prog(u32 hook_idx, const struct landlock_data *ctx,
		struct landlock_hooks *hooks)
{
	struct landlock_node *node;
	u32 ret = 0;

	if (!hooks)
		return 0;

	for (node = hooks->nodes[hook_idx]; node; node = node->prev) {
		struct landlock_rule *rule;

		for (rule = node->rule; rule; rule = rule->prev) {
			if (WARN_ON(!rule->prog))
				continue;
			rcu_read_lock();
			ret = BPF_PROG_RUN(rule->prog, (void *)ctx);
			rcu_read_unlock();
			if (ret) {
				if (ret > MAX_ERRNO)
					ret = MAX_ERRNO;
				goto out;
			}
		}
	}

out:
	return ret;
}

static int landlock_enforce(enum landlock_hook hook, __u64 args[6])
{
	u32 ret = 0;
	u32 hook_idx = get_index(hook);

	struct landlock_data ctx = {
		.hook = hook,
		.args[0] = args[0],
		.args[1] = args[1],
		.args[2] = args[2],
		.args[3] = args[3],
		.args[4] = args[4],
		.args[5] = args[5],
	};

	/* placeholder for seccomp and cgroup managers */
	ret = landlock_run_prog(hook_idx, &ctx, NULL);

	return -ret;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id, union bpf_prog_subtype *prog_subtype)
{
	switch (func_id) {
	default:
		return NULL;
	}
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type arg_types[6],
		union bpf_prog_subtype *prog_subtype)
{
	int arg_nb, expected_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_data))
		return false;

	/* check size */
	switch (off) {
	case offsetof(struct landlock_data, hook):
		expected_size = sizeof(__u32);
		break;
	case offsetof(struct landlock_data, args[0]) ...
			offsetof(struct landlock_data, args[5]):
		expected_size = sizeof(__u64);
		break;
	default:
		return false;
	}
	if (expected_size != size)
		return false;

	/* check pointer access and set pointer type */
	switch (off) {
	case offsetof(struct landlock_data, args[0]) ...
			offsetof(struct landlock_data, args[5]):
		arg_nb = (off - offsetof(struct landlock_data, args[0]))
			/ FIELD_SIZEOF(struct landlock_data, args[0]);
		*reg_type = arg_types[arg_nb];
		if (*reg_type == NOT_INIT)
			return false;
		break;
	}

	return true;
}

static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook hook = prog_subtype->landlock_rule.hook;

	switch (hook) {
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook hook = prog_subtype->landlock_rule.hook;

	switch (hook) {
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
	if (!prog_subtype->landlock_rule.hook ||
			prog_subtype->landlock_rule.hook > _LANDLOCK_HOOK_LAST)
		return false;
	if (prog_subtype->landlock_rule.access & ~_LANDLOCK_SUBTYPE_ACCESS_MASK)
		return false;
	if (prog_subtype->landlock_rule.option & ~_LANDLOCK_SUBTYPE_OPTION_MASK)
		return false;

	return true;
}

static const struct bpf_verifier_ops bpf_landlock_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

static struct bpf_prog_type_list bpf_landlock_type __read_mostly = {
	.ops	= &bpf_landlock_ops,
	.type	= BPF_PROG_TYPE_LANDLOCK,
};

static int __init register_landlock_filter_ops(void)
{
	bpf_register_prog_type(&bpf_landlock_type);
	return 0;
}

late_initcall(register_landlock_filter_ops);
