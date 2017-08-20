/*
 * Landlock LSM - hook helpers
 *
 * Copyright © 2016-2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/bpf.h> /* enum bpf_access_type, struct landlock_context */
#include <linux/errno.h>
#include <linux/filter.h> /* BPF_PROG_RUN() */
#include <linux/rculist.h> /* list_add_tail_rcu */
#include <linux/stddef.h> /* offsetof */

#include "hooks.h" /* CTX_ARG_NB */


bool landlock_is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type ctx_types[CTX_ARG_NB],
		const union bpf_prog_subtype *prog_subtype)
{
	int max_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_context))
		return false;
	if (size <= 0 || size > sizeof(__u64))
		return false;

	/* set max size */
	switch (off) {
	case offsetof(struct landlock_context, status):
	case offsetof(struct landlock_context, event):
	case offsetof(struct landlock_context, arg1):
	case offsetof(struct landlock_context, arg2):
		max_size = sizeof(__u64);
		break;
	default:
		return false;
	}

	/* set register type */
	switch (off) {
	case offsetof(struct landlock_context, arg1):
		*reg_type = ctx_types[0];
		break;
	case offsetof(struct landlock_context, arg2):
		*reg_type = ctx_types[1];
		break;
	default:
		*reg_type = SCALAR_VALUE;
	}

	/* check memory range access */
	switch (*reg_type) {
	case NOT_INIT:
		return false;
	case SCALAR_VALUE:
		/* allow partial raw value */
		if (size > max_size)
			return false;
		break;
	default:
		/* deny partial pointer */
		if (size != max_size)
			return false;
	}

	return true;
}

int landlock_decide(enum landlock_subtype_event event,
		__u64 ctx_values[CTX_ARG_NB], const char *hook)
{
	bool deny = false;

	return deny ? -EPERM : 0;
}
