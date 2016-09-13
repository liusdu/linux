/*
 * Landlock LSM
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/bpf.h> /* enum bpf_reg_type, struct landlock_data */
#include <linux/cred.h>
#include <linux/err.h> /* MAX_ERRNO */
#include <linux/filter.h> /* struct bpf_prog, BPF_PROG_RUN() */
#include <linux/kernel.h> /* FIELD_SIZEOF() */
#include <linux/lsm_hooks.h>
#include <linux/types.h> /* uintptr_t */

#define LANDLOCK_MAP0(m, ...)
#define LANDLOCK_MAP1(m, d, t, a) m(d, t, a)
#define LANDLOCK_MAP2(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP1(m, __VA_ARGS__)
#define LANDLOCK_MAP3(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP2(m, __VA_ARGS__)
#define LANDLOCK_MAP4(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP3(m, __VA_ARGS__)
#define LANDLOCK_MAP5(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP4(m, __VA_ARGS__)
#define LANDLOCK_MAP6(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP5(m, __VA_ARGS__)
#define LANDLOCK_MAP(n, ...) LANDLOCK_MAP##n(__VA_ARGS__)

#define LANDLOCK_ARG_D(d, t, a) d
#define LANDLOCK_ARG_TA(d, t, a) t a
#define LANDLOCK_ARG_A(d, t, a) ((u64)(uintptr_t)a)

#define LANDLOCK_HOOKx(X, NAME, CNAME, ...)				\
	static inline int landlock_hook_##NAME(				\
		LANDLOCK_MAP(X, LANDLOCK_ARG_TA, __VA_ARGS__))		\
	{								\
		__u64 args[6] = {					\
			LANDLOCK_MAP(X, LANDLOCK_ARG_A, __VA_ARGS__)	\
		};							\
		return landlock_run_prog(LANDLOCK_HOOK_##CNAME, args);	\
	}								\
	static inline bool __is_valid_access_hook_##CNAME(		\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type,			\
			union bpf_prog_subtype *prog_subtype)		\
	{								\
		enum bpf_reg_type arg_types[6] = {			\
			LANDLOCK_MAP(X, LANDLOCK_ARG_D, __VA_ARGS__)	\
		};							\
		return __is_valid_access(off, size, type, reg_type,	\
				arg_types, prog_subtype);		\
	}								\

#define LANDLOCK_HOOK1(NAME, ...) LANDLOCK_HOOKx(1, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK2(NAME, ...) LANDLOCK_HOOKx(2, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK3(NAME, ...) LANDLOCK_HOOKx(3, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK4(NAME, ...) LANDLOCK_HOOKx(4, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK5(NAME, ...) LANDLOCK_HOOKx(5, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK6(NAME, ...) LANDLOCK_HOOKx(6, NAME, __VA_ARGS__)

#define LANDLOCK_HOOK_INIT(NAME) LSM_HOOK_INIT(NAME, landlock_hook_##NAME)


static int landlock_run_prog(enum landlock_hook_id hook_id, __u64 args[6])
{
	return 0;
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
	case offsetof(struct landlock_data, origin):
	case offsetof(struct landlock_data, cookie):
		expected_size = sizeof(__u16);
		break;
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

LANDLOCK_HOOK2(file_open, FILE_OPEN,
	PTR_TO_STRUCT_FILE, struct file *, file,
	NOT_INIT, const struct cred *, cred
)

LANDLOCK_HOOK2(file_permission, FILE_PERMISSION,
	PTR_TO_STRUCT_FILE, struct file *, file,
	UNKNOWN_VALUE, int, mask
)

LANDLOCK_HOOK4(mmap_file, MMAP_FILE,
	PTR_TO_STRUCT_FILE, struct file *, file,
	UNKNOWN_VALUE, unsigned long, reqprot,
	UNKNOWN_VALUE, unsigned long, prot,
	UNKNOWN_VALUE, unsigned long, flags
)

static struct security_hook_list landlock_hooks[] = {
	LANDLOCK_HOOK_INIT(file_open),
	LANDLOCK_HOOK_INIT(file_permission),
	LANDLOCK_HOOK_INIT(mmap_file),
};

void __init landlock_add_hooks(void)
{
	pr_info("landlock: Becoming ready for sandboxing\n");
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
}

#define LANDLOCK_CASE_ACCESS_HOOK(CNAME)			\
	case LANDLOCK_HOOK_##CNAME:				\
		return __is_valid_access_hook_##CNAME(		\
				off, size, type, reg_type, prog_subtype);

static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook_id hook_id = prog_subtype->landlock_hook.id;

	switch (hook_id) {
	LANDLOCK_CASE_ACCESS_HOOK(FILE_OPEN)
	LANDLOCK_CASE_ACCESS_HOOK(FILE_PERMISSION)
	LANDLOCK_CASE_ACCESS_HOOK(MMAP_FILE)
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook_id hook_id = prog_subtype->landlock_hook.id;

	switch (hook_id) {
	case LANDLOCK_HOOK_FILE_OPEN:
	case LANDLOCK_HOOK_FILE_PERMISSION:
	case LANDLOCK_HOOK_MMAP_FILE:
		break;
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
	if (!prog_subtype->landlock_hook.id ||
			prog_subtype->landlock_hook.id > _LANDLOCK_HOOK_LAST)
		return false;
	if (!prog_subtype->landlock_hook.origin ||
			(prog_subtype->landlock_hook.origin &
			 ~_LANDLOCK_FLAG_ORIGIN_MASK))
		return false;
#ifndef CONFIG_SECCOMP_FILTER
	if (prog_subtype->landlock_hook.origin & LANDLOCK_FLAG_ORIGIN_SECCOMP)
		return false;
#endif /* !CONFIG_SECCOMP_FILTER */
	if (prog_subtype->landlock_hook.access & ~_LANDLOCK_FLAG_ACCESS_MASK)
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
