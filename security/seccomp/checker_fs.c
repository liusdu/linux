/*
 * Seccomp Linux Security Module - File System Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/compat.h>
#include <linux/namei.h>	/* user_lpath() */
#include <linux/path.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/uaccess.h>	/* copy_from_user() */

#ifdef CONFIG_COMPAT
/* struct seccomp_object_path */
struct compat_seccomp_object_path {
	__u32 flags;
	compat_uptr_t path;	/* const char * */
};
#endif

static const u32 path_flags_mask_literal =
	SECCOMP_OBJFLAG_FS_DENTRY |
	SECCOMP_OBJFLAG_FS_INODE |
	SECCOMP_OBJFLAG_FS_DEVICE |
	SECCOMP_OBJFLAG_FS_MOUNT |
	SECCOMP_OBJFLAG_FS_NOFOLLOW;

static const u32 path_flags_mask_beneath =
	SECCOMP_OBJFLAG_FS_DENTRY |
	SECCOMP_OBJFLAG_FS_INODE |
	SECCOMP_OBJFLAG_FS_NOFOLLOW;

/* Return true for any error, or false if flags are OK. */
static bool wrong_check_flags(u32 check, u32 flags)
{
	u32 path_flags_mask;

	/* Do not allow insecure check: inode without device */
	if ((flags & SECCOMP_OBJFLAG_FS_INODE) &&
	    !(flags & SECCOMP_OBJFLAG_FS_DEVICE))
		return true;

	switch (check) {
	case SECCOMP_CHECK_FS_LITERAL:
		path_flags_mask = path_flags_mask_literal;
		break;
	case SECCOMP_CHECK_FS_BENEATH:
		path_flags_mask = path_flags_mask_beneath;
		break;
	default:
		WARN_ON(1);
		return true;
	}
	/* Need at least one flag, but only in the allowed mask */
	return !(flags & path_flags_mask) ||
		((flags | path_flags_mask) != path_flags_mask);
}

static long set_argtype_path(const struct seccomp_checker *user_checker,
			     struct seccomp_filter_checker *kernel_checker)
{
	struct seccomp_object_path user_cp;

	/* @len is not used for @object_path */
	if (user_checker->len != 0)
		return -EINVAL;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_seccomp_object_path user_cp32;

		if (copy_from_user(&user_cp32, user_checker->object_path, sizeof(user_cp32)))
			return -EFAULT;
		user_cp.flags = user_cp32.flags;
		user_cp.path = compat_ptr(user_cp32.path);
	} else			/* Falls through to the if below */
#endif
	if (copy_from_user(&user_cp, user_checker->object_path, sizeof(user_cp)))
		return -EFAULT;

	if (wrong_check_flags(kernel_checker->check, user_cp.flags))
		return -EINVAL;
	kernel_checker->object_path.flags = user_cp.flags;
	/* Do not follow symlinks for objects */
	return user_lpath(user_cp.path, &kernel_checker->object_path.path);
}

long seccomp_set_argcheck_fs(const struct seccomp_checker *user_checker,
			     struct seccomp_filter_checker *kernel_checker)
{
	switch (user_checker->type) {
	case SECCOMP_OBJTYPE_PATH:
		kernel_checker->type = user_checker->type;
		return set_argtype_path(user_checker, kernel_checker);
	}
	return -EINVAL;
}
