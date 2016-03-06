/*
 * Seccomp Linux Security Module - File System Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bitops.h>	/* BIT() */
#include <linux/compat.h>
#include <linux/namei.h>	/* user_lpath() */
#include <linux/path.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/syscalls.h>	/* __SACT__CONST_CHAR_PTR */
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

/* This cache prohibit TOCTOU race conditions between seccomp filter checks and
 * LSM hooks checks, i.e. the dereferenced data is kept in cache and only
 * dereferenced once for the whole syscall lifetime.
 *
 * Ignore @follow_symlink if @str_path match a cache entry (i.e. do not store
 * @follow_symlink in the cache).
 */
static const struct path *get_cache_path(const char __user *str_path,
					 bool follow_symlink, u8 arg_nr)
{
	struct path *path = NULL;
	u64 hash_len = 0;
	struct filename *name;
	struct seccomp_argeval_cache_entry **entry = NULL;
	struct seccomp_argeval_cache **arg_cache = &current->seccomp.arg_cache;
	bool new_cache = false;

	/* Find a cache entry matching @str_path */
	while (*arg_cache) {
		if ((*arg_cache)->type == SECCOMP_OBJTYPE_PATH) {
			entry = &(*arg_cache)->entry;
			while (*entry) {
				if ((*entry)->uptr == str_path) {
					/* Add this argument to the cache */
					(*entry)->args |= BIT(arg_nr);
					return (*entry)->fs.path;
				}
				entry = &(*entry)->next;
			}
			break;
		}
		arg_cache = &(*arg_cache)->next;
	}

	/* Save @str_path to avoid syscall argument TOCTOU race condition
	 * thanks to the audit_names list for the current audit context (cf.
	 * __audit_reusename).
	 * @name will be freed with audit_syscall_exit(), audit_free() or
	 * audit_seccomp_exit().
	 */
	name = getname(str_path);
	if (IS_ERR(name))
		return NULL;

	path = kmalloc(sizeof(*path), GFP_KERNEL);
	if (path) {
		int ret;

		/* @follow_symlink is only evaluated for the first cache entry */
		if (follow_symlink)
			ret = user_path(str_path, path);
		else
			ret = user_lpath(str_path, path);
		if (ret) {
			/* Store invalid path entry as well */
			kfree(path);
			path = NULL;
		} else {
			/* FIXME: How not to make this racy because of possible
			 * concurrent dentry update by other task?
			 */
			hash_len = path->dentry->d_name.hash_len;
		}
	} else {
		return NULL;
	}

	/* Append a new cache entry for @str_path */
	if (!*arg_cache) {
		*arg_cache = kmalloc(sizeof(**arg_cache), GFP_KERNEL);
		if (!*arg_cache)
			goto free_path;
		new_cache = true;
		(*arg_cache)->type = SECCOMP_OBJTYPE_PATH;
		(*arg_cache)->next = NULL;
		entry = &(*arg_cache)->entry;
	}
	*entry = kmalloc(sizeof(**entry), GFP_KERNEL);
	if (!*entry)
		goto free_cache;
	(*entry)->uptr = str_path;
	(*entry)->args = BIT(arg_nr);
	(*entry)->fs.path = path;
	(*entry)->fs.hash_len = hash_len;
	(*entry)->next = NULL;
	return (*entry)->fs.path;

free_cache:
	if (new_cache) {
		/* It is not mandatory to free the cache because it is linked */
		kfree(*arg_cache);
		*arg_cache = NULL;
	}

free_path:
	kfree(path);
	return NULL;
}

#define EQUAL_NOT_NULL(a, b) (a && a == b)

static bool check_path_literal(const struct path *p1, const struct path *p2,
			       u32 flags)
{
	bool result_dentry = !(flags & SECCOMP_OBJFLAG_FS_DENTRY);
	bool result_inode = !(flags & SECCOMP_OBJFLAG_FS_INODE);
	bool result_device = !(flags & SECCOMP_OBJFLAG_FS_DEVICE);
	bool result_mount = !(flags & SECCOMP_OBJFLAG_FS_MOUNT);

	if (unlikely(!p1 || !p2)) {
		WARN_ON(1);
		return false;
	}

	if (!result_dentry && p1->dentry == p2->dentry)
		result_dentry = true;
	/* XXX: Use d_inode_rcu() instead? */
	if (!result_inode
	    && EQUAL_NOT_NULL(d_inode(p1->dentry)->i_ino,
			      d_inode(p2->dentry)->i_ino))
		result_inode = true;
	/* Check superblock instead of device major/minor */
	if (!result_device
	    && EQUAL_NOT_NULL(d_inode(p1->dentry)->i_sb,
			      d_inode(p2->dentry)->i_sb))
		result_device = true;
	if (!result_mount && EQUAL_NOT_NULL(p1->mnt, p2->mnt))
		result_mount = true;

	return result_dentry && result_inode && result_device && result_mount;
}

static bool check_path_beneath(const struct path *p1, const struct path *p2,
			       u32 flags)
{
	struct path walker = {
		/* Mount can't be checked here */
		.mnt = NULL,
		.dentry = NULL,
	};

	if (unlikely(!p1 || !p2)) {
		WARN_ON(1);
		return false;
	}

	/* Meanigless mount and device checks are not in flags thanks to
	 * previous call to wrong_check_flags().
	 */
	if (unlikely((flags | path_flags_mask_beneath)
				!= path_flags_mask_beneath)) {
		WARN_ON(1);
		return false;
	}

	for (walker.dentry = p2->dentry; !IS_ROOT(walker.dentry);
			walker.dentry = walker.dentry->d_parent) {
		if (check_path_literal(p1, &walker, flags))
			return true;
	}
	return false;
}

/* Must be called with a locked path->dentry */
static bool argrule_match_path(const struct seccomp_filter_checker *checker,
			       const struct path *arg)
{
	const struct seccomp_filter_object_path *object_path;

	if (unlikely(!checker || !arg)) {
		WARN_ON(1);
		return false;
	}

	switch (checker->type) {
	case SECCOMP_OBJTYPE_PATH:
		object_path = &checker->object_path;
		if (unlikely(!object_path->path.dentry)) {
			WARN_ON(1);
			return false;
		}

		/* Comparing mnt+pathname is not enough because pivot_root can
		 * remove a path prefix; could be used to allow access to a
		 * subdirectory with bind mounting and pivot-rooting to
		 * simulate the initial mnt+pathname configuration.
		 *
		 * The check should allow to compare bind-mounted files and
		 * keep the user's path semantic.
		 */
		switch (checker->check) {
		case SECCOMP_CHECK_FS_LITERAL:
			return check_path_literal(&object_path->path, arg,
						  object_path->flags);
		case SECCOMP_CHECK_FS_BENEATH:
			return check_path_beneath(&object_path->path, arg,
						  object_path->flags);
		default:
			WARN_ON(1);
			return false;
		}
	default:
		WARN_ON(1);
	}
	return false;
}

/* Return matched checks. */
u8 seccomp_argrule_path(const u8(*argdesc)[6], const u64(*args)[6],
			u8 to_check,
			const struct seccomp_filter_checker *checker)
{
	int i;
	const char __user *str_path;
	const struct path *path;
	u8 ret = 0;
	bool follow_symlink;

	if (unlikely(!argdesc || !args || !checker)) {
		WARN_ON(1);
		goto out;
	}
	switch (checker->check) {
	case SECCOMP_CHECK_FS_LITERAL:
	case SECCOMP_CHECK_FS_BENEATH:
		break;
	default:
		WARN_ON(1);
		goto out;
	}

	if (wrong_check_flags(checker->check, checker->object_path.flags)) {
		WARN_ON(1);
		goto out;
	}
	follow_symlink = !(checker->object_path.flags & SECCOMP_OBJFLAG_FS_NOFOLLOW);

	/* XXX: Add a whole cache lock? */
	for (i = 0; i < 6; i++) {
		if (!(BIT(i) & to_check))
			continue;
		if ((*argdesc)[i] != __SACT__CONST_CHAR_PTR)
			continue;
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			str_path = compat_ptr((*args)[i]);
		} else	/* Falls below */
#endif
		str_path = (const char __user *)((unsigned long)(*args)[i]);
		/* Path are interpreted differently according to each syscall:
		 * some follow symlinks whereas other don't (cf.
		 * linux/namei.h:user_*path*).
		 */
		/* XXX: Do we need to check mnt/namespace? */
		path = get_cache_path(str_path, follow_symlink, i);
		if (!path)
			continue;
		spin_lock(&path->dentry->d_lock);
		if (argrule_match_path(checker, path))
			ret |= BIT(i);
		spin_unlock(&path->dentry->d_lock);
	}

out:
	return ret;
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
