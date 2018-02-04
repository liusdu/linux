/*
 * Landlock - UAPI headers
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI__LINUX_LANDLOCK_H__
#define _UAPI__LINUX_LANDLOCK_H__

#include <linux/types.h>

#define LANDLOCK_RET_ALLOW	0
#define LANDLOCK_RET_DENY	1

/**
 * enum landlock_hook_type - hook type for which a Landlock program is called
 *
 * TODO: doc
 */
enum landlock_hook_type {
	LANDLOCK_HOOK_FS_PICK = 1,
	LANDLOCK_HOOK_FS_WALK,
	LANDLOCK_HOOK_FS_GET,
};

/**
 * DOC: landlock_subtype_options
 *
 * TODO: doc
 */
#define LANDLOCK_OPTION_PREVIOUS			(1ULL << 0)

/**
 * DOC: landlock_perm_fs
 *
 * - %LANDLOCK_TRIGGER_FS_PICK_APPEND: append data to a file
 * TODO
 *
 * Each of the following actions are specific to syscall multiplexers. Each of
 * them trigger a dedicated Landlock event where their command can be read.
 *
 * - %LANDLOCK_TRIGGER_FS_PICK_IOCTL: ioctl command
 * - %LANDLOCK_TRIGGER_FS_PICK_LOCK: flock or fcntl lock command
 * - %LANDLOCK_TRIGGER_FS_PICK_FCNTL: fcntl command
 */
#define LANDLOCK_TRIGGER_FS_PICK_APPEND			(1ULL << 0)
#define LANDLOCK_TRIGGER_FS_PICK_CHDIR			(1ULL << 1)
#define LANDLOCK_TRIGGER_FS_PICK_CREATE			(1ULL << 2)
#define LANDLOCK_TRIGGER_FS_PICK_EXECUTE		(1ULL << 3)
#define LANDLOCK_TRIGGER_FS_PICK_FCNTL			(1ULL << 4)
#define LANDLOCK_TRIGGER_FS_PICK_GETATTR		(1ULL << 5)
#define LANDLOCK_TRIGGER_FS_PICK_IOCTL			(1ULL << 6)
#define LANDLOCK_TRIGGER_FS_PICK_LINK			(1ULL << 7)
#define LANDLOCK_TRIGGER_FS_PICK_LINKTO			(1ULL << 8)
#define LANDLOCK_TRIGGER_FS_PICK_LOCK			(1ULL << 9)
#define LANDLOCK_TRIGGER_FS_PICK_MAP			(1ULL << 10)
#define LANDLOCK_TRIGGER_FS_PICK_MOUNTON		(1ULL << 11)
#define LANDLOCK_TRIGGER_FS_PICK_OPEN			(1ULL << 12)
#define LANDLOCK_TRIGGER_FS_PICK_READ			(1ULL << 13)
#define LANDLOCK_TRIGGER_FS_PICK_READDIR		(1ULL << 14)
#define LANDLOCK_TRIGGER_FS_PICK_RECEIVE		(1ULL << 15)
#define LANDLOCK_TRIGGER_FS_PICK_RENAME			(1ULL << 16)
#define LANDLOCK_TRIGGER_FS_PICK_RENAMETO		(1ULL << 17)
#define LANDLOCK_TRIGGER_FS_PICK_RMDIR			(1ULL << 18)
#define LANDLOCK_TRIGGER_FS_PICK_SETATTR		(1ULL << 19)
#define LANDLOCK_TRIGGER_FS_PICK_TRANSFER		(1ULL << 20)
#define LANDLOCK_TRIGGER_FS_PICK_UNLINK			(1ULL << 21)
#define LANDLOCK_TRIGGER_FS_PICK_WRITE			(1ULL << 22)

/* inode_lookup */
/* LOOKUP_ROOT can only be seen for the first fs_walk call */
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_ROOT		1
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT		2
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT	3

/**
 * struct landlock_ctx_fs_pick - context accessible to a fs_pick program
 */
struct landlock_ctx_fs_pick {
	__u64 cookie;
	__u64 inode_tag;
	__u64 inode;
	__u8 inode_lookup;
};

/**
 * struct landlock_ctx_fs_walk - context accessible to a fs_walk program
 */
struct landlock_ctx_fs_walk {
	__u64 cookie;
	__u64 inode_tag;
	__u64 inode;
	__u8 inode_lookup;
};

// rule: be cache-friendly => do not repeat the same object in the same session (e.g. no inode, only cookie, for fs_get)
struct landlock_ctx_fs_get {
	__u64 cookie;
	__u64 inode_tag;
};

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
