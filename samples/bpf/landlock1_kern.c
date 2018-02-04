/*
 * Landlock sample 1 - partial read-only filesystem
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

/*
 * This file contains a function that will be compiled to eBPF bytecode thanks
 * to LLVM/Clang.
 *
 * Each SEC() means that the following function or variable will be part of a
 * custom ELF section. This sections are then processed by the userspace part
 * (see landlock1_user.c) to extract eBPF bytecode and take into account
 * variables describing the eBPF program subtype or its license.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/landlock.h>

#include "bpf_helpers.h"
#include "landlock1.h" /* MAP_MARK_* */

SEC("maps")
struct bpf_map_def inode_map = {
	.type = BPF_MAP_TYPE_INODE,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 20,
};

SEC("subtype/landlock1")
static union bpf_prog_subtype _subtype1 = {
	.landlock_hook = {
		.type = LANDLOCK_HOOK_FS_WALK,
	}
};

/* WARNING: do not (yet) handle relative paths (need a fs_get prog) */
static __always_inline __u64 update_cookie(__u64 cookie, __u8 lookup, void *inode)
{
	__u64 map_allow = 0;

	if (cookie == 0) {
		/* only look for the first match in the map, ignore nested
		 * paths in this example */
		map_allow = bpf_inode_map_lookup(&inode_map, inode);
		if (map_allow) {
			cookie = 1 | map_allow;
		}
	} else {
		map_allow = cookie & _MAP_MARK_MASK;
		cookie &= ~_MAP_MARK_MASK;
		switch (lookup) {
		case LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT:
			cookie--;
			break;
		case LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT:
			break;
		default:
			/* ignore _MAP_MARK_MASK overflow in this example */
			cookie++;
			break;
		}
		if (cookie >= 1)
			cookie |= map_allow;
	}
	return cookie;
}

SEC("landlock1")
int fs_walk(struct landlock_ctx_fs_walk *ctx) {
	ctx->cookie = update_cookie(ctx->cookie, ctx->inode_lookup,
			(void *)ctx->inode);
	return LANDLOCK_RET_ALLOW;
}

SEC("subtype/landlock2")
static union bpf_prog_subtype _subtype2 = {
	.landlock_hook = {
		.type = LANDLOCK_HOOK_FS_PICK,
		.options = LANDLOCK_OPTION_PREVIOUS,
		.previous = 1, /* landlock1 */
		/* TODO: add more triggers */
		.triggers = LANDLOCK_TRIGGER_FS_PICK_CHDIR | \
			    LANDLOCK_TRIGGER_FS_PICK_GETATTR | \
			    LANDLOCK_TRIGGER_FS_PICK_READDIR | \
			    LANDLOCK_TRIGGER_FS_PICK_TRANSFER | \
			    LANDLOCK_TRIGGER_FS_PICK_OPEN,
	}
};

SEC("landlock2")
int fs_pick_ro(struct landlock_ctx_fs_pick *ctx) {
	__u64 cookie = ctx->cookie;

	cookie = update_cookie(cookie, ctx->inode_lookup, (void *)ctx->inode);
	if (cookie & MAP_MARK_READ)
		return LANDLOCK_RET_ALLOW;
	return LANDLOCK_RET_DENY;
}

SEC("subtype/landlock3")
static union bpf_prog_subtype _subtype3 = {
	.landlock_hook = {
		.type = LANDLOCK_HOOK_FS_PICK,
		.options = LANDLOCK_OPTION_PREVIOUS,
		.previous = 2, /* landlock2 */
		.triggers = LANDLOCK_TRIGGER_FS_PICK_APPEND | \
			    LANDLOCK_TRIGGER_FS_PICK_CREATE | \
			    LANDLOCK_TRIGGER_FS_PICK_LINK | \
			    LANDLOCK_TRIGGER_FS_PICK_LINKTO | \
			    LANDLOCK_TRIGGER_FS_PICK_LOCK | \
			    LANDLOCK_TRIGGER_FS_PICK_MOUNTON | \
			    LANDLOCK_TRIGGER_FS_PICK_RENAME | \
			    LANDLOCK_TRIGGER_FS_PICK_RENAMETO | \
			    LANDLOCK_TRIGGER_FS_PICK_RMDIR | \
			    LANDLOCK_TRIGGER_FS_PICK_SETATTR | \
			    LANDLOCK_TRIGGER_FS_PICK_UNLINK | \
			    LANDLOCK_TRIGGER_FS_PICK_WRITE,
	}
};

SEC("landlock3")
int fs_pick_rw(struct landlock_ctx_fs_pick *ctx) {
	__u64 cookie = ctx->cookie;

	cookie = update_cookie(cookie, ctx->inode_lookup, (void *)ctx->inode);
	if (cookie & MAP_MARK_WRITE)
		return LANDLOCK_RET_ALLOW;
	return LANDLOCK_RET_DENY;
}

SEC("license")
static const char _license[] = "GPL";
