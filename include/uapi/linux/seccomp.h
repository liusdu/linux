#ifndef _UAPI_LINUX_SECCOMP_H
#define _UAPI_LINUX_SECCOMP_H

#include <linux/compiler.h>
#include <linux/types.h>


/* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
#define SECCOMP_MODE_DISABLED	0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT	1 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */

/* Valid operations for seccomp syscall. */
#define SECCOMP_SET_MODE_STRICT	0
#define SECCOMP_SET_MODE_FILTER	1
#define SECCOMP_ADD_CHECKER_GROUP	2 /* add a group of checkers */

/* Valid flags for SECCOMP_SET_MODE_FILTER */
#define SECCOMP_FILTER_FLAG_TSYNC	1

/*
 * All BPF programs must return a 32-bit value.
 * The bottom 16-bits are for optional return data.
 * The upper 16-bits are ordered from least permissive values to most.
 *
 * The ordering ensures that a min_t() over composed return values always
 * selects the least permissive choice.
 */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
#define SECCOMP_RET_TRACE	0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU

/* Object checks */
#define SECCOMP_CHECK_FS_LITERAL	1
#define SECCOMP_CHECK_FS_BENEATH	2

/* Object flags */
#define SECCOMP_OBJFLAG_FS_DENTRY	(1 << 0)
#define SECCOMP_OBJFLAG_FS_INODE	(1 << 1)
#define SECCOMP_OBJFLAG_FS_DEVICE	(1 << 2)
#define SECCOMP_OBJFLAG_FS_MOUNT	(1 << 3)
/* Do the evaluation follow the argument path? (cf. fs/namei.c)
 * This flag is only used for the seccomp filter but not by the LSM check to
 * enforce access control. You need to take care of the different path
 * interpretation per syscall (e.g. rename(2) or open(2) with O_NOFOLLOW).
 */
#define SECCOMP_OBJFLAG_FS_NOFOLLOW	(1 << 4)

/* Argument types */
#define SECCOMP_OBJTYPE_PATH		1

/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

/* TODO: Add a "at" field (default to AT_FDCWD) */
struct seccomp_object_path {
	/* e.g. SECCOMP_OBJFLAG_FS_DENTRY */
	__u32 flags;
	const char *path;
};

struct seccomp_checker {
	__u32 check;
	__u32 type;
	/* Must match the checker extra size, if any */
	unsigned int len;
	/* Checkers must be pointers to allow futur additions */
	union {
		const struct seccomp_object_path *object_path;
	};
};

#define SECCOMP_MAKE_PATH_DENTRY(_p)				\
	{							\
		.flags = SECCOMP_OBJFLAG_FS_DENTRY,		\
		.path = _p,					\
	}

#define SECCOMP_MAKE_PATH_INODE(_p)				\
	{							\
		.flags = SECCOMP_OBJFLAG_FS_INODE |		\
			SECCOMP_OBJFLAG_FS_DEVICE,		\
		.path = _p,					\
	}

#define SECCOMP_MAKE_PATH_MOUNT(_p)				\
	{							\
		.flags = SECCOMP_OBJFLAG_FS_MOUNT,		\
		.path = _p,					\
	}

#define SECCOMP_MAKE_PATH_ALL(_p)				\
	{							\
		.flags = SECCOMP_OBJFLAG_FS_DENTRY |		\
			SECCOMP_OBJFLAG_FS_INODE |		\
			SECCOMP_OBJFLAG_FS_DEVICE |		\
			SECCOMP_OBJFLAG_FS_MOUNT,		\
		.path = _p,					\
	}

#define SECCOMP_MAKE_OBJ_PATH(_c, _p)				\
	{							\
		.check = SECCOMP_CHECK_##_c,			\
		.type = SECCOMP_OBJTYPE_PATH,			\
		.len = 0,					\
		.object_path = _p,				\
	}

struct seccomp_checker_group {
	__u8 version;
	__u8 id;
	unsigned int len;
	const struct seccomp_checker (*checkers)[];
};

#endif /* _UAPI_LINUX_SECCOMP_H */
