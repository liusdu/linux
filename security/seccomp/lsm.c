/*
 * Seccomp Linux Security Module
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/syscall.h>	/* sys_call_table */
#include <linux/compat.h>
#include <linux/slab.h>	/* kcalloc() */
#include <linux/syscalls.h>	/* syscall_argdesc */

#include "lsm.h"

/* TODO: Remove the need for CONFIG_SYSFS dependency */

struct syscall_argdesc (*seccomp_syscalls_argdesc)[] = NULL;
#ifdef CONFIG_COMPAT
struct syscall_argdesc (*compat_seccomp_syscalls_argdesc)[] = NULL;
#endif	/* CONFIG_COMPAT */

static const struct syscall_argdesc *__init
find_syscall_argdesc(const struct syscall_argdesc *start,
		const struct syscall_argdesc *stop, const void *addr)
{
	if (unlikely(!addr || !start || !stop)) {
		WARN_ON(1);
		return NULL;
	}

	for (; start < stop; start++) {
		if (start->addr == addr)
			return start;
	}
	return NULL;
}

static inline void __init init_argdesc(void)
{
	const struct syscall_argdesc *argdesc;
	const void *addr;
	int i;

	seccomp_syscalls_argdesc = kcalloc(NR_syscalls,
			sizeof((*seccomp_syscalls_argdesc)[0]), GFP_KERNEL);
	if (unlikely(!seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < NR_syscalls; i++) {
		addr = sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_syscalls_argdesc,
				__stop_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*seccomp_syscalls_argdesc)[i] = *argdesc;
	}

#ifdef CONFIG_COMPAT
	compat_seccomp_syscalls_argdesc = kcalloc(IA32_NR_syscalls,
			sizeof((*compat_seccomp_syscalls_argdesc)[0]),
			GFP_KERNEL);
	if (unlikely(!compat_seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < IA32_NR_syscalls; i++) {
		addr = ia32_sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_compat_syscalls_argdesc,
				__stop_compat_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*compat_seccomp_syscalls_argdesc)[i] = *argdesc;
	}
#endif	/* CONFIG_COMPAT */
}

void __init seccomp_init(void)
{
	pr_info("seccomp: Becoming ready for sandboxing\n");
	init_argdesc();
}
