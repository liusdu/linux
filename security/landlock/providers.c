/*
 * Landlock LSM - seccomp provider
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/barrier.h> /* smp_store_release() */
#include <asm/page.h> /* PAGE_SIZE */
#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/compiler.h> /* READ_ONCE() */
#include <linux/err.h> /* ERR_PTR() */
#include <linux/errno.h>
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/kernel.h> /* round_up() */
#include <linux/landlock.h>
#include <linux/refcount.h> /* refcount_t() */
#include <linux/sched.h> /* current_cred(), task_no_new_privs() */
#include <linux/security.h> /* security_capable_noaudit() */
#include <linux/slab.h> /* alloc(), kfree() */
#include <linux/uaccess.h> /* get_user() */

#include "common.h" /* struct landlock_prog_list */

static void put_landlock_prog_list(struct landlock_prog_list *prog_list)
{
	struct landlock_prog_list *orig = prog_list;

	/* clean up single-reference branches iteratively */
	while (orig && refcount_dec_and_test(&orig->usage)) {
		struct landlock_prog_list *freeme = orig;

		if (orig->prog)
			bpf_prog_put(orig->prog);
		landlock_put_chain(orig->chain);
		orig = orig->prev;
		kfree(freeme);
	}
}

static void put_landlock_prog_set(struct landlock_prog_set *prog_set)
{
	if (prog_set && refcount_dec_and_test(&prog_set->usage)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(prog_set->programs); i++)
			put_landlock_prog_list(prog_set->programs[i]);
		kfree(prog_set);
	}
}

static struct landlock_prog_set *new_landlock_prog_set(void)
{
	struct landlock_prog_set *ret;

	/* array filled with NULL values */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	refcount_set(&ret->usage, 1);
	return ret;
}

/**
 * store_landlock_prog - prepend and deduplicate a Landlock prog_list
 *
 * Prepend @prog to @dst_prog_set while ignoring @prog and its chained programs
 * if they are already in @ref_prog_set.  Whatever is the result of this
 * function call, you can call bpf_prog_put(@prog) after.
 *
 * @dst_prog_set: prog_set to prepend to
 * @ref_prog_set: prog_set to check for duplicate programs
 * @prog: program chain to prepend
 *
 * Return -errno on error, 0 if @prog was successfully stored, or 1 if
 * @dst_prog_set wasn't updated (because of duplicate @prog).
 */
static int store_landlock_prog(struct landlock_prog_set *dst_prog_set,
		const struct landlock_prog_set *ref_prog_set, struct bpf_prog *prog)
{
	struct landlock_prog_list *tmp_list = NULL;
	int err;
	u32 hook_idx;
	bool new_is_last_of_type;
	bool first = true;
	struct landlock_chain *chain = NULL;
	enum landlock_hook_type last_type;
	struct bpf_prog *new = prog;

	/* allocate all the memory we need */
	for (; new; new = new->aux->extra->landlock_hook.previous) {
		bool ignore = false;
		struct landlock_prog_list *new_list;

		new_is_last_of_type = first || (last_type != get_type(new));
		last_type = get_type(new);
		first = false;
		/* ignore duplicate programs */
		if (ref_prog_set) {
			struct landlock_prog_list *ref;

			if (WARN_ON(!new->aux->extra))
				continue;
			hook_idx = get_index(get_type(new));
			for (ref = ref_prog_set->programs[hook_idx];
					ref && !ignore;
					ref = ref->prev)
				ignore = (ref->prog == new);
			/* remaining programs are already in ref_prog_set */
			if (ignore) {
				bool is_forkable = landlock_is_forkable(get_type(new));

				/*
				 * The subtype verifier has already checked the
				 * coherency of the program types chained in
				 * @new (cf. good_previous_prog).
				 *
				 * Here we only allow linking to a chain if the
				 * common program's type is able to fork (e.g.
				 * fs_pick).  This program must also be the
				 * last one of its type in both the @ref and
				 * the @new chains.
				 */
				if (!is_forkable || !new_is_last_of_type ||
						!ref->is_last_of_type) {
					err = -EINVAL;
					goto put_tmp_list;
				}
				/* use the same session (i.e. cookie state) */
				chain = ref->chain;
				/* will increment the usage counter later */
				break;
			}
		}

		new = bpf_prog_inc(new);
		if (IS_ERR(new)) {
			err = PTR_ERR(new);
			goto put_tmp_list;
		}
		new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
		if (!new_list) {
			bpf_prog_put(new);
			err = -ENOMEM;
			goto put_tmp_list;
		}
		/* ignore Landlock types in this tmp_list */
		new_list->is_last_of_type = new_is_last_of_type;
		new_list->prog = new;
		new_list->prev = tmp_list;
		refcount_set(&new_list->usage, 1);
		tmp_list = new_list;
	}

	if (!tmp_list)
		/* inform user space that this program was already added */
		return -EEXIST;

	if (!chain) {
		u8 chain_index;

		if (ref_prog_set) {
			/* this is a new independent chain */
			chain_index = ref_prog_set->chain_last + 1;
			/* check for integer overflow */
			if (chain_index < ref_prog_set->chain_last) {
				err = -E2BIG;
				goto put_tmp_list;
			}
		} else {
			chain_index = 0;
		}
		chain = kzalloc(sizeof(*chain), GFP_KERNEL);
		if (!chain) {
			err = -ENOMEM;
			goto put_tmp_list;
		}
		chain->index = chain_index;
	}

	/* properly store the list (without error cases) */
	while (tmp_list) {
		struct landlock_prog_list *new_list;

		new_list = tmp_list;
		tmp_list = tmp_list->prev;
		/* do not increment the previous prog list usage */
		hook_idx = get_index(get_type(new_list->prog));
		new_list->prev = dst_prog_set->programs[hook_idx];
		new_list->chain = chain;
		refcount_inc(&chain->usage);
		/* no need to add from the last program to the first because
		 * each of them are a different Landlock type */
		smp_store_release(&dst_prog_set->programs[hook_idx], new_list);
	}
	dst_prog_set->chain_last = chain->index;
	return 0;

put_tmp_list:
	put_landlock_prog_list(tmp_list);
	return err;
}

/* limit Landlock program set to 256KB */
#define LANDLOCK_EVENTS_MAX_PAGES (1 << 6)

/**
 * landlock_prepend_prog - attach a Landlock prog_list to @current_prog_set
 *
 * Whatever is the result of this function call, you can call
 * bpf_prog_put(@prog) after.
 *
 * @current_prog_set: landlock_prog_set pointer, must be locked (if needed) to
 *                  prevent a concurrent put/free. This pointer must not be
 *                  freed after the call.
 * @prog: non-NULL Landlock prog_list to prepend to @current_prog_set. @prog will be
 *        owned by landlock_prepend_prog() and freed if an error happened.
 *
 * Return @current_prog_set or a new pointer when OK. Return a pointer error
 * otherwise.
 */
static struct landlock_prog_set *landlock_prepend_prog(
		struct landlock_prog_set *current_prog_set,
		struct bpf_prog *prog)
{
	struct landlock_prog_set *new_prog_set = current_prog_set;
	unsigned long pages;
	int err;
	size_t i;
	struct landlock_prog_set tmp_prog_set = {};

	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);

	/* validate memory size allocation */
	pages = prog->pages;
	if (current_prog_set) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(current_prog_set->programs); i++) {
			struct landlock_prog_list *walker_p;

			for (walker_p = current_prog_set->programs[i];
					walker_p; walker_p = walker_p->prev)
				pages += walker_p->prog->pages;
		}
		/* count a struct landlock_prog_set if we need to allocate one */
		if (refcount_read(&current_prog_set->usage) != 1)
			pages += round_up(sizeof(*current_prog_set), PAGE_SIZE)
				/ PAGE_SIZE;
	}
	if (pages > LANDLOCK_EVENTS_MAX_PAGES)
		return ERR_PTR(-E2BIG);

	/* ensure early that we can allocate enough memory for the new
	 * prog_lists */
	err = store_landlock_prog(&tmp_prog_set, current_prog_set, prog);
	if (err)
		return ERR_PTR(err);

	/*
	 * Each task_struct points to an array of prog list pointers.  These
	 * tables are duplicated when additions are made (which means each
	 * table needs to be refcounted for the processes using it). When a new
	 * table is created, all the refcounters on the prog_list are bumped (to
	 * track each table that references the prog). When a new prog is
	 * added, it's just prepended to the list for the new table to point
	 * at.
	 *
	 * Manage all the possible errors before this step to not uselessly
	 * duplicate current_prog_set and avoid a rollback.
	 */
	if (!new_prog_set) {
		/*
		 * If there is no Landlock program set used by the current task,
		 * then create a new one.
		 */
		new_prog_set = new_landlock_prog_set();
		if (IS_ERR(new_prog_set))
			goto put_tmp_lists;
	} else if (refcount_read(&current_prog_set->usage) > 1) {
		/*
		 * If the current task is not the sole user of its Landlock
		 * program set, then duplicate them.
		 */
		new_prog_set = new_landlock_prog_set();
		if (IS_ERR(new_prog_set))
			goto put_tmp_lists;
		for (i = 0; i < ARRAY_SIZE(new_prog_set->programs); i++) {
			new_prog_set->programs[i] =
				READ_ONCE(current_prog_set->programs[i]);
			if (new_prog_set->programs[i])
				refcount_inc(&new_prog_set->programs[i]->usage);
		}

		/*
		 * Landlock program set from the current task will not be freed here
		 * because the usage is strictly greater than 1. It is only
		 * prevented to be freed by another task thanks to the caller
		 * of landlock_prepend_prog() which should be locked if needed.
		 */
		put_landlock_prog_set(current_prog_set);
	}

	/* prepend tmp_prog_set to new_prog_set */
	for (i = 0; i < ARRAY_SIZE(tmp_prog_set.programs); i++) {
		/* get the last new list */
		struct landlock_prog_list *last_list =
			tmp_prog_set.programs[i];

		if (last_list) {
			while (last_list->prev)
				last_list = last_list->prev;
			/* no need to increment usage (pointer replacement) */
			last_list->prev = new_prog_set->programs[i];
			new_prog_set->programs[i] = tmp_prog_set.programs[i];
		}
	}
	new_prog_set->chain_last = tmp_prog_set.chain_last;
	return new_prog_set;

put_tmp_lists:
	for (i = 0; i < ARRAY_SIZE(tmp_prog_set.programs); i++)
		put_landlock_prog_list(tmp_prog_set.programs[i]);
	return new_prog_set;
}

#ifdef CONFIG_SECCOMP_FILTER

/**
 * landlock_seccomp_prepend_prog - attach a Landlock program to the current
 *                                 process
 *
 * current->seccomp.landlock_state->prog_set is lazily allocated. When a process fork,
 * only a pointer is copied. When a new event is added by a process, if there
 * is other references to this process' prog_set, then a new allocation
 * is made to contain an array pointing to Landlock program lists. This design
 * enable low-performance impact and is memory efficient while keeping the
 * property of prepend-only programs.
 *
 * For now, installing a Landlock prog requires that the requesting task has
 * the global CAP_SYS_ADMIN. We cannot force the use of no_new_privs to not
 * exclude containers where a process may legitimately acquire more privileges
 * thanks to an SUID binary.
 *
 * @flags: not used for now, but could be used for TSYNC
 * @user_bpf_fd: file descriptor pointing to a loaded Landlock prog
 */
int landlock_seccomp_prepend_prog(unsigned int flags,
		const char __user *user_bpf_fd)
{
	struct landlock_prog_set *new_prog_set;
	struct bpf_prog *prog;
	int bpf_fd, err;

	/* planned to be replaced with a no_new_privs check to allow
	 * unprivileged tasks */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* enable to check if Landlock is supported with early EFAULT */
	if (!user_bpf_fd)
		return -EFAULT;
	if (flags)
		return -EINVAL;
	err = get_user(bpf_fd, user_bpf_fd);
	if (err)
		return err;

	/* allocate current->security here to not have to handle this in
	 * hook_nameidata_free_security() */
	if (!current->security) {
		current->security = landlock_new_task_security(GFP_KERNEL);
		if (!current->security)
			return -ENOMEM;
	}
	prog = bpf_prog_get(bpf_fd);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto free_task;
	}

	/*
	 * We don't need to lock anything for the current process hierarchy,
	 * everything is guarded by the atomic counters.
	 */
	new_prog_set = landlock_prepend_prog(
			current->seccomp.landlock_prog_set, prog);
	bpf_prog_put(prog);
	/* @prog is managed/freed by landlock_prepend_prog() */
	if (IS_ERR(new_prog_set)) {
		err = PTR_ERR(new_prog_set);
		goto free_task;
	}
	current->seccomp.landlock_prog_set = new_prog_set;
	return 0;

free_task:
	landlock_free_task_security(current->security);
	current->security = NULL;
	return err;
}

void put_seccomp_landlock(struct task_struct *tsk)
{
	put_landlock_prog_set(tsk->seccomp.landlock_prog_set);
}

void get_seccomp_landlock(struct task_struct *tsk)
{
	if (tsk->seccomp.landlock_prog_set)
		refcount_inc(&tsk->seccomp.landlock_prog_set->usage);
}

#endif /* CONFIG_SECCOMP_FILTER */
