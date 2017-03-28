/*
 * Landlock LSM - public kernel headers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H
#ifdef CONFIG_SECURITY_LANDLOCK

/*
 * This is not intended for the UAPI headers. Each userland software should use
 * a static minimal version for the required features as explained in the
 * documentation.
 */
#define LANDLOCK_VERSION 1

#endif /* CONFIG_SECURITY_LANDLOCK */
#endif /* _LINUX_LANDLOCK_H */
