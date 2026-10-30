/* Copyright (c) 2026 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

/* This file is force-included (after kconfig.h) by the unit test Makefile.
 * The unit tests compile Homa and the mocks as ordinary userspace code, so
 * kernel configuration options that depend on kernel-only code generation
 * must be disabled; otherwise the kernel headers of some distributions fail
 * to compile in this environment.
 */

#ifndef _KCONFIG_OVERRIDES_H
#define _KCONFIG_OVERRIDES_H

/* Per-CPU variables are declared with the __seg_gs address space, which
 * conflicts with the ordinary variables defined in mock.c.
 */
#undef CONFIG_USE_X86_SEG_SUPPORT
#undef CONFIG_CC_HAS_NAMED_AS

/* Indirect branch tracking uses the nocf_check attribute, which is rejected
 * (with -Werror) unless the compiler is run with -fcf-protection.
 */
#undef CONFIG_X86_KERNEL_IBT

/* mock.c defines __list_add_valid and __list_del_entry_valid when
 * CONFIG_DEBUG_LIST is set, which conflicts with the inline versions that
 * the headers always provide in this kernel version.
 */
#undef CONFIG_DEBUG_LIST

/* mock.c defines preempt_count_add and preempt_count_sub as out-of-line
 * functions, which the headers declare only when preemption debugging is on.
 */
#ifndef CONFIG_DEBUG_PREEMPT
#define CONFIG_DEBUG_PREEMPT 1
#endif

#endif /* _KCONFIG_OVERRIDES_H */
