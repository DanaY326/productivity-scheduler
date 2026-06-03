/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions shared between focus.bpf.c and the userspace loader.
 */
#ifndef __FOCUS_H
#define __FOCUS_H

#define MAX_CPUS		512	/* power of two, bounds topology arrays */
#define MAX_CG_DEPTH		8	/* cgroup ancestors checked for marks */
#define MAX_CHAIN_DEPTH		3	/* wake-chain hops from a focus task */

/* Scheduling classes, highest priority first. */
enum fs_class {
	FS_FOCUS,
	FS_BOOST,
	FS_NORMAL,
	FS_DISTRACT,
	FS_NR_CLASSES,
	FS_IDLE = 0xff,
};

/* Values stored in the tgid_marks / cgroup_marks maps. */
enum fs_mark {
	MARK_NONE	= 0,
	MARK_FOCUS	= 1,
	MARK_DISTRACT	= 2,
};

/* DSQ ids, one shared vtime DSQ per class. */
#define DSQ_BASE	0x100
#define CLASS_DSQ(c)	(DSQ_BASE + (c))

enum fs_stat {
	ST_DISP_FOCUS,		/* dispatches per class (FS_* order) */
	ST_DISP_BOOST,
	ST_DISP_NORMAL,
	ST_DISP_DISTRACT,
	ST_RT_FOCUS,		/* runtime ns per class (FS_* order) */
	ST_RT_BOOST,
	ST_RT_NORMAL,
	ST_RT_DISTRACT,
	ST_DIRECT_IDLE,		/* direct dispatch to an idle CPU */
	ST_PREEMPT_KICK,	/* wakeup preemption IPIs */
	ST_TICK_PREEMPT,	/* slice zeroed from ops.tick */
	ST_SMT_KICK,		/* distract evicted from a focus sibling */
	ST_BOOST_DOWN,		/* wakee boosted by focus chain */
	ST_BOOST_UP,		/* waker boosted by focus chain */
	ST_HOG_DEMOTE,		/* focus/boost hog demoted to NORMAL */
	ST_AUDIO_RESCUE,	/* interactive distract task run as NORMAL */
	ST_CAP_THROTTLE,	/* distract skipped/stopped due to cap */
	ST_STARVE_RESCUE,	/* starvation guard fired */
	ST_PLACE_PERF,		/* focus/boost placed on a perf CPU */
	ST_PLACE_EFF,		/* distract placed on an eff CPU */
	FS_NR_STATS,
};

#endif /* __FOCUS_H */
