/* SPDX-License-Identifier: GPL-2.0 */
/*
 * focus-sched: a focus-aware sched_ext scheduler.
 *
 * Tasks are sorted into four classes, highest priority first:
 *
 *   FOCUS     tgid/cgroup marked "focus" by userspace (active window, focus
 *             tab group), unless it behaves like a CPU hog.
 *   BOOST     tasks on the focus wake chain: woken by, or waking, a FOCUS or
 *             BOOST task. Decays after boost_ns and is depth-limited.
 *   NORMAL    everything else, plus demoted hogs and rescued audio threads.
 *   DISTRACT  tgid/cgroup marked "distract".
 *
 * Each class has its own vtime-ordered DSQ; dispatch drains them in priority
 * order, with starvation guards for NORMAL and DISTRACT. On top of that:
 *
 *  - wakeup preemption: a queued FOCUS/BOOST task kicks a CPU running lower
 *    class work, and ops.tick() backs this up by zeroing slices;
 *  - placement: FOCUS/BOOST prefer idle performance cores sharing an LLC with
 *    prev_cpu, DISTRACT is packed onto efficiency CPUs;
 *  - SMT isolation: DISTRACT never shares a physical core with FOCUS/BOOST;
 *  - a global duty-cycle cap on DISTRACT runtime refilled by a bpf_timer.
 *
 * See PLAN.md for the design rationale.
 */
#include <scx/common.bpf.h>
#include <bpf_experimental.h>
#include "focus.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define MSEC			1000000ULL
#define CAP_PERIOD_NS		(100 * MSEC)
#define NORMAL_STARVE_NS	(50 * MSEC)
#define DISTRACT_STARVE_NS	(250 * MSEC)
#define MARK_TTL_NS		(250 * MSEC)
#define PREEMPT_MIN_RUN_NS	(1 * MSEC)	/* NORMAL victims must have run this long */
#define PREEMPT_COOLDOWN_NS	(500 * 1000ULL)	/* don't re-kick the same CPU sooner */
#define INTERACTIVE_RUN_NS	(1 * MSEC)
#define INTERACTIVE_GAP_NS	(100 * MSEC)
#define RESCUE_RUN_NS		(500 * 1000ULL)
#define RESCUE_GAP_NS		(20 * MSEC)
#define NO_CHAIN		0xff

/*
 * Topology, filled in by the loader before load. A CPU is "efficiency" if it
 * is an E-core / LITTLE core or part of the user-supplied --eff-cpus set.
 */
const volatile u32 nr_cpus = 1;
const volatile u32 nr_online_cpus = 1;
const volatile bool have_eff;
const volatile u8 cpu_eff[MAX_CPUS];
const volatile s32 cpu_sibling[MAX_CPUS];
const volatile u32 cpu_llc[MAX_CPUS];

const volatile u64 focus_slice_ns = 3 * MSEC;
const volatile u64 interactive_slice_ns = 2 * MSEC;
const volatile u64 normal_slice_ns = 5 * MSEC;
const volatile u64 distract_slice_ns = 20 * MSEC;

/*
 * Runtime tunables, written by the loader through the mmap'd .data section.
 * Bumping cfg_gen makes every task re-resolve its mark on next enqueue.
 */
volatile u64 cfg_gen = 1;
volatile u32 cap_pct = 30;
volatile u64 boost_ns = 30 * MSEC;
volatile u64 hog_ns = 2500 * 1000ULL;
volatile bool smt_isolation = true;
volatile bool audio_rescue = true;
volatile bool energy_mode;

/* Global scheduler state. */
static u64 vtime_now;
static u64 last_disp_at[FS_NR_CLASSES];
u64 distract_used_ns;
u64 distract_budget_ns;

/* Userspace-managed marks; tgid marks take precedence over cgroup marks. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, u8);
} tgid_marks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} cgroup_marks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, FS_NR_STATS);
} stats SEC(".maps");

private(FOCUS) struct bpf_cpumask __kptr *perf_mask;
private(FOCUS) struct bpf_cpumask __kptr *eff_mask;

struct cpu_ctx {
	u64 started_at;
	u64 kicked_at;
	u8 cls;					/* class running here, FS_IDLE if none */
	struct bpf_cpumask __kptr *llc_perf;	/* perf CPUs sharing this CPU's LLC */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

struct task_ctx {
	u64 gen;		/* cfg_gen when mark was resolved */
	u64 mark_at;
	u64 boost_until;
	u64 last_run_at;
	u64 charged_at;		/* distract cap accounting checkpoint */
	u64 last_woke_at;
	u64 avg_runtime;	/* EWMA of runtime per run */
	u64 avg_wake_gap;	/* EWMA of time between wakeups */
	u8 mark;
	u8 depth;		/* wake-chain hops from a FOCUS task */
	u8 cls;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct cap_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cap_timer);
} cap_timer SEC(".maps");

static void stat_add(u32 idx, u64 val)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		*cnt += val;
}

static struct cpu_ctx *lookup_cpu_ctx(s32 cpu)
{
	u32 idx = 0;

	if (cpu < 0)
		return bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

static struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static bool is_eff(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return false;
	return cpu_eff[cpu];
}

static s32 sibling_of(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return -1;
	return cpu_sibling[cpu];
}

static u8 cpu_class(s32 cpu)
{
	struct cpu_ctx *cctx;

	if (cpu < 0)
		return FS_IDLE;
	cctx = lookup_cpu_ctx(cpu);
	return cctx ? cctx->cls : FS_IDLE;
}

static u64 ewma(u64 avg, u64 sample)
{
	return avg ? (avg * 3 + sample) / 4 : sample;
}

static bool distract_capped(void)
{
	return cap_pct < 100 && distract_used_ns >= distract_budget_ns;
}

/*
 * Resolve the userspace mark for @p: its tgid first, then its cgroup and up
 * to MAX_CG_DEPTH ancestors so marking an app scope covers child cgroups.
 */
static u8 lookup_mark(const struct task_struct *p)
{
	struct cgroup *cgrp;
	u32 tgid = p->tgid;
	int level, i;
	u8 *m;

	m = bpf_map_lookup_elem(&tgid_marks, &tgid);
	if (m)
		return *m;

	cgrp = BPF_CORE_READ(p, cgroups, dfl_cgrp);
	if (!cgrp)
		return MARK_NONE;
	level = BPF_CORE_READ(cgrp, level);

	bpf_for(i, 0, MAX_CG_DEPTH) {
		struct cgroup *anc = NULL;
		u64 id;

		/* the root cgroup (level 0) is never marked */
		if (level - i < 1)
			break;
		if (bpf_core_read(&anc, sizeof(anc), &cgrp->ancestors[level - i]) || !anc)
			break;
		id = BPF_CORE_READ(anc, kn, id);
		m = bpf_map_lookup_elem(&cgroup_marks, &id);
		if (m)
			return *m;
	}
	return MARK_NONE;
}

static void refresh_mark(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	u64 gen = cfg_gen;

	if (tctx->gen == gen && now - tctx->mark_at < MARK_TTL_NS)
		return;
	tctx->mark = lookup_mark(p);
	tctx->gen = gen;
	tctx->mark_at = now;
}

/* Hops from a FOCUS task on the wake chain, NO_CHAIN if not on it. */
static u8 chain_depth(struct task_ctx *tctx, u64 now)
{
	if (tctx->mark == MARK_FOCUS)
		return 0;
	if (tctx->mark != MARK_DISTRACT && time_before(now, tctx->boost_until))
		return tctx->depth;
	return NO_CHAIN;
}

static bool prefers_perf(struct task_ctx *tctx, u64 now)
{
	return chain_depth(tctx, now) != NO_CHAIN;
}

static bool is_interactive(struct task_ctx *tctx)
{
	return tctx->avg_wake_gap && tctx->avg_runtime < INTERACTIVE_RUN_NS &&
	       tctx->avg_wake_gap < INTERACTIVE_GAP_NS;
}

static u8 classify(const struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	refresh_mark(p, tctx, now);

	if (tctx->mark == MARK_DISTRACT) {
		/* short, frequent runs: likely an audio/IO thread, don't glitch it */
		if (audio_rescue && tctx->avg_wake_gap &&
		    tctx->avg_runtime < RESCUE_RUN_NS &&
		    tctx->avg_wake_gap < RESCUE_GAP_NS) {
			stat_add(ST_AUDIO_RESCUE, 1);
			return FS_NORMAL;
		}
		return FS_DISTRACT;
	}

	if (prefers_perf(tctx, now)) {
		if (tctx->avg_runtime >= hog_ns) {
			stat_add(ST_HOG_DEMOTE, 1);
			return FS_NORMAL;
		}
		return tctx->mark == MARK_FOCUS ? FS_FOCUS : FS_BOOST;
	}

	return FS_NORMAL;
}

static u64 task_slice(u8 cls, struct task_ctx *tctx)
{
	switch (cls) {
	case FS_FOCUS:
	case FS_BOOST:
		return focus_slice_ns;
	case FS_DISTRACT:
		return distract_slice_ns;
	default:
		return is_interactive(tctx) ? interactive_slice_ns : normal_slice_ns;
	}
}

static u64 task_vtime(const struct task_struct *p, struct task_ctx *tctx, u8 cls)
{
	u64 lag = task_slice(cls, tctx);
	u64 vtime = p->scx.dsq_vtime;

	/* interactive tasks may bank an extra slice of credit while sleeping */
	if (is_interactive(tctx))
		lag *= 2;
	if (time_before(vtime, vtime_now - lag))
		vtime = vtime_now - lag;
	return vtime;
}

/*
 * Pick an idle CPU for @p according to its class, or return a negative value
 * to queue it on its class DSQ instead.
 */
static s32 pick_cpu(struct task_struct *p, struct task_ctx *tctx, u8 cls,
		    s32 prev_cpu, u64 wake_flags, u64 now)
{
	const struct cpumask *perf = cast_mask(perf_mask);
	const struct cpumask *eff = cast_mask(eff_mask);
	u64 core_flag = smt_isolation ? SCX_PICK_IDLE_CORE : 0;
	struct cpu_ctx *cctx;
	s32 cpu;

	/* scx_bpf_select_cpu_and() needs v6.16; fall back to the default policy */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		bool is_idle = false;

		if (cls == FS_DISTRACT && distract_capped())
			return -EBUSY;
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return is_idle ? cpu : -EBUSY;
	}

	if (cls == FS_DISTRACT) {
		if (distract_capped())
			return -EBUSY;
		if (have_eff && eff) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, eff, core_flag);
			if (cpu >= 0) {
				stat_add(ST_PLACE_EFF, 1);
				return cpu;
			}
			/* pack: wait for an efficiency CPU rather than waking a perf one */
			if (energy_mode)
				return -EBUSY;
		}
		/* only whole idle cores, so we never land next to focus work */
		return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, core_flag);
	}

	if (prefers_perf(tctx, now)) {
		cctx = lookup_cpu_ctx(prev_cpu);
		if (cctx) {
			const struct cpumask *llc = cast_mask(cctx->llc_perf);

			if (llc) {
				cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, llc,
							     SCX_PICK_IDLE_CORE);
				if (cpu >= 0)
					goto perf_found;
			}
		}
		if (perf) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, perf,
						     SCX_PICK_IDLE_CORE);
			if (cpu >= 0)
				goto perf_found;
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, perf, 0);
			if (cpu >= 0)
				goto perf_found;
		}
	}

	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);

perf_found:
	stat_add(ST_PLACE_PERF, 1);
	return cpu;
}

/* Wake an idle CPU that could run @p's class from the shared DSQ. */
static bool kick_idle_cpu(struct task_struct *p, u8 cls, struct task_ctx *tctx, u64 now)
{
	const struct cpumask *perf = cast_mask(perf_mask);
	const struct cpumask *eff = cast_mask(eff_mask);
	s32 cpu = -1;

	if (cls == FS_DISTRACT && have_eff && eff) {
		cpu = scx_bpf_pick_idle_cpu(eff, 0);
		if (cpu < 0 && energy_mode)
			return false;
	} else if (prefers_perf(tctx, now) && perf) {
		cpu = scx_bpf_pick_idle_cpu(perf, 0);
	}
	if (cpu < 0)
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu < 0)
		return false;

	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	return true;
}

/*
 * No idle CPU for a FOCUS/BOOST task: preempt a CPU running lower-class work.
 * DISTRACT victims are preferred over NORMAL ones, perf CPUs over eff ones,
 * and NORMAL is only preempted for FOCUS once it has run PREEMPT_MIN_RUN_NS.
 */
static void preempt_victim(struct task_struct *p, u8 cls, u64 now)
{
	struct cpu_ctx *cctx;
	u8 best_cls = cls;
	s32 cpu, best = -1;

	bpf_for(cpu, 0, nr_cpus) {
		u8 c;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		cctx = lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;
		c = cctx->cls;
		if (c == FS_IDLE || c <= cls)
			continue;
		if (now - cctx->kicked_at < PREEMPT_COOLDOWN_NS)
			continue;
		if (c == FS_NORMAL &&
		    (cls != FS_FOCUS || now - cctx->started_at < PREEMPT_MIN_RUN_NS))
			continue;
		if (best < 0 || c > best_cls || (c == best_cls && is_eff(best) && !is_eff(cpu))) {
			best = cpu;
			best_cls = c;
			if (c == FS_DISTRACT && !is_eff(cpu))
				break;
		}
	}

	if (best < 0)
		return;
	cctx = lookup_cpu_ctx(best);
	if (cctx)
		cctx->kicked_at = now;
	scx_bpf_kick_cpu(best, SCX_KICK_PREEMPT);
	stat_add(ST_PREEMPT_KICK, 1);
}

s32 BPF_STRUCT_OPS(focus_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	u64 now = scx_bpf_now();
	s32 cpu;
	u8 cls;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	cls = classify(p, tctx, now);
	tctx->cls = cls;

	cpu = pick_cpu(p, tctx, cls, prev_cpu, wake_flags, now);
	if (cpu < 0)
		return prev_cpu;

	stat_add(ST_DIRECT_IDLE, 1);
	stat_add(ST_DISP_FOCUS + cls, 1);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(cls, tctx), 0);
	return cpu;
}

void BPF_STRUCT_OPS(focus_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now = scx_bpf_now();
	u64 dsq;
	u8 cls;

	tctx = lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_dsq_insert(p, CLASS_DSQ(FS_NORMAL), normal_slice_ns, enq_flags);
		return;
	}

	cls = classify(p, tctx, now);
	tctx->cls = cls;

	/* per-CPU tasks can only run in one place, queue them there directly */
	if (p->nr_cpus_allowed == 1) {
		s32 cpu = scx_bpf_task_cpu(p);

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(cls, tctx), enq_flags);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	dsq = CLASS_DSQ(cls);
	if (cls < FS_NR_CLASSES && !scx_bpf_dsq_nr_queued(dsq))
		last_disp_at[cls] = now;
	scx_bpf_dsq_insert_vtime(p, dsq, task_slice(cls, tctx),
				 task_vtime(p, tctx, cls), enq_flags);

	/* over budget: the cap timer wakes CPUs when the budget is refilled */
	if (cls == FS_DISTRACT && distract_capped())
		return;

	if (!kick_idle_cpu(p, cls, tctx, now) && cls <= FS_BOOST)
		preempt_victim(p, cls, now);
}

static bool starving(u8 cls, u64 now, u64 thresh)
{
	if (cls >= FS_NR_CLASSES)
		return false;
	return scx_bpf_dsq_nr_queued(CLASS_DSQ(cls)) &&
	       now - last_disp_at[cls] > thresh;
}

static bool consume(u8 cls, u64 now)
{
	if (cls >= FS_NR_CLASSES)
		return false;
	if (!scx_bpf_dsq_move_to_local(CLASS_DSQ(cls), 0))
		return false;
	last_disp_at[cls] = now;
	stat_add(ST_DISP_FOCUS + cls, 1);
	return true;
}

static bool distract_allowed_on(s32 cpu)
{
	if (distract_capped())
		return false;
	if (energy_mode && have_eff && !is_eff(cpu))
		return false;
	if (smt_isolation && cpu_class(sibling_of(cpu)) <= FS_BOOST)
		return false;
	return true;
}

void BPF_STRUCT_OPS(focus_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = scx_bpf_now();

	/* starving distract overrides placement and SMT isolation, not the cap */
	if (!distract_capped() && starving(FS_DISTRACT, now, DISTRACT_STARVE_NS) &&
	    consume(FS_DISTRACT, now)) {
		stat_add(ST_STARVE_RESCUE, 1);
		return;
	}
	if ((starving(FS_BOOST, now, NORMAL_STARVE_NS) && consume(FS_BOOST, now)) ||
	    (starving(FS_NORMAL, now, NORMAL_STARVE_NS) && consume(FS_NORMAL, now))) {
		stat_add(ST_STARVE_RESCUE, 1);
		return;
	}

	if (consume(FS_FOCUS, now) || consume(FS_BOOST, now) || consume(FS_NORMAL, now))
		return;

	if (distract_allowed_on(cpu)) {
		consume(FS_DISTRACT, now);
	} else if (distract_capped() &&
		   scx_bpf_dsq_nr_queued(CLASS_DSQ(FS_DISTRACT))) {
		stat_add(ST_CAP_THROTTLE, 1);
	}
}

/*
 * Wake-chain tracking. The waker is the current task for regular wakeups;
 * skip interrupt context where current is unrelated.
 */
void BPF_STRUCT_OPS(focus_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx, *wctx;
	struct task_struct *waker;
	u64 now = scx_bpf_now();
	u8 pd, wd;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->last_woke_at)
		tctx->avg_wake_gap = ewma(tctx->avg_wake_gap, now - tctx->last_woke_at);
	tctx->last_woke_at = now;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;
	if (bpf_in_hardirq() || bpf_in_serving_softirq() || bpf_in_nmi())
		return;

	waker = bpf_get_current_task_btf();
	if (!waker->pid || waker == p || (waker->flags & PF_KTHREAD))
		return;
	wctx = lookup_task_ctx(waker);
	if (!wctx)
		return;

	refresh_mark(p, tctx, now);
	refresh_mark(waker, wctx, now);
	pd = chain_depth(tctx, now);
	wd = chain_depth(wctx, now);

	/* downstream: focus chain woke @p */
	if (wd < MAX_CHAIN_DEPTH && tctx->mark != MARK_DISTRACT && pd > wd) {
		if (pd == NO_CHAIN)
			stat_add(ST_BOOST_DOWN, 1);
		tctx->boost_until = now + boost_ns;
		tctx->depth = wd + 1;
		return;
	}

	/* upstream: @waker feeds the focus chain (compositor, audio, IPC peer) */
	if (pd < MAX_CHAIN_DEPTH && wctx->mark != MARK_DISTRACT && wd > pd) {
		if (wd == NO_CHAIN)
			stat_add(ST_BOOST_UP, 1);
		wctx->boost_until = now + boost_ns;
		wctx->depth = pd + 1;
	}
}

void BPF_STRUCT_OPS(focus_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u64 now = scx_bpf_now();
	s32 cpu = bpf_get_smp_processor_id();
	s32 sib;

	tctx = lookup_task_ctx(p);
	cctx = lookup_cpu_ctx(-1);
	if (!tctx || !cctx)
		return;

	tctx->last_run_at = now;
	tctx->charged_at = now;
	cctx->cls = tctx->cls;
	cctx->started_at = now;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/* SMT isolation: evict distract work from our sibling hyperthread */
	if (smt_isolation && tctx->cls <= FS_BOOST) {
		sib = sibling_of(cpu);
		if (sib >= 0 && cpu_class(sib) == FS_DISTRACT) {
			scx_bpf_kick_cpu(sib, SCX_KICK_PREEMPT);
			stat_add(ST_SMT_KICK, 1);
		}
	}
}

static void charge_distract(struct task_ctx *tctx, u64 now)
{
	if (tctx->cls != FS_DISTRACT)
		return;
	__sync_fetch_and_add(&distract_used_ns, now - tctx->charged_at);
	tctx->charged_at = now;
}

void BPF_STRUCT_OPS(focus_tick, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u64 now = scx_bpf_now();

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	charge_distract(tctx, now);

	if (tctx->cls == FS_DISTRACT && distract_capped()) {
		scx_bpf_task_set_slice(p, 0);
		stat_add(ST_CAP_THROTTLE, 1);
		return;
	}

	/* backstop for missed preemption IPIs: yield to waiting focus work */
	if (tctx->cls < FS_NORMAL || !scx_bpf_dsq_nr_queued(CLASS_DSQ(FS_FOCUS)))
		return;
	cctx = lookup_cpu_ctx(-1);
	if (tctx->cls == FS_NORMAL &&
	    (!cctx || now - cctx->started_at < PREEMPT_MIN_RUN_NS))
		return;
	scx_bpf_task_set_slice(p, 0);
	stat_add(ST_TICK_PREEMPT, 1);
}

void BPF_STRUCT_OPS(focus_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u64 now = scx_bpf_now();
	u64 runtime;
	s32 sib;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	runtime = now - tctx->last_run_at;
	tctx->avg_runtime = ewma(tctx->avg_runtime, runtime);
	charge_distract(tctx, now);
	if (tctx->cls < FS_NR_CLASSES)
		stat_add(ST_RT_FOCUS + tctx->cls, runtime);

	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime +
				   scale_by_task_weight_inverse(p, runtime));

	cctx = lookup_cpu_ctx(-1);
	if (cctx)
		cctx->cls = FS_IDLE;

	/* our sibling may have been refusing distract work while we ran */
	if (smt_isolation && tctx->cls <= FS_BOOST &&
	    scx_bpf_dsq_nr_queued(CLASS_DSQ(FS_DISTRACT))) {
		sib = sibling_of(bpf_get_smp_processor_id());
		if (sib >= 0)
			scx_bpf_kick_cpu(sib, SCX_KICK_IDLE);
	}
}

void BPF_STRUCT_OPS(focus_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS(focus_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	tctx->cls = FS_NORMAL;
	tctx->depth = NO_CHAIN;
	return 0;
}

static u64 compute_budget(void)
{
	return CAP_PERIOD_NS * nr_online_cpus * cap_pct / 100;
}

/* Refill the distract budget each period and wake CPUs for queued work. */
static int cap_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;

	distract_budget_ns = compute_budget();
	distract_used_ns = 0;

	if (scx_bpf_dsq_nr_queued(CLASS_DSQ(FS_DISTRACT)) ||
	    scx_bpf_dsq_nr_queued(CLASS_DSQ(FS_NORMAL))) {
		bpf_for(cpu, 0, nr_cpus)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}

	if (bpf_timer_start(timer, CAP_PERIOD_NS, 0))
		scx_bpf_error("failed to re-arm cap timer");
	return 0;
}

static s32 init_cpumasks(void)
{
	struct bpf_cpumask *perf, *eff, *llc;
	struct cpu_ctx *cctx;
	s32 i, j;

	perf = bpf_cpumask_create();
	if (!perf)
		return -ENOMEM;
	eff = bpf_cpumask_create();
	if (!eff) {
		bpf_cpumask_release(perf);
		return -ENOMEM;
	}

	bpf_for(i, 0, nr_cpus) {
		if (is_eff(i))
			bpf_cpumask_set_cpu(i, eff);
		else
			bpf_cpumask_set_cpu(i, perf);
	}

	perf = bpf_kptr_xchg(&perf_mask, perf);
	if (perf)
		bpf_cpumask_release(perf);
	eff = bpf_kptr_xchg(&eff_mask, eff);
	if (eff)
		bpf_cpumask_release(eff);

	bpf_for(i, 0, nr_cpus) {
		if (i >= MAX_CPUS)
			break;
		cctx = lookup_cpu_ctx(i);
		if (!cctx)
			return -ENOENT;
		cctx->cls = FS_IDLE;

		llc = bpf_cpumask_create();
		if (!llc)
			return -ENOMEM;
		bpf_for(j, 0, nr_cpus) {
			if (j >= MAX_CPUS)
				break;
			if (cpu_llc[j] == cpu_llc[i] && !cpu_eff[j])
				bpf_cpumask_set_cpu(j, llc);
		}
		llc = bpf_kptr_xchg(&cctx->llc_perf, llc);
		if (llc)
			bpf_cpumask_release(llc);
	}
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(focus_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	s32 err, c;

	bpf_for(c, 0, FS_NR_CLASSES) {
		err = scx_bpf_create_dsq(CLASS_DSQ(c), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ %d (%d)", c, err);
			return err;
		}
	}

	err = init_cpumasks();
	if (err) {
		scx_bpf_error("failed to init cpumasks (%d)", err);
		return err;
	}

	distract_budget_ns = compute_budget();

	timer = bpf_map_lookup_elem(&cap_timer, &key);
	if (!timer) {
		scx_bpf_error("failed to lookup cap timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &cap_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, cap_timerfn);
	err = bpf_timer_start(timer, CAP_PERIOD_NS, 0);
	if (err)
		scx_bpf_error("failed to arm cap timer (%d)", err);
	return err;
}

void BPF_STRUCT_OPS(focus_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(focus_ops,
	       .select_cpu		= (void *)focus_select_cpu,
	       .enqueue			= (void *)focus_enqueue,
	       .dispatch		= (void *)focus_dispatch,
	       .runnable		= (void *)focus_runnable,
	       .running			= (void *)focus_running,
	       .tick			= (void *)focus_tick,
	       .stopping		= (void *)focus_stopping,
	       .enable			= (void *)focus_enable,
	       .init_task		= (void *)focus_init_task,
	       .init			= (void *)focus_init,
	       .exit			= (void *)focus_exit,
	       .timeout_ms		= 5000,
	       .name			= "focus");
