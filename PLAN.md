# focus-sched: a focus-aware sched_ext scheduler

## Goal

Make whatever you're focused on (the active window, and the browser tabs in a
"focus" tab group) feel faster under load. At the same time, push distractions
(configured apps, and browser tabs in a "distract" group) onto cheap CPUs and
give them only a capped share of CPU time.

The core is a sched_ext BPF scheduler, written to use what cgroups can't do:
per-event decisions, CPU placement, wake-chain awareness and preemption.

## Architecture

```
 ┌──────────────┐  native msg   ┌──────────────┐
 │  Chrome ext  │──────────────▶│ native_host  │
 │ (tab groups) │               └──────┬───────┘
 └──────────────┘                      │ JSON over $XDG_RUNTIME_DIR/focusd.sock
                                       ▼
 window focus  ┌───────────────────────────────────┐
 (sway/hypr/X) │ focusd (user, Python)             │
 ─────────────▶│  - active window → pid → cgroup   │
               │  - distraction rules (comm/cgroup)│
               │  - schedule (active hours)        │
               └──────────────┬────────────────────┘
                              │ line protocol over /run/focus-sched.sock
                              ▼
               ┌───────────────────────────────────┐
               │ focus-sched loader (root, C)      │
               │  - topology detection → rodata    │
               │  - BPF map sync, tunables, stats  │
               └──────────────┬────────────────────┘
                              │ maps / .bss
                              ▼
               ┌───────────────────────────────────┐
               │ focus.bpf.c (sched_ext, kernel)   │
               └───────────────────────────────────┘
```

## Task classes

Each task's class is recomputed when it is enqueued. In priority order:

| Class      | Who                                             | DSQ        | Slice  |
|------------|-------------------------------------------------|------------|--------|
| `FOCUS`    | tgid or cgroup marked focus (not CPU hogs)      | FOCUS_DSQ  | 3 ms   |
| `BOOST`    | tasks on the focus wake chain (decaying)        | BOOST_DSQ  | 2 ms   |
| `NORMAL`   | everything else, plus demoted hogs and rescued audio | NORMAL_DSQ | 2/5 ms |
| `DISTRACT` | tgid or cgroup marked distract                  | DISTRACT_DSQ | 20 ms |

Within each DSQ, tasks are ordered by weighted vtime. Across DSQs the order is
strict priority, with starvation guards.

## Scheduler features, and why cgroups can't do each one

1. **Preemption on wakeup.** When a FOCUS or BOOST task is queued and no idle
   CPU is free, find a CPU running DISTRACT (or, for FOCUS, a long-running
   NORMAL task) and `scx_bpf_kick_cpu(SCX_KICK_PREEMPT)` it. A backstop in
   `ops.tick` zeroes the slice of lower-class tasks while FOCUS work waits.
   *(cgroups set a share; they don't decide when to preempt.)*
2. **Per-task slice length.** Short slices for the focused and interactive
   tasks, long slices for batch work and distractions.
3. **CPU placement.**
   - *Hybrid cores:* topology detection splits CPUs into a *performance* set
     and an *efficiency* set (Intel `cpu_atom`, ARM `cpu_capacity`, AMD CPPC,
     or `--eff-cpus`). FOCUS and BOOST go to performance CPUs; DISTRACT is
     packed onto efficiency CPUs.
   - *SMT isolation:* when a FOCUS or BOOST task starts running, a DISTRACT
     task on its SMT sibling is kicked off, and that sibling won't take more
     distract work until the focus task stops.
   - *LLC affinity:* FOCUS and BOOST tasks first try an idle CPU that shares
     an LLC (last-level cache) with `prev_cpu` and is a performance CPU,
     preferring fully idle cores.
4. **Wake-chain boosting.** In `ops.runnable` (`SCX_ENQ_WAKEUP`):
   - *downstream:* a task woken by a FOCUS or BOOST task becomes BOOST;
   - *upstream:* a task that wakes a FOCUS or BOOST task becomes BOOST
     (compositor, PipeWire, X server, language server, ...).
   Depth is limited (`MAX_CHAIN_DEPTH`) and boosts decay after `boost_ns`.
   Interrupt context, kthreads (for upstream) and distract tasks are ignored.
5. **Behavior classification.** Per-task EWMAs of runtime per run and the
   interval between wakeups:
   - *Hog demotion:* a FOCUS or BOOST task that keeps using up its full slice
     (e.g. a compile running inside the focused terminal) drops to NORMAL
     priority. It keeps its performance-CPU placement.
   - *Audio rescue:* a DISTRACT task with very short runs and frequent
     wakeups (a music app's audio thread) is scheduled as NORMAL, so muting
     your focus doesn't make your music glitch.
   - *Interactive NORMAL:* short slice and extra vtime credit.
6. **Distraction cap (duty cycle).** Distract runtime is accounted globally
   per 100 ms period against `cap_pct` × online CPUs. Over budget, DISTRACT
   isn't dispatched and running distract tasks lose their slice at the next
   tick. A `bpf_timer` refills the budget and wakes idle CPUs.
7. **Energy packing.** In energy mode, performance CPUs never pull distract
   work unless it is starving. Distract stays on the efficiency cores, so
   performance cores can idle.
8. **Observability.** Per-CPU counters for dispatches per class, runtime per
   class, preempt kicks, SMT kicks, boosts up and down, cap throttles,
   starvation rescues and audio rescues. The loader prints them, and they are
   readable over the socket.

Safety: `timeout_ms` is set to 5 s. Starvation guards run NORMAL after 50 ms
of waiting and DISTRACT after 250 ms. If anything goes wrong, the kernel's
sched_ext watchdog reverts to EEVDF.

## Milestones

1. [x] Build system: pinned scx headers, vendored `vmlinux.h`, skeleton.
2. [x] BPF scheduler with all features above, plus loader with control socket.
3. [x] `focusd`: window backends (sway/i3, Hyprland, X11), rules,
   schedule, browser bridge.
4. [x] Chrome extension and native messaging host.
5. [x] Benchmarks: `wakelat` (wakeup latency percentiles), `hog`
   (throughput), and a script comparing EEVDF with focus-sched.
6. [ ] Run on real hardware, tune defaults, collect numbers.
7. [ ] Stretch goals: Firefox port, cpufreq (`scx_bpf_cpuperf_set`) boost for
   focus CPUs, a GNOME Shell extension for Wayland focus.

## Known limitations

- Chrome exposes tab→PID mapping only through `chrome.processes`, which is
  on the dev channel only. On stable, the extension falls back to in-browser
  CPU throttling via `chrome.debugger`, which shows a "being debugged"
  infobar.
- Renderer processes can be shared across tabs. A PID in both groups is
  treated as focus.
- On GNOME and KDE Wayland, nothing can observe window focus without a shell
  extension. Use `focusctl` or the browser groups instead.
- Wakeups delivered by IPI (inter-processor interrupt) or interrupt context
  have no meaningful waker, so wake-chain tracking skips them.
