# focus-sched

A focus-aware Linux CPU scheduler built on sched_ext. Whatever you're focused
on (the active window, and browser tabs in a "focus" tab group) gets priority,
fast cores and preemption. Distractions (configured apps, and tabs in a
"distract" group) are packed onto efficiency cores and limited to a CPU budget.

See [PLAN.md](PLAN.md) for the design and which scheduler features it uses.

```
scheduler/   focus.bpf.c (sched_ext policy) + focus.c (loader, control socket)
focusd/      focusd.py (window focus + rules daemon), focusctl.py, native host
extension/   Chrome MV3 extension for tab groups
bench/       wakelat (latency), hog (throughput), run_bench.sh (EEVDF vs focus)
dev/         Dockerfile for a build-only environment
```

## Requirements

- Linux with `CONFIG_SCHED_CLASS_EXT=y`, kernel **6.12+**. Kernel **6.16+** is
  needed for the placement features (`scx_bpf_select_cpu_and`); on older
  kernels the scheduler falls back to default idle-CPU selection.
  Fedora 41+, Arch, and Ubuntu 25.04+ kernels ship with sched_ext enabled.
- clang ≥ 17, bpftool, libbpf ≥ 1.4, libelf, zlib, Python ≥ 3.11.

On a Mac, develop in a Linux VM (e.g. UTM running Fedora). Docker can only
compile the code: the scheduler loads into the kernel, so it needs a real
sched_ext kernel to run.

## Build and run

```sh
make -C scheduler                       # fetches pinned scx headers on first build
make -C bench

# run the scheduler (root); hand the control socket to your user
sudo scheduler/build/focus-sched -u "$(id -u):$(id -g)"

# in your session
mkdir -p ~/.config/focusd && cp focusd/config.example.toml ~/.config/focusd/config.toml
focusd/focusd.py
```

Ctrl-C on `focus-sched` restores the default scheduler. If the BPF scheduler
misbehaves (stalls a task for 5 s, hits an error), the kernel's sched_ext
watchdog unloads it automatically. `cat /sys/kernel/sched_ext/state` shows
whether it's active.

### Loader options

| flag | meaning |
|---|---|
| `-c PCT` | cap distract runtime at PCT% of all CPUs (default 30; 100 = off) |
| `-E` | energy mode: distract work stays on efficiency CPUs |
| `-e CPULIST` | override efficiency-CPU detection (e.g. `-e 12-15` on a non-hybrid chip to dedicate cores to distractions) |
| `-S` / `-A` | disable SMT isolation / audio rescue |
| `-b MS`, `-H US` | wake-chain boost duration, hog-demotion threshold |
| `-i SEC` | stats interval (0 = quiet) |

### Browser tab groups

1. Go to `chrome://extensions`, enable Developer mode, then **Load unpacked**
   → `extension/`.
2. `focusd/install_native_host.sh <extension-id>`
3. Name tab groups starting with `focus` / `🎯` or `distract` / `🚫`.

On Chrome **dev channel**, the extension maps tabs to renderer PIDs, and the
scheduler handles them. On stable, `chrome.processes` isn't available, so
distract tabs are slowed inside the browser with DevTools CPU throttling
instead. Chrome shows a "being debugged" bar while it's active; closing that
bar exempts the tab.

### Manual control

```sh
focusd/focusctl.py stats                 # counters since load
focusd/focusctl.py tune cap_pct 15       # live tunables: cap_pct boost_ms hog_us
                                         #   smt_isolation audio_rescue energy_mode
focusd/focusctl.py pin --focus 1234      # pin PIDs (needed on GNOME/KDE Wayland)
focusd/focusctl.py status
```

### Control socket protocol

The control socket is `/run/focus-sched.sock`. It takes one command per line
and replies to each with a line starting `ok` or `err`.

```
ping
set focus_tgid|focus_cgroup|distract_tgid|distract_cgroup [id ...]   # replaces that set
tune <key> <value>
get
stats
```

cgroup ids are the inode numbers of cgroup v2 directories
(`stat -c %i /sys/fs/cgroup/<path>`). A mark on a cgroup also covers up to 8
levels of child cgroups. tgid marks take precedence over cgroup marks.

## Benchmark

```sh
sudo bench/run_bench.sh 15
```

This runs `wakelat` (4 threads waking every 1 ms, marked focus) against `hog`
(2× oversubscribed spinners, marked distract), first under EEVDF and then
under focus-sched. It prints wakeup-latency percentiles, hog throughput, and
the scheduler's counters. Expect the focus run to show much lower p99/p99.9
latency, and hog throughput close to `cap_pct`.

## Status

The BPF scheduler compiles cleanly for x86 and arm64 against scx v1.1.4
headers, and the loader passes a syntax check. **Nothing has been loaded on a
sched_ext kernel yet.** The first real run may surface BPF verifier
complaints, which are only checked at load time. Run `focus-sched -v` to see
the full verifier log.
