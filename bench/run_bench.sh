#!/bin/sh
# Compare EEVDF vs focus-sched: wakeup latency of a "focused" app under a
# "distracting" CPU hog, plus the hog's throughput.
#
#   sudo ./run_bench.sh [duration_s] [extra focus-sched args...]
#
# Each scenario runs wakelat (marked focus) alongside hog (marked distract,
# 2x oversubscribed). Under EEVDF the marks are ignored.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
sched="$here/../scheduler/build/focus-sched"
ctl="$here/../focusd/focusctl.py"
sock=/run/focus-sched-bench.sock
dur=${1:-10}
[ $# -gt 0 ] && shift
hog_threads=$(( $(nproc) * 2 ))

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$sched" ] || { echo "build the scheduler first (make -C scheduler)" >&2; exit 1; }
make -s -C "$here"

if [ -e /sys/kernel/sched_ext/root/ops ] && [ -n "$(cat /sys/kernel/sched_ext/root/ops)" ]; then
    echo "another sched_ext scheduler is loaded; stop it first" >&2
    exit 1
fi

scenario() {
    name=$1
    "$here/hog" -t "$hog_threads" -d $((dur + 2)) > "/tmp/bench-hog-$name" 2>/dev/null &
    hog_pid=$!
    "$here/wakelat" -t 4 -d "$dur" -w 1 > "/tmp/bench-lat-$name" 2>/dev/null &
    lat_pid=$!
    if [ "$name" = focus ]; then
        python3 "$ctl" --sched-socket "$sock" raw "set distract_tgid $hog_pid" > /dev/null
        python3 "$ctl" --sched-socket "$sock" raw "set focus_tgid $lat_pid" > /dev/null
    fi
    wait "$lat_pid" "$hog_pid"
    printf '%-12s %s %s\n' "$name" "$(cat "/tmp/bench-lat-$name")" "$(cat "/tmp/bench-hog-$name")"
}

echo "duration ${dur}s, hog threads $hog_threads, $(nproc) CPUs"
scenario eevdf

"$sched" -s "$sock" -i 0 "$@" > /tmp/bench-sched.log 2>&1 &
sched_pid=$!
trap 'kill $sched_pid 2>/dev/null; wait $sched_pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do
    [ -S "$sock" ] && python3 "$ctl" --sched-socket "$sock" raw ping > /dev/null 2>&1 && break
    sleep 0.1
done
python3 "$ctl" --sched-socket "$sock" raw ping > /dev/null || { cat /tmp/bench-sched.log; exit 1; }

scenario focus
echo
python3 "$ctl" --sched-socket "$sock" stats
