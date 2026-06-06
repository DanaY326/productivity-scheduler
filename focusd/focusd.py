#!/usr/bin/env python3
"""focusd: feeds focus-sched with what you're focused on and what distracts you.

Runs as your user. Watches the active window (sway, Hyprland or X11), applies
distraction rules from the config, merges in browser tab groups reported by
the extension's native host, and keeps the scheduler's mark maps in sync over
its control socket.

Its own socket ($XDG_RUNTIME_DIR/focusd.sock) takes JSON lines:
  {"source": "browser", "browser_pid": N, "focus_pids": [...], "distract_pids": [...]}
  {"cmd": "pin", "focus": [pids], "distract": [pids]}
  {"cmd": "unpin"}
  {"cmd": "status"}
"""
import argparse
import datetime
import fnmatch
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import tomllib

CGROUP_ROOT = "/sys/fs/cgroup"

DEFAULT_CONFIG = {
    "scheduler": {"socket": "/run/focus-sched.sock"},
    "focus": {"backend": "auto"},
    "distract": {"comm": [], "cgroup": []},
    "schedule": {"active": [], "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
    "daemon": {"scan_interval": 2.0, "resync_interval": 10.0},
}


def log(*args):
    print(time.strftime("%H:%M:%S"), *args, file=sys.stderr, flush=True)


def load_config(path):
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            for section, values in tomllib.load(f).items():
                cfg.setdefault(section, {}).update(values)
    return cfg


# ---- /proc helpers ---------------------------------------------------------

def proc_table():
    """Return {tgid: (ppid, comm, cgroup_path)} for every process."""
    table = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
            with open(f"/proc/{pid}/cgroup") as f:
                cg = next((l.split("::", 1)[1].strip() for l in f if l.startswith("0::")), "/")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        # comm may contain spaces/parens; it is delimited by the first '(' and last ')'
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        table[pid] = (ppid, comm, cg)
    return table


def descendants(table, roots):
    children = {}
    for pid, (ppid, _, _) in table.items():
        children.setdefault(ppid, []).append(pid)
    out, stack = set(), list(roots)
    while stack:
        pid = stack.pop()
        for child in children.get(pid, ()):
            if child not in out:
                out.add(child)
                stack.append(child)
    return out


def cgroup_id(path):
    """cgroup v2 ids are the inode numbers of the cgroup directories."""
    try:
        return os.stat(CGROUP_ROOT + path).st_ino
    except OSError:
        return None


def is_app_cgroup(path):
    """Desktop launchers (GNOME, KDE, uwsm) put each app in its own unit."""
    leaf = os.path.basename(path)
    return leaf.startswith("app-") and leaf.endswith((".scope", ".service"))


# ---- active-window backends -------------------------------------------------

class WindowWatcher(threading.Thread):
    def __init__(self, on_focus):
        super().__init__(daemon=True)
        self.on_focus = on_focus

    def lines(self, argv):
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        yield from proc.stdout
        raise RuntimeError(f"{argv[0]} exited ({proc.wait()})")

    def run(self):
        while True:
            try:
                self.watch()
            except Exception as e:  # keep the daemon alive across compositor restarts
                log(f"{type(self).__name__}: {e}; retrying in 5s")
                time.sleep(5)


class SwayWatcher(WindowWatcher):
    def watch(self):
        for line in self.lines(["swaymsg", "-t", "subscribe", "-m", '["window"]']):
            ev = json.loads(line)
            if ev.get("change") == "focus":
                self.on_focus(ev.get("container", {}).get("pid"))


class HyprlandWatcher(WindowWatcher):
    def watch(self):
        sig = os.environ["HYPRLAND_INSTANCE_SIGNATURE"]
        path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "hypr", sig, ".socket2.sock")
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(path)
            for line in s.makefile():
                if line.startswith("activewindow>>"):
                    out = subprocess.run(["hyprctl", "activewindow", "-j"],
                                         capture_output=True, text=True).stdout
                    self.on_focus(json.loads(out or "{}").get("pid"))


class X11Watcher(WindowWatcher):
    def watch(self):
        for line in self.lines(["xprop", "-root", "-spy", "_NET_ACTIVE_WINDOW"]):
            wid = line.strip().split()[-1]
            if wid in ("0x0", "found."):
                self.on_focus(None)
                continue
            out = subprocess.run(["xprop", "-id", wid, "_NET_WM_PID"],
                                 capture_output=True, text=True).stdout
            parts = out.split("=")
            self.on_focus(int(parts[1]) if len(parts) == 2 and parts[1].strip().isdigit() else None)


def pick_backend(name):
    if name == "auto":
        if os.environ.get("SWAYSOCK") and shutil.which("swaymsg"):
            name = "sway"
        elif os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
            name = "hyprland"
        elif os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY") and shutil.which("xprop"):
            name = "x11"
        else:
            name = "none"
    return name, {"sway": SwayWatcher, "hyprland": HyprlandWatcher, "x11": X11Watcher}.get(name)


# ---- scheduler client -------------------------------------------------------

class SchedClient:
    def __init__(self, path):
        self.path, self.sock, self.file = path, None, None

    def command(self, line):
        for attempt in range(2):
            try:
                if not self.sock:
                    self.sock = socket.socket(socket.AF_UNIX)
                    self.sock.connect(self.path)
                    self.file = self.sock.makefile("r")
                self.sock.sendall((line + "\n").encode())
                reply = self.file.readline().strip()
                if not reply:
                    raise ConnectionError("scheduler closed the connection")
                return reply
            except OSError as e:
                self.close()
                if attempt:
                    raise ConnectionError(e) from e
        return None

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = self.file = None


# ---- daemon -----------------------------------------------------------------

class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sched = SchedClient(cfg["scheduler"]["socket"])
        self.lock = threading.Lock()
        self.dirty = threading.Event()
        self.focus_pid = None
        self.browser = {}          # last report from the native host
        self.pins = {"focus": set(), "distract": set()}
        self.sent = {}
        self.last_sync = 0.0
        self.status = {}

    def on_focus(self, pid):
        with self.lock:
            if pid != self.focus_pid:
                self.focus_pid = pid
                self.dirty.set()

    def schedule_active(self, now=None):
        sched = self.cfg["schedule"]
        if not sched.get("active"):
            return True
        now = now or datetime.datetime.now()
        if now.strftime("%a").lower() not in [d.lower()[:3] for d in sched.get("days", [])]:
            return False
        hhmm = now.strftime("%H:%M")
        return any(r.split("-")[0] <= hhmm < r.split("-")[1] for r in sched["active"])

    def desired(self):
        table = proc_table()
        dcfg = self.cfg["distract"]
        comm_pats = [p.lower() for p in dcfg.get("comm", [])]
        cg_pats = dcfg.get("cgroup", [])

        with self.lock:
            focus_pid, browser = self.focus_pid, dict(self.browser)
            pin_focus, pin_distract = set(self.pins["focus"]), set(self.pins["distract"])

        d_tgids, d_cgroups = set(), set()
        if self.schedule_active():
            roots = {pid for pid, (_, comm, _) in table.items()
                     if any(fnmatch.fnmatch(comm.lower(), p) for p in comm_pats)}
            d_tgids = roots | descendants(table, roots)
            for path in {cg for _, _, cg in table.values()}:
                if any(fnmatch.fnmatch(os.path.basename(path), p) for p in cg_pats):
                    cid = cgroup_id(path)
                    if cid:
                        d_cgroups.add(cid)
            d_tgids |= set(browser.get("distract_pids", ()))

        f_tgids, f_cgroups = set(), set()
        if focus_pid and focus_pid in table:
            _, _, cg = table[focus_pid]
            looking_at_distraction = focus_pid in d_tgids or cgroup_id(cg) in d_cgroups
            bpid = browser.get("browser_pid")
            if looking_at_distraction:
                pass
            elif bpid and (focus_pid == bpid or focus_pid in descendants(table, [bpid])):
                # browser focused: boost it, minus renderers of distract tab groups
                f_tgids = ({bpid} | descendants(table, [bpid])) - d_tgids
                f_tgids |= set(browser.get("focus_pids", ()))
            elif is_app_cgroup(cg) and cgroup_id(cg):
                f_cgroups.add(cgroup_id(cg))
            else:
                f_tgids = {focus_pid} | descendants(table, [focus_pid])

        # explicit pins win over rules; otherwise distraction wins over focus
        f_tgids = (f_tgids - d_tgids) | pin_focus
        d_tgids = (d_tgids - pin_focus) | pin_distract
        f_tgids -= pin_distract
        live = set(table)
        return {
            "focus_tgid": sorted(f_tgids & live),
            "focus_cgroup": sorted(f_cgroups - d_cgroups),
            "distract_tgid": sorted(d_tgids & live),
            "distract_cgroup": sorted(d_cgroups),
        }

    def sync(self, force=False):
        want = self.desired()
        # distract first so a pid moving distract -> focus ends up as focus
        for key in ("distract_tgid", "distract_cgroup", "focus_tgid", "focus_cgroup"):
            if not force and self.sent.get(key) == want[key]:
                continue
            reply = self.sched.command(f"set {key} " + " ".join(map(str, want[key])))
            if not reply or not reply.startswith("ok"):
                log(f"scheduler rejected set {key}: {reply}")
                continue
            if self.sent.get(key) != want[key]:
                log(f"{key}: {len(want[key])} ids")
            self.sent[key] = want[key]
        self.status = {"focus_pid": self.focus_pid, "schedule_active": self.schedule_active(), **want}

    def handle_client(self, conn):
        is_browser = False
        try:
            for line in conn.makefile():
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    conn.sendall(b'{"ok": false, "error": "bad json"}\n')
                    continue
                reply = {"ok": True}
                with self.lock:
                    if msg.get("source") == "browser":
                        is_browser = True
                        self.browser = {k: msg.get(k) for k in ("browser_pid", "focus_pids", "distract_pids")}
                    elif msg.get("cmd") == "pin":
                        self.pins["focus"] |= set(map(int, msg.get("focus", ())))
                        self.pins["distract"] |= set(map(int, msg.get("distract", ())))
                    elif msg.get("cmd") == "unpin":
                        self.pins = {"focus": set(), "distract": set()}
                    elif msg.get("cmd") == "status":
                        reply = {"ok": True, **self.status}
                    else:
                        reply = {"ok": False, "error": "unknown message"}
                self.dirty.set()
                conn.sendall((json.dumps(reply) + "\n").encode())
        finally:
            if is_browser:
                with self.lock:
                    self.browser = {}
                self.dirty.set()
            conn.close()

    def serve(self, path):
        if os.path.exists(path):
            os.unlink(path)
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
        os.chmod(path, 0o600)
        srv.listen(4)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def run(self, listen_path):
        name, watcher = pick_backend(self.cfg["focus"].get("backend", "auto"))
        log(f"window backend: {name}")
        if watcher:
            watcher(self.on_focus).start()
        else:
            log("no window backend; use focusctl pin or browser tab groups")
        threading.Thread(target=self.serve, args=(listen_path,), daemon=True).start()
        log(f"listening on {listen_path}")

        dcfg = self.cfg["daemon"]
        while True:
            self.dirty.wait(timeout=dcfg["scan_interval"])
            self.dirty.clear()
            now = time.monotonic()
            force = now - self.last_sync > dcfg["resync_interval"]
            try:
                self.sync(force=force)
                if force:
                    self.last_sync = now
            except ConnectionError as e:
                log(f"scheduler unavailable ({e}); will retry")
                self.sent = {}


def default_listen_path():
    return os.path.join(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/focusd-{os.getuid()}"), "focusd.sock")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-c", "--config", default=os.path.expanduser("~/.config/focusd/config.toml"))
    ap.add_argument("-l", "--listen", default=default_listen_path())
    ap.add_argument("--print-once", action="store_true", help="print the computed sets and exit")
    args = ap.parse_args()

    daemon = Daemon(load_config(args.config))
    if args.print_once:
        print(json.dumps(daemon.desired(), indent=2))
        return
    os.makedirs(os.path.dirname(args.listen), exist_ok=True)
    daemon.run(args.listen)


if __name__ == "__main__":
    main()
