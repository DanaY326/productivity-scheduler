#!/usr/bin/env python3
"""focusctl: poke focus-sched and focusd by hand.

  focusctl stats                       scheduler counters
  focusctl get                         scheduler tunables
  focusctl tune cap_pct 20             change a tunable
  focusctl pin --focus 1234 --distract 555 666
  focusctl unpin
  focusctl status                      what focusd last pushed
  focusctl raw "set focus_tgid 1234"   send a raw scheduler command
"""
import argparse
import json
import os
import socket
import sys

SCHED_SOCK = "/run/focus-sched.sock"
FOCUSD_SOCK = os.path.join(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/focusd-{os.getuid()}"), "focusd.sock")


def talk(path, line):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(path)
        s.sendall((line + "\n").encode())
        return s.makefile().readline().strip()


def sched(args, line):
    reply = talk(args.sched_socket, line)
    if not reply.startswith("ok"):
        sys.exit(reply)
    return reply[2:].strip()


def focusd(args, msg):
    reply = json.loads(talk(args.focusd_socket, json.dumps(msg)))
    if not reply.pop("ok", False):
        sys.exit(reply.get("error", "focusd error"))
    return reply


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sched-socket", default=SCHED_SOCK)
    ap.add_argument("--focusd-socket", default=FOCUSD_SOCK)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    sub.add_parser("get")
    t = sub.add_parser("tune")
    t.add_argument("key")
    t.add_argument("value")
    p = sub.add_parser("pin")
    p.add_argument("--focus", nargs="*", type=int, default=[])
    p.add_argument("--distract", nargs="*", type=int, default=[])
    sub.add_parser("unpin")
    sub.add_parser("status")
    r = sub.add_parser("raw")
    r.add_argument("line")
    args = ap.parse_args()

    if args.cmd in ("stats", "get"):
        for kv in sched(args, args.cmd).split():
            k, v = kv.split("=", 1)
            if k.startswith("rt_"):
                v = f"{int(v) / 1e9:.2f}s"
            print(f"{k:16} {v}")
    elif args.cmd == "tune":
        sched(args, f"tune {args.key} {args.value}")
    elif args.cmd == "raw":
        print(talk(args.sched_socket, args.line))
    elif args.cmd == "pin":
        focusd(args, {"cmd": "pin", "focus": args.focus, "distract": args.distract})
    elif args.cmd == "unpin":
        focusd(args, {"cmd": "unpin"})
    elif args.cmd == "status":
        print(json.dumps(focusd(args, {"cmd": "status"}), indent=2))


if __name__ == "__main__":
    main()
