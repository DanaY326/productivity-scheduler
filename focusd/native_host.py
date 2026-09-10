#!/usr/bin/env python3
"""Chrome native messaging host: relays tab-group PIDs from the extension to focusd.

Chrome launches this with the extension's port; messages are 4-byte
little-endian length-prefixed JSON on stdin/stdout. Our parent process is the
browser, which is how focusd learns the browser's main PID.
"""
import json
import os
import socket
import struct
import sys

FOCUSD_SOCK = os.path.join(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/focusd-{os.getuid()}"), "focusd.sock")


def read_message():
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    return json.loads(sys.stdin.buffer.read(length))


def write_message(msg):
    data = json.dumps(msg).encode()
    sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
    sys.stdout.buffer.flush()


def browser_pid():
    # Chrome may launch us through a shell; walk up past it
    pid = os.getppid()
    with open(f"/proc/{pid}/comm") as f:
        if f.read().strip() in ("sh", "bash", "dash"):
            with open(f"/proc/{pid}/stat") as s:
                pid = int(s.read().rsplit(")", 1)[1].split()[1])
    return pid


def main():
    sock, rfile = None, None
    bpid = browser_pid()
    while (msg := read_message()) is not None:
        report = {
            "source": "browser",
            "browser_pid": bpid,
            "focus_pids": [int(p) for p in msg.get("focus_pids", [])],
            "distract_pids": [int(p) for p in msg.get("distract_pids", [])],
        }
        try:
            if sock is None:
                sock = socket.socket(socket.AF_UNIX)
                sock.connect(FOCUSD_SOCK)
                rfile = sock.makefile()
            sock.sendall((json.dumps(report) + "\n").encode())
            write_message({"ok": json.loads(rfile.readline()).get("ok", False)})
        except (OSError, ValueError) as e:
            if sock:
                sock.close()
            sock = None
            write_message({"ok": False, "error": f"focusd unavailable: {e}"})


if __name__ == "__main__":
    main()
