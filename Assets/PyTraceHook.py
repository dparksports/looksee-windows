# LookSee python trace hook — the "why" half of the Python Spawns tab.
#
# Installed opt-in per environment as PyTraceHook_ac.py + PyTraceHook_ac.pth
# in site-packages. The .pth import runs this file during site initialization,
# before user code: the audit hook is then in place for the whole interpreter
# session. Each record is one JSON line appended to a per-pid file under
# %LOCALAPPDATA%\LookSee\pytrace, which the LookSee app tails.
#
# Keep this cheap and quiet: no network, no logging module, no I/O except the
# single append per matched audit event.
#
# Reach limits (documented in the app UI too): a .pth in real site-packages
# survives -I/-E, but -S, frozen and embedded interpreters never load site at
# all. Nothing here can instrument those.

import json
import os
import sys
import time
import traceback

_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "LookSee", "pytrace")
_TRACE_EVENTS = frozenset((
    "subprocess.Popen",
    "_winapi.CreateProcess",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.startfile",
    "sys.addaudithook",  # another observer registering — record its stack too
))
_MAX_ARG = 300


def _safe_arg(a):
    try:
        r = repr(a)
    except Exception:
        r = "<unrepr>"
    return r if len(r) <= _MAX_ARG else r[: _MAX_ARG - 3] + "..."


def _audit(event, args):
    if event not in _TRACE_EVENTS:
        return
    try:
        rec = {
            "ts": time.time(),
            "pid": os.getpid(),
            "event": event,
            "args": [_safe_arg(a) for a in args],
            "stack": traceback.format_stack(),
        }
        with open(_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass  # tracing must never take the host program down


_PATH = os.path.join(_DIR, "trace-%d.jsonl" % os.getpid())

try:
    os.makedirs(_DIR, exist_ok=True)
except Exception:
    pass  # unwritable profile: records are dropped, the host program is unaffected

# TLS plaintext enabler: CPython's ssl module reads SSLKEYLOGFILE when an
# SSLContext is constructed, so setting it here covers contexts created by any
# later user code. Never overrides a value the user already had, and a
# no-keylog flag file (the app's "Disable TLS keylogging" toggle) wins too.
if (
    "SSLKEYLOGFILE" not in os.environ
    and not os.path.exists(os.path.join(_DIR, "no-keylog"))
):
    os.environ["SSLKEYLOGFILE"] = os.path.join(_DIR, "sslkeys.log")

# Per-process registration guard. The marker holds the registering pid:
# children inherit it, see a foreign pid and register themselves; a second
# loader in the SAME process (sitecustomize plus our .pth) sees its own pid
# and skips, avoiding double records.
if os.environ.get("LOOKSEE_PYTRACE_PID") != str(os.getpid()):
    os.environ["LOOKSEE_PYTRACE_PID"] = str(os.getpid())
    try:
        sys.addaudithook(_audit)
    except Exception:
        pass  # e.g. audit hooks frozen after -X audit hook setup; stay quiet
