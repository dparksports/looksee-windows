"""Instrumented TLS client for the Python Spawns self-test.

Loads the REAL audit-hook payload (Assets/PyTraceHook.py, copied next to this
script as PyTraceHook_ac.py by run-selftest), which must set SSLKEYLOGFILE
before any ssl context exists. Then it spawns a child process (exercising the
audit hook's stack capture) and makes the TLS request through the relay.
"""
import os
import socket
import ssl
import subprocess
import sys

hook_dir = sys.argv[1]          # dir containing PyTraceHook_ac.py
relay_port = int(sys.argv[2])

sys.path.insert(0, hook_dir)
import PyTraceHook_ac  # noqa: E402  (must run before any ssl context)

keylog = os.environ.get("SSLKEYLOGFILE", "")
assert keylog.endswith("sslkeys.log"), f"hook did not set SSLKEYLOGFILE (got {keylog!r})"

# Exercise the audit hook: this spawn must land in trace-<pid>.jsonl with a
# stack naming this very subprocess.run call.
subprocess.run(["cmd.exe", "/c", "echo selftest child"], capture_output=True)

ctx = ssl.create_default_context(cafile=os.environ["SELFTEST_CERT"])
ctx.check_hostname = True  # relay is transparent: end-to-end verification holds

raw = socket.create_connection(("127.0.0.1", relay_port), timeout=15)
s = ctx.wrap_socket(raw, server_hostname="localhost")
s.sendall(b"GET /selftest HTTP/1.1\r\n"
          b"Host: localhost\r\n"
          b"User-Agent: pytrace-selftest\r\n"
          b"Connection: close\r\n\r\n")
body = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    body += chunk

print(f"CLIENT-OK version={s.version()} bytes={len(body)} pid={os.getpid()}", flush=True)
