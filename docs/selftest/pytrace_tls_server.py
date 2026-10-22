"""One-shot local TLS server for the Python Spawns self-test.

Serves a single HTTPS response on 127.0.0.1:<port>, then exits. Used with
pytrace_relay.py + pytrace_tls_client.py to produce real TLS streams + real
SSLKEYLOGFILE secrets without any network access.
"""
import os
import socket
import ssl
import sys

port = int(sys.argv[1])
cert, key = sys.argv[2], sys.argv[3]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
if os.environ.get("FORCE_TLS12"):
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # exercise the 1.2 decrypt path

srv = socket.create_server(("127.0.0.1", port))
print("SERVER-READY", flush=True)
conn, _ = srv.accept()
tls = ctx.wrap_socket(conn, server_side=True)
req = tls.recv(65536)
print("SERVER-REQUEST", len(req), flush=True)
tls.sendall(b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 19\r\n"
            b"Server: pytrace-selftest\r\n"
            b"Connection: close\r\n\r\n"
            b"Hello from TLS 1.3")
tls.close()
