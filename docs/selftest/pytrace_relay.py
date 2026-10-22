"""Transparent loopback relay for the Python Spawns self-test.

Accepts ONE connection on 127.0.0.1:<listen_port>, connects to
127.0.0.1:<upstream_port>, and pumps bytes both ways while appending each
direction's bytes to <out_dir>/client.bin (client→server) and
<out_dir>/server.bin (server→client). The TLS session passes through
untouched, so the recorded streams + the client's SSLKEYLOGFILE are a real
decryptable pair — this is the loopback stand-in for the NIC-level capture.
"""
import socket
import sys
import threading

listen_port, upstream_port, out_dir = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

srv = socket.create_server(("127.0.0.1", listen_port))
print("RELAY-READY", flush=True)
conn, _ = srv.accept()
up = socket.create_connection(("127.0.0.1", upstream_port), timeout=15)

client_log = open(f"{out_dir}/client.bin", "wb")
server_log = open(f"{out_dir}/server.bin", "wb")


def pump(src, dst, log):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            log.write(data)
            log.flush()
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


t1 = threading.Thread(target=pump, args=(conn, up, client_log))
t2 = threading.Thread(target=pump, args=(up, conn, server_log))
t1.start()
t2.start()
t1.join()
t2.join()
print("RELAY-DONE", flush=True)
