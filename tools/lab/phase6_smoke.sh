#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import socket
import subprocess
import sys
import threading

ready = threading.Event()
peer = {}

def serve_once():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        peer["port"] = server.getsockname()[1]
        ready.set()
        connection, address = server.accept()
        with connection:
            connection.recv(1)
        peer["address"] = address[0]

server = threading.Thread(target=serve_once, daemon=True)
server.start()
ready.wait()

child = subprocess.run([sys.executable, "-c", "pass"], check=False)
if child.returncode != 0:
    raise SystemExit(f"known child failed with status {child.returncode}")

with socket.create_connection(("127.0.0.1", peer["port"])) as client:
    client.sendall(b"x")
server.join(timeout=5)
if server.is_alive():
    raise SystemExit("known listener did not accept the connection")

print(f"known_child={sys.executable} status={child.returncode}")
print(f"known_bind=127.0.0.1:{peer['port']}")
print(f"known_connect=127.0.0.1:{peer['port']}")
print(f"known_accept_peer={peer['address']}")
PY
