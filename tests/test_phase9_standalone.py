"""Standalone SQLite smoke test. Build Corvus before running this script."""

import json
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "corvus.exe"


def reserve_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(method, url, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None


def run_standalone_smoke_test():
    if not BINARY.exists():
        raise RuntimeError("Build Corvus first: cargo build -p security-control-plane --bin corvus")

    port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="corvus-phase9-") as temp_dir:
        temp_path = Path(temp_dir)
        database_path = temp_path / "corvus.db"
        config_path = temp_path / "corvus.toml"
        config_path.write_text(
            f'mode = "standalone"\nbind_address = "127.0.0.1:{port}"\n'
            f'[storage]\nsqlite_path = "{database_path.as_posix()}"\n',
            encoding="utf-8",
        )
        process = subprocess.Popen(
            [str(BINARY), "--config", str(config_path)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.time() + 15
            while time.time() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Corvus exited early with status {process.returncode}")
                try:
                    request("GET", base + "/api/v1/health")
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Corvus did not become ready")

            for _ in range(10):
                event = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "app_id": "phase9-test",
                    "environment": "test",
                    "event_type": "auth.login",
                    "severity": "medium",
                    "source": {
                        "ip": "192.0.2.92",
                        "sensor": {
                            "sensor_type": "agent",
                            "raw_event_type": "http_request",
                        },
                    },
                    "action": {
                        "status_code": 401,
                        "is_success": False,
                        "endpoint": "/login",
                    },
                    "is_security_significant": True,
                }
                status, _ = request("POST", base + "/api/v1/telemetry", event)
                assert status == 202

            deadline = time.time() + 5
            incidents = []
            while time.time() < deadline:
                _, incidents = request("GET", base + "/api/v1/incidents")
                if incidents:
                    break
                time.sleep(0.05)
            assert incidents, "Expected the standalone detection pipeline to create an incident"
            assert database_path.exists() and database_path.stat().st_size > 0
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    run_standalone_smoke_test()
    print("PASS Phase 9 standalone SQLite integration")
