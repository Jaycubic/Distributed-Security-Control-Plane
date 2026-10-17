"""Phase 7 integration checks. Start Corvus before running this script."""

import json
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone


BASE = "http://localhost:8080"


def request(method, path, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.status, json.loads(response.read())


def make_event(event_type, port, ip=None):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_id": "phase7-test",
        "environment": "test",
        "event_type": event_type,
        "severity": "low",
        "source": {
            "ip": ip,
            "port": port,
            "sensor": {
                "sensor_type": "native_sensor",
                "raw_event_type": event_type,
            },
            "pid": 1234,
            "process_name": "test-server",
        },
        "is_security_significant": event_type == "kernel.net.bind",
    }


def test_bindings_api_and_port_scan():
    ports = list(range(32000, 32015))
    source_ip = f"192.0.2.{uuid.uuid4().int % 254 + 1}"
    bind_events = [make_event("kernel.net.bind", port) for port in ports]
    status, body = request("POST", "/api/v1/telemetry", bind_events)
    assert status == 202 and body["accepted_count"] == len(ports), body

    deadline = time.time() + 3
    bindings = []
    while time.time() < deadline:
        status, bindings = request("GET", "/api/v1/port-guardian/bindings")
        if all(any(binding["port"] == port for binding in bindings) for port in ports):
            break
        time.sleep(0.05)
    assert status == 200
    assert all(any(binding["port"] == port for binding in bindings) for port in ports)

    connection_events = [
        make_event("kernel.net.connect", port, source_ip) for port in ports
    ]
    status, body = request("POST", "/api/v1/telemetry", connection_events)
    assert status == 202 and body["accepted_count"] == len(ports), body

    def scan_incident_exists(incidents):
        return any(
            item.get("severity") == "critical"
            and any(
                signal.get("rule_name") == "Port Scan / Connection Flood Detected"
                and signal.get("severity") == "critical"
                and source_ip in signal.get("description", "")
                for signal in item.get("signals", [])
            )
            for item in incidents
        )

    deadline = time.time() + 3
    incidents = []
    while time.time() < deadline:
        _, incidents = request("GET", "/api/v1/incidents")
        if scan_incident_exists(incidents):
            break
        time.sleep(0.05)
    assert scan_incident_exists(incidents), incidents


if __name__ == "__main__":
    test_bindings_api_and_port_scan()
    print("PASS Phase 7 Port Guardian integration")
