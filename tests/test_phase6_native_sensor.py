"""
Phase 6 Native Sensor — Integration Verification
Tests that the normalization and event ingestion pipeline accepts
NativeSensor events correctly without any eBPF kernel dependency.
"""
import requests
import json
import time
import uuid
from datetime import datetime, timezone

BASE = "http://localhost:8080"

def make_native_sensor_event(event_type: str, severity: str = "low") -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_id": "test-server",
        "environment": "production",
        "event_type": event_type,
        "severity": severity,
        "source": {
            "sensor": {
                "sensor_type": "native_sensor",
                "raw_event_type": event_type,
                "sensor_id": "native-sensor-test-server"
            },
            "pid": 1234,
            "process_name": "/bin/bash"
        },
        "is_security_significant": True,
        "metadata": {
            "uid": 0,
            "comm": "bash",
            "filename": "/bin/bash",
            "ppid": 1
        }
    }

def test_native_sensor_execve_event_ingested():
    event = make_native_sensor_event("kernel.execve", "critical")
    r = requests.post(f"{BASE}/api/v1/telemetry", json=event)
    assert r.status_code in (200, 202), f"Expected 200 or 202, got {r.status_code}: {r.text}"
    body = r.json()
    assert "event_ids" in body or "event_id" in body

def test_native_sensor_bind_event_ingested():
    event = make_native_sensor_event("kernel.net.bind", "low")
    event["source"]["ip"] = "0.0.0.0"
    event["source"]["port"] = 8080
    r = requests.post(f"{BASE}/api/v1/telemetry", json=event)
    assert r.status_code in (200, 202)

def test_native_sensor_connect_event_ingested():
    event = make_native_sensor_event("kernel.net.connect", "medium")
    event["source"]["ip"] = "185.220.101.1"
    event["source"]["port"] = 443
    r = requests.post(f"{BASE}/api/v1/telemetry", json=event)
    assert r.status_code in (200, 202)

def test_bash_root_execve_triggers_kernel_anomaly_rule():
    """Send 1 critical execve event and verify an incident is created."""
    event = make_native_sensor_event("kernel.execve", "critical")
    event["source"]["ip"] = "192.168.1.105"
    r = requests.post(f"{BASE}/api/v1/telemetry", json=event)
    assert r.status_code in (200, 202)
    time.sleep(1.0)
    incidents = requests.get(f"{BASE}/api/v1/incidents").json()
    found = any(
        inc.get("severity") in ("critical", "high") for inc in incidents
    )
    assert found, f"Expected incident. Got: {incidents}"

if __name__ == "__main__":
    passed = 0
    failed = 0
    test_funcs = [
        test_native_sensor_execve_event_ingested,
        test_native_sensor_bind_event_ingested,
        test_native_sensor_connect_event_ingested,
        test_bash_root_execve_triggers_kernel_anomaly_rule,
    ]
    for fn in test_funcs:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\nPhase 6 Test Results: {passed} passed, {failed} failed")
    if failed > 0:
        exit(1)
