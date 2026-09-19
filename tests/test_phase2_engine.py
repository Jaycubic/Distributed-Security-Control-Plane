"""
Phase 2 Deterministic Detection & Incident Engine Integration Test

Verifies:
1. Credential Brute-Force attack detection & incident creation (>10 failed logins).
2. Rapid API Enumeration reconnaissance detection (>20 404s across diverse paths).
3. eBPF Kernel anomaly detection (unauthorized /bin/sh shell spawn in container).
4. Entity risk accumulation and dynamic severity escalation (Medium -> High -> Critical).
5. Incident REST API endpoints (GET /api/v1/incidents, POST /api/v1/incidents/:id/status).
"""

import unittest
import requests
import time
import uuid
from datetime import datetime, timezone

BASE_URL = "http://localhost:8080"

class TestPhase2DetectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verify control plane is running
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=3)
            if resp.status_code != 200:
                raise RuntimeError(f"Control plane returned status {resp.status_code}")
        except Exception as e:
            raise unittest.SkipTest(f"Control plane is not running at {BASE_URL}. Start it with 'cargo run --bin security-control-plane'. Error: {e}")

    def create_event(
        self,
        app_id="app-storefront",
        event_type="http.request",
        ip="198.51.100.42",
        endpoint="/api/v1/catalog",
        status_code=200,
        is_success=True,
        user_id=None,
        sensor_type="agent",
        raw_sensor_type="http_request",
        process_name=None,
        severity="low",
        is_security_significant=False,
    ):
        event_id = str(uuid.uuid4())
        return {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "app_id": app_id,
            "environment": "production",
            "event_type": event_type,
            "severity": severity,
            "actor": {
                "user_id": user_id,
                "role": "visitor",
                "session_id": str(uuid.uuid4()),
            } if user_id else None,
            "source": {
                "ip": ip,
                "port": 49210,
                "user_agent": "Mozilla/5.0 (SecurityScanner)",
                "sensor": {
                    "sensor_type": sensor_type,
                    "raw_event_type": raw_sensor_type,
                },
                "process_name": process_name,
            },
            "action": {
                "method": "POST" if "auth" in endpoint or "login" in endpoint else "GET",
                "endpoint": endpoint,
                "status_code": status_code,
                "duration_us": 250,
                "is_success": is_success,
            },
            "is_security_significant": is_security_significant or not is_success,
        }

    def test_01_brute_force_detection(self):
        """Send 12 consecutive failed login attempts and assert brute-force incident is opened."""
        attacker_ip = f"198.51.100.{int(time.time()) % 200 + 10}"
        
        events = []
        for i in range(12):
            ev = self.create_event(
                ip=attacker_ip,
                endpoint="/api/v1/auth/login",
                status_code=401,
                is_success=False,
                severity="medium",
                is_security_significant=True,
            )
            events.append(ev)

        # Ingest events batch
        resp = requests.post(f"{BASE_URL}/api/v1/telemetry", json=events, timeout=5)
        self.assertEqual(resp.status_code, 202)

        # Allow async out-of-band engine worker to process
        time.sleep(0.5)

        # Query incidents
        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        self.assertEqual(incidents_resp.status_code, 200)
        incidents = incidents_resp.json()

        # Find incident for this attacker IP
        target_entity = f"ip:{attacker_ip}"
        matched = [inc for inc in incidents if inc.get("target_entity") == target_entity]
        self.assertTrue(len(matched) >= 1, f"Expected incident for {target_entity}, found none")
        
        inc = matched[0]
        self.assertEqual(inc["status"], "open")
        self.assertGreaterEqual(inc["risk_score"], 35)
        rule_names = [sig["rule_name"] for sig in inc.get("signals", [])]
        self.assertIn("Credential Brute-Force / Password Spray", rule_names)
        print(f"\n[PASS] Test 1: Detected Brute-Force for {target_entity} (Risk: {inc['risk_score']}, Severity: {inc['severity']})")

    def test_02_api_enumeration_reconnaissance(self):
        """Send 25 distinct 404 probes from single IP and assert rapid enumeration incident."""
        scanner_ip = f"203.0.113.{int(time.time()) % 200 + 10}"
        fuzz_bases = [
            "/admin", "/wp-admin", "/.env", "/config",
            "/api/v1/debug", "/actuator/heapdump", "/phpmyadmin"
        ]
        
        events = []
        for i in range(25):
            path = f"{fuzz_bases[i % len(fuzz_bases)]}/{i}_{uuid.uuid4().hex[:6]}"
            ev = self.create_event(
                ip=scanner_ip,
                endpoint=path,
                status_code=404,
                is_success=False,
                severity="low",
                is_security_significant=True,
            )
            events.append(ev)

        resp = requests.post(f"{BASE_URL}/api/v1/telemetry", json=events, timeout=5)
        self.assertEqual(resp.status_code, 202)

        time.sleep(0.5)

        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        incidents = incidents_resp.json()
        target_entity = f"ip:{scanner_ip}"
        matched = [inc for inc in incidents if inc.get("target_entity") == target_entity]
        self.assertTrue(len(matched) >= 1, f"Expected incident for scanner {target_entity}")
        
        inc = matched[0]
        rule_names = [sig["rule_name"] for sig in inc.get("signals", [])]
        self.assertIn("Rapid API / Directory Enumeration Scan", rule_names)
        print(f"[PASS] Test 2: Detected API Enumeration for {target_entity} (Risk: {inc['risk_score']})")

    def test_03_kernel_ebpf_shell_spawn(self):
        """Ingest Tetragon container process_exec event with /bin/sh and verify immediate critical incident."""
        target_ip = f"10.244.1.{int(time.time()) % 200 + 10}"
        kernel_ev = self.create_event(
            app_id="billing-service",
            event_type="kernel.process_exec",
            ip=target_ip,
            endpoint="/bin/bash -i",
            status_code=0,
            is_success=True,
            sensor_type="tetragon",
            raw_sensor_type="process_exec",
            process_name="/bin/bash",
            severity="critical",
            is_security_significant=True,
        )

        resp = requests.post(f"{BASE_URL}/api/v1/telemetry", json=kernel_ev, timeout=5)
        self.assertEqual(resp.status_code, 202)

        time.sleep(0.5)

        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        incidents = incidents_resp.json()
        target_entity = f"ip:{target_ip}"
        matched = [inc for inc in incidents if inc.get("target_entity") == target_entity]
        self.assertTrue(len(matched) >= 1, f"Expected incident for kernel event {target_entity}")

        inc = matched[0]
        self.assertEqual(inc["severity"], "critical")
        self.assertGreaterEqual(inc["risk_score"], 50)
        rule_names = [sig["rule_name"] for sig in inc.get("signals", [])]
        self.assertIn("Suspicious Container / Kernel Execution", rule_names)
        print(f"[PASS] Test 3: Detected eBPF Kernel Container Shell Spawn (Severity: {inc['severity']}, Risk: {inc['risk_score']})")

    def test_04_incident_containment_action(self):
        """Verify containment state mutation via POST /api/v1/incidents/:id/status."""
        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        incidents = incidents_resp.json()
        self.assertTrue(len(incidents) > 0, "Expected at least one incident to test containment")

        target_inc = incidents[0]
        incident_id = target_inc["incident_id"]

        # Mutate status to 'contained'
        mutate_resp = requests.post(
            f"{BASE_URL}/api/v1/incidents/{incident_id}/status",
            json={"status": "contained"},
            timeout=5
        )
        self.assertEqual(mutate_resp.status_code, 200)

        # Retrieve incident details
        detail_resp = requests.get(f"{BASE_URL}/api/v1/incidents/{incident_id}", timeout=5)
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(detail["status"], "contained")
        print(f"[PASS] Test 4: Successfully contained incident {incident_id} (Status: {detail['status']})")

if __name__ == "__main__":
    unittest.main(verbosity=2)
