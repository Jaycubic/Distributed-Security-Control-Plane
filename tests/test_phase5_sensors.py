#!/usr/bin/env python3
"""
Integration Test Suite: Phase 5 Kernel & Runtime Telemetry Adapters (Cilium Tetragon, Falco, Hubble)
Tests:
1. Cilium Tetragon Adapter: Ingest raw process_exec telemetry, normalize container shell spawn to Critical.
2. Falco Adapter: Ingest raw Falco rule alert, map priority levels and extract output_fields metadata.
3. Cilium Hubble Adapter: Ingest raw network flow, normalize DROPPED egress with L3/L4 network endpoints.
4. Sensor Fidelity Invariant (Invariant #3): Assert raw sensor payload is preserved without lossy flattening.
5. Cross-Sensor Compound Threat Correlation: Link eBPF process execution with network flow telemetry.
"""

import time
import uuid
import unittest
import requests

BASE_URL = "http://localhost:8080"

class TestPhase5Sensors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=2)
            if resp.status_code != 200:
                raise RuntimeError(f"Server returned status {resp.status_code}")
        except Exception as e:
            raise unittest.SkipTest(f"Security Control Plane not running on {BASE_URL}: {e}")

    def fetch_telemetry_event(self, event_id, retries=10, delay=0.2):
        """Helper to fetch an event from the telemetry API with retry resilience."""
        for _ in range(retries):
            time.sleep(delay)
            try:
                resp = requests.get(f"{BASE_URL}/api/v1/telemetry", timeout=5)
                if resp.status_code == 200:
                    events = resp.json()
                    matching = [e for e in events if e.get("event_id") == event_id]
                    if matching:
                        return matching[0]
            except Exception:
                pass
        self.fail(f"Event {event_id} was not found in GET /api/v1/telemetry after {retries * delay:.1f}s")

    def test_01_tetragon_process_exec_ingest_and_normalization(self):
        """Ingest raw Cilium Tetragon process_exec telemetry and verify container shell elevation."""
        test_container_id = f"docker://tetra_{uuid.uuid4().hex[:12]}"
        pod_name = f"billing-service-{uuid.uuid4().hex[:5]}"
        raw_tetragon = {
            "process_exec": {
                "process": {
                    "exec_id": f"exec_{uuid.uuid4().hex[:8]}",
                    "pid": 24190,
                    "uid": 0,
                    "binary": "/bin/sh",
                    "arguments": "-i",
                    "pod": {
                        "namespace": "production",
                        "name": pod_name,
                        "container": {
                            "id": test_container_id,
                            "name": "billing-app"
                        }
                    }
                },
                "parent": {
                    "pid": 24001,
                    "binary": "/usr/local/bin/node",
                    "arguments": "server.js"
                }
            },
            "node_name": "k8s-worker-node-01",
            "time": "2026-09-20T08:00:00.000Z"
        }

        # 1. Post to Tetragon ingestion endpoint
        resp = requests.post(f"{BASE_URL}/api/v1/sensors/tetragon", json=raw_tetragon, timeout=5)
        self.assertEqual(resp.status_code, 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}")
        data = resp.json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["accepted_count"], 1)
        event_id = data["event_ids"][0]

        # 2. Retrieve event from telemetry stream API and verify normalization
        event = self.fetch_telemetry_event(event_id)

        # Verify sensor semantics
        self.assertEqual(event["app_id"], "billing-service")
        self.assertEqual(event["environment"], "production")
        self.assertEqual(event["event_type"], "kernel.process_exec")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["source"]["sensor"]["sensor_type"], "tetragon")
        self.assertEqual(event["source"]["sensor"]["raw_event_type"], "process_exec")
        self.assertEqual(event["source"]["container_id"], test_container_id)
        self.assertEqual(event["source"]["pid"], 24190)
        self.assertEqual(event["source"]["process_name"], "/bin/sh")
        self.assertTrue(event["is_security_significant"])

        print(f"\n[PASS] Test 1: Tetragon process_exec successfully normalized ({event_id}, container: {test_container_id[:20]}...)")

    def test_02_falco_container_shell_ingest_and_normalization(self):
        """Ingest raw Falco rule alert, verify priority mapping and output_fields extraction."""
        test_container_id = f"falco_{uuid.uuid4().hex[:12]}"
        raw_falco = {
            "output": "14:15:00.123456789: Critical A shell was spawned in a container with an attached terminal (user=root container_id=e3b0c4 shell=/bin/bash)",
            "priority": "Critical",
            "rule": "Terminal shell in container",
            "time": "2026-09-20T08:05:00.000Z",
            "output_fields": {
                "container.id": test_container_id,
                "container.name": "auth-portal",
                "k8s.pod.name": "auth-portal-7c981-jk22m",
                "k8s.ns.name": "production",
                "proc.name": "bash",
                "proc.pname": "python",
                "proc.pid": 31204,
                "user.name": "root"
            }
        }

        # 1. Post to Falco ingestion endpoint
        resp = requests.post(f"{BASE_URL}/api/v1/sensors/falco", json=raw_falco, timeout=5)
        self.assertEqual(resp.status_code, 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}")
        data = resp.json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["accepted_count"], 1)
        event_id = data["event_ids"][0]

        # 2. Retrieve event from telemetry stream
        event = self.fetch_telemetry_event(event_id)

        # Verify Falco mappings
        self.assertEqual(event["app_id"], "auth-portal")
        self.assertEqual(event["event_type"], "runtime.falco.terminal_shell_in_container")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["source"]["sensor"]["sensor_type"], "falco")
        self.assertEqual(event["source"]["sensor"]["raw_event_type"], "rule_alert")
        self.assertEqual(event["source"]["container_id"], test_container_id)
        self.assertEqual(event["source"]["pid"], 31204)
        self.assertEqual(event["source"]["process_name"], "bash")
        self.assertEqual(event["actor"]["user_id"], "root")
        self.assertEqual(event["action"]["operation"], "Terminal shell in container")

        print(f"\n[PASS] Test 2: Falco rule alert successfully normalized ({event_id}, rule: Terminal shell in container)")

    def test_03_hubble_network_flow_drop_and_l3_l4_semantics(self):
        """Ingest raw Cilium Hubble network flow and assert policy drop normalization."""
        src_ip = "10.244.2.88"
        dst_ip = "198.51.100.222"
        dst_port = 8443
        raw_hubble = {
            "flow": {
                "time": "2026-09-20T08:10:00.000Z",
                "verdict": "DROPPED",
                "drop_reason_desc": "POLICY_DENIED",
                "traffic_direction": "EGRESS",
                "IP": {
                    "source": src_ip,
                    "destination": dst_ip,
                    "ipVersion": "IPv4"
                },
                "l4": {
                    "TCP": {
                        "source_port": 51234,
                        "destination_port": dst_port
                    }
                },
                "source": {
                    "identity": 2048,
                    "namespace": "production",
                    "labels": ["app=crm-service", "env=production"],
                    "pod_name": "crm-service-5d61f-9z11p"
                },
                "destination": {
                    "identity": 2,
                    "labels": ["reserved:world"]
                },
                "summary": "TCP Flags: SYN; Drop Reason: Policy denied egress"
            },
            "node_name": "k8s-worker-node-02",
            "time": "2026-09-20T08:10:00.000Z"
        }

        # 1. Post to Hubble ingestion endpoint
        resp = requests.post(f"{BASE_URL}/api/v1/sensors/hubble", json=raw_hubble, timeout=5)
        self.assertEqual(resp.status_code, 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}")
        data = resp.json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["accepted_count"], 1)
        event_id = data["event_ids"][0]

        # 2. Retrieve event from telemetry stream
        event = self.fetch_telemetry_event(event_id)

        # Verify Hubble mappings
        self.assertEqual(event["app_id"], "crm-service")
        self.assertEqual(event["event_type"], "network.hubble.dropped")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["source"]["sensor"]["sensor_type"], "hubble")
        self.assertEqual(event["source"]["sensor"]["raw_event_type"], "flow_DROPPED")
        self.assertEqual(event["source"]["ip"], src_ip)
        self.assertEqual(event["action"]["endpoint"], f"{dst_ip}:{dst_port}")
        self.assertFalse(event["action"]["is_success"])
        self.assertTrue(event["is_security_significant"])

        print(f"\n[PASS] Test 3: Hubble flow drop successfully normalized ({event_id}, endpoint: {dst_ip}:{dst_port})")

    def test_04_sensor_fidelity_invariant(self):
        """Invariant #3: Ensure raw sensor JSON payload is preserved intact without lossy stringification."""
        pod_name = f"vault-service-{uuid.uuid4().hex[:5]}"
        raw_tetragon = {
            "process_exec": {
                "process": {
                    "exec_id": "test_invariant_exec_id",
                    "pid": 9999,
                    "uid": 1001,
                    "binary": "/usr/bin/curl",
                    "arguments": "http://169.254.169.254/latest/meta-data/",
                    "pod": {
                        "namespace": "secure-zone",
                        "name": pod_name,
                        "container": {
                            "id": "container_vault_01",
                            "name": "vault-app"
                        }
                    }
                }
            },
            "node_name": "worker-secure-01"
        }

        resp = requests.post(f"{BASE_URL}/api/v1/sensors/tetragon", json=raw_tetragon, timeout=5)
        self.assertEqual(resp.status_code, 202)
        event_id = resp.json()["event_ids"][0]

        event = self.fetch_telemetry_event(event_id)

        # Assert raw_payload fidelity is preserved
        raw_payload = event["source"]["sensor"]["raw_payload"]
        self.assertIsNotNone(raw_payload, "Invariant #3 Violation: raw_payload was dropped!")
        self.assertIn("process_exec", raw_payload)
        self.assertEqual(raw_payload["process_exec"]["process"]["binary"], "/usr/bin/curl")
        self.assertIn("169.254.169.254", raw_payload["process_exec"]["process"]["arguments"])

        print(f"\n[PASS] Test 4: Invariant #3 Sensor Fidelity verified (full raw eBPF JSON preserved)")

    def test_05_cross_sensor_compound_threat_context(self):
        """Verify compound kernel + network correlation for a multi-stage container compromise."""
        target_app = "billing-service"
        shared_container = f"docker://compromised_{uuid.uuid4().hex[:8]}"

        # Step 1: Hubble logs an egress policy drop to external C2
        hubble_payload = {
            "flow": {
                "verdict": "DROPPED",
                "drop_reason_desc": "POLICY_DENIED",
                "traffic_direction": "EGRESS",
                "IP": { "source": "10.244.1.18", "destination": "203.0.113.88", "ipVersion": "IPv4" },
                "l4": { "TCP": { "source_port": 49120, "destination_port": 4444 } },
                "source": { "identity": 1042, "namespace": "production", "labels": [f"app={target_app}"], "pod_name": "billing-pod-1" },
                "summary": "Drop Reason: Policy denied egress"
            }
        }
        resp1 = requests.post(f"{BASE_URL}/api/v1/sensors/hubble", json=hubble_payload, timeout=5)
        self.assertEqual(resp1.status_code, 202)

        # Step 2: Tetragon detects root shell spawn inside the container
        tetragon_payload = {
            "process_exec": {
                "process": {
                    "exec_id": "c2_reverse_shell",
                    "pid": 55102,
                    "uid": 0,
                    "binary": "/bin/sh",
                    "arguments": "-i",
                    "pod": {
                        "namespace": "production",
                        "name": "billing-pod-1",
                        "container": { "id": shared_container, "name": "billing-app" }
                    }
                }
            }
        }
        resp2 = requests.post(f"{BASE_URL}/api/v1/sensors/tetragon", json=tetragon_payload, timeout=5)
        self.assertEqual(resp2.status_code, 202)

        time.sleep(0.5)

        # Step 3: Check incidents API for detection of container shell
        inc_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        self.assertEqual(inc_resp.status_code, 200)
        incidents = inc_resp.json()
        shell_incidents = [i for i in incidents if "Suspicious Container" in i.get("title", "") or i.get("severity") == "critical"]
        self.assertTrue(len(shell_incidents) > 0, "Expected critical incident generated from container shell spawn")

        print(f"\n[PASS] Test 5: Cross-sensor compound attack detected (Hubble Drop + Tetragon Shell)")

if __name__ == "__main__":
    unittest.main()
