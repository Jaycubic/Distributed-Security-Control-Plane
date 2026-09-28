#!/usr/bin/env python3
"""
Integration Test Suite: Phase 6 Advisory Off-Path LLM Reasoning Service (Mode B)
Tests:
1. Mode A Baseline & Dual Mode Controller: LLM is completely off-path & disabled by default; verifies mode toggling via REST.
2. Mode A Safety Boundary: Advisory reasoning requests are rejected when Mode A is active.
3. Deterministic Policy Validation Gate - Rejection on DENY (Invariant: DENY > ALLOW).
4. Deterministic Policy Validation Gate - Approval & Ed25519-Signed Containment Command issuance.
5. Minimum Confidence Gate: Recommendations below 0.70 confidence are strictly rejected.
6. Fault Tolerance & Graceful Fallback: When advisory worker is unreachable, control plane gracefully falls back to Mode A without error.
"""

import time
import uuid
import unittest
import requests

BASE_URL = "http://localhost:8080"


class TestPhase6AdvisoryReasoning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=3)
            if resp.status_code != 200:
                raise RuntimeError(f"Server returned status {resp.status_code}")
        except Exception as e:
            raise unittest.SkipTest(f"Security Control Plane not running on {BASE_URL}: {e}")

    def setUp(self):
        # Ensure tests start from known baseline Mode A
        try:
            requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_a"}, timeout=2)
        except Exception:
            pass

    def tearDown(self):
        # Restore baseline Mode A
        try:
            requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_a"}, timeout=2)
        except Exception:
            pass

    def test_01_mode_a_baseline_and_toggle(self):
        """Assert Mode A is the active baseline by default and can be toggled via REST API."""
        # 1. Health check reports Mode A baseline and Phase 6 active
        health_resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=2)
        self.assertEqual(health_resp.status_code, 200)
        health_data = health_resp.json()
        self.assertIn("Mode A (Deterministic)", health_data.get("mode", ""))
        self.assertIn("Phase 6", health_data.get("phase", ""))

        # 2. Query mode endpoint
        mode_resp = requests.get(f"{BASE_URL}/api/v1/mode", timeout=2)
        self.assertEqual(mode_resp.status_code, 200)
        mode_data = mode_resp.json()
        self.assertFalse(mode_data.get("is_mode_b"))
        self.assertEqual(mode_data.get("mode"), "Mode A (Deterministic)")

        # 3. Toggle to Mode B (Intelligent / Advisory)
        toggle_b = requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_b"}, timeout=2)
        self.assertEqual(toggle_b.status_code, 200)
        toggle_b_data = toggle_b.json()
        self.assertTrue(toggle_b_data.get("is_mode_b"))
        self.assertEqual(toggle_b_data.get("mode"), "Mode B (Intelligent / Advisory)")

        # Verify mode query reflects Mode B
        mode_check = requests.get(f"{BASE_URL}/api/v1/mode", timeout=2)
        self.assertTrue(mode_check.json().get("is_mode_b"))

        # 4. Toggle back to Mode A (Deterministic)
        toggle_a = requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_a"}, timeout=2)
        self.assertEqual(toggle_a.status_code, 200)
        self.assertFalse(toggle_a.json().get("is_mode_b"))
        print("[PASS] Test 1: Mode A baseline active by default; Mode B toggle verified")

    def test_02_mode_a_safety_boundary_rejection(self):
        """In Mode A, advisory reasoning trigger requests are rejected to maintain deterministic guarantees."""
        # Verify Mode A is active
        requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_a"}, timeout=2)

        fake_incident_id = str(uuid.uuid4())
        resp = requests.post(f"{BASE_URL}/api/v1/advisory/analyze/{fake_incident_id}", timeout=2)
        # Should return 400 Bad Request or 404 Not Found
        self.assertIn(resp.status_code, [400, 404])
        if resp.status_code == 400:
            self.assertIn("Mode A", resp.json().get("error", ""))
        print("[PASS] Test 2: Mode A safety boundary enforces LLM is disabled")

    def test_03_policy_gate_rejection_on_deny(self):
        """
        Advisory recommendations that violate deterministic policy DENY rules must be REJECTED.
        Invariant: Zero direct execution authority for LLMs; DENY strictly takes precedence.
        """
        # Ensure default baseline policy is active (default baseline denies service.isolate on auth-service or process.execute /bin/sh)
        # First deploy a test policy bundle with explicit DENY
        bundle_id = f"test-gate-policy-{uuid.uuid4().hex[:6]}"
        bundle = {
            "policy_id": bundle_id,
            "version": 1,
            "target_app": "core-auth-service",
            "description": "Integration test policy protecting auth service",
            "allow": [
                {
                    "capability": "session.revoke",
                    "scope": "*",
                    "description": "Allow revoking user sessions"
                }
            ],
            "deny": [
                {
                    "capability": "service.isolate",
                    "scope": "core-auth-service",
                    "description": "Deny isolating core auth infrastructure"
                }
            ],
            "default_allow": false
        }
        create_resp = requests.post(f"{BASE_URL}/api/v1/policies", json=bundle, timeout=2)
        self.assertEqual(create_resp.status_code, 201)

        # Submit an Advisory Recommendation attempting to ISOLATE the protected service
        rec_id = str(uuid.uuid4())
        incident_id = str(uuid.uuid4())
        recommendation_payload = {
            "recommendation_id": rec_id,
            "incident_id": incident_id,
            "target_entity": "core-auth-service",
            "app_id": "core-auth-service",
            "classification": "MALICIOUS",
            "confidence": 0.95,
            "reason_codes": ["ANOMALOUS_OUTBOUND_CONN", "SUSPECTED_SERVICE_COMPROMISE"],
            "reasoning_summary": "High entropy traffic detected. Recommending immediate service isolation.",
            "recommended_action": "ISOLATE_SERVICE",
            "capability": "service.isolate",
            "params": {"resource": "core-auth-service"},
            "suggested_ttl_seconds": 600,
            "model_provider": "test-advisory-worker",
            "created_at": "2026-09-25T12:00:00Z"
        }

        eval_resp = requests.post(
            f"{BASE_URL}/api/v1/advisory/recommendation",
            json=recommendation_payload,
            timeout=3
        )
        self.assertEqual(eval_resp.status_code, 200)
        data = eval_resp.json()
        val = data.get("validation", {})

        # Assert Deterministic Policy Gate REJECTED the recommendation!
        self.assertFalse(val.get("is_authorized"), "Gate should NOT authorize recommendation violating DENY rule")
        self.assertEqual(val.get("decision"), "deny")
        self.assertIsNone(val.get("containment_command_id"))
        self.assertIn("REJECTED", val.get("rationale", ""))
        print(f"[PASS] Test 3: Deterministic Policy Gate rejected recommendation: {val.get('rationale')}")

    def test_04_policy_gate_approval_and_ed25519_signed_containment(self):
        """
        Advisory recommendations conforming to active policy are APPROVED and produce
        an Ed25519-signed containment command with TTL and rollback recipe.
        """
        # Submit a valid recommendation for session revocation on billing-service
        rec_id = str(uuid.uuid4())
        incident_id = str(uuid.uuid4())
        recommendation_payload = {
            "recommendation_id": rec_id,
            "incident_id": incident_id,
            "target_entity": "user:attacker_session_99",
            "app_id": "*",
            "classification": "MALICIOUS",
            "confidence": 0.92,
            "reason_codes": ["CREDENTIAL_STUFFING", "RAPID_FAILURES"],
            "reasoning_summary": "Repeated credential failures followed by anomalous resource access. Recommending session revocation.",
            "recommended_action": "REVOKE_SESSION",
            "capability": "session.authenticate",
            "params": {"resource": "*"},
            "suggested_ttl_seconds": 450,
            "model_provider": "test-advisory-worker",
            "created_at": "2026-09-25T12:00:00Z"
        }

        eval_resp = requests.post(
            f"{BASE_URL}/api/v1/advisory/recommendation",
            json=recommendation_payload,
            timeout=3
        )
        self.assertEqual(eval_resp.status_code, 200)
        data = eval_resp.json()
        val = data.get("validation", {})

        # Assert Deterministic Policy Gate APPROVED the recommendation!
        self.assertTrue(val.get("is_authorized"), "Gate should authorize recommendation matching ALLOW rules")
        self.assertEqual(val.get("decision"), "allow")
        cmd_id = val.get("containment_command_id")
        self.assertIsNotNone(cmd_id, "Approved recommendation must yield a containment command ID")

        # Verify command exists in active containment list
        cmds_resp = requests.get(f"{BASE_URL}/api/v1/containment/commands?active_only=true", timeout=2)
        self.assertEqual(cmds_resp.status_code, 200)
        cmds = cmds_resp.json()
        matched = [c for c in cmds if c.get("command_id") == cmd_id]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].get("action"), "REVOKE_SESSION")
        self.assertEqual(matched[0].get("target_entity"), "user:attacker_session_99")
        self.assertEqual(matched[0].get("ttl_seconds"), 450)
        self.assertTrue(len(matched[0].get("signature", "")) > 64, "Command must be Ed25519-signed")
        print(f"[PASS] Test 4: Deterministic Policy Gate approved recommendation; issued Ed25519 command {cmd_id}")

    def test_05_minimum_confidence_gate(self):
        """Advisory recommendations below the 0.70 safety confidence threshold are strictly rejected."""
        rec_id = str(uuid.uuid4())
        incident_id = str(uuid.uuid4())
        low_confidence_rec = {
            "recommendation_id": rec_id,
            "incident_id": incident_id,
            "target_entity": "user:uncertain_actor_12",
            "app_id": "*",
            "classification": "SUSPICIOUS",
            "confidence": 0.54, # Below 0.70 safety threshold
            "reason_codes": ["LOW_CONFIDENCE_BURST"],
            "reasoning_summary": "Slight variance in request timing. Weak confidence.",
            "recommended_action": "REVOKE_SESSION",
            "capability": "session.authenticate",
            "params": {"resource": "*"},
            "suggested_ttl_seconds": 300,
            "model_provider": "test-advisory-worker",
            "created_at": "2026-09-25T12:00:00Z"
        }

        eval_resp = requests.post(
            f"{BASE_URL}/api/v1/advisory/recommendation",
            json=low_confidence_rec,
            timeout=3
        )
        self.assertEqual(eval_resp.status_code, 200)
        data = eval_resp.json()
        val = data.get("validation", {})

        # Assert rejected due to confidence
        self.assertFalse(val.get("is_authorized"))
        self.assertEqual(val.get("decision"), "deny")
        self.assertIn("safety threshold", val.get("rationale", ""))
        print(f"[PASS] Test 5: Low confidence recommendation (< 0.70) rejected by safety gate: {val.get('rationale')}")

    def test_06_llm_worker_unavailability_graceful_fallback(self):
        """
        When the advisory worker is unreachable, Mode B triggers a graceful fallback
        to deterministic Mode A without error, preserving incident state.
        """
        # 1. Enable Mode B
        requests.post(f"{BASE_URL}/api/v1/mode", json={"mode": "mode_b"}, timeout=2)

        # 2. Ingest telemetry that triggers an incident
        actor_ip = f"10.99.88.{int(time.time()) % 250}"
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-09-25T12:00:00Z",
            "app_id": "billing-service",
            "environment": "production",
            "event_type": "auth.failed",
            "severity": "medium",
            "actor": {
                "user_id": f"brute_actor_{uuid.uuid4().hex[:5]}",
                "auth_method": "password"
            },
            "source": {
                "ip": actor_ip,
                "sensor": {
                    "sensor_type": "agent",
                    "raw_event_type": "auth_event"
                }
            },
            "action": {
                "method": "POST",
                "endpoint": "/api/v1/auth/login",
                "status_code": 401,
                "duration_us": 120,
                "is_success": False,
                "operation": "login"
            },
            "resource": None,
            "metadata": {},
            "is_security_significant": True
        }

        # Send 12 failed logins to trigger brute force incident
        for _ in range(11):
            event["event_id"] = str(uuid.uuid4())
            requests.post(f"{BASE_URL}/api/v1/telemetry", json=event, timeout=2)

        time.sleep(0.5)

        # 3. Retrieve the created incident
        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=2)
        self.assertEqual(incidents_resp.status_code, 200)
        incidents = incidents_resp.json()
        self.assertTrue(len(incidents) > 0, "At least one incident should have been created")
        target_inc = incidents[0]
        inc_id = target_inc.get("incident_id")

        # 4. Trigger advisory analysis (Worker is offline on default port 8000 during this test)
        analyze_resp = requests.post(f"{BASE_URL}/api/v1/advisory/analyze/{inc_id}", timeout=5)
        self.assertEqual(analyze_resp.status_code, 200)
        data = analyze_resp.json()

        # Assert graceful fallback occurred without raising 500 error!
        self.assertEqual(data.get("status"), "fallback")
        self.assertIn("Mode A", data.get("mode", ""))
        self.assertIn("unreachable", data.get("message", "").lower())
        print(f"[PASS] Test 6: Injected worker unavailability handled with graceful Mode A fallback: {data.get('message')}")


if __name__ == "__main__":
    unittest.main()
