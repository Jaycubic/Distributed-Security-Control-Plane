#!/usr/bin/env python3
"""
Integration Test Suite: Phase 4 Deno-Inspired Capability Policy Engine & Graduated Containment System
Tests:
1. Declarative Policy Bundles & Evaluation: Hard Invariant (DENY strictly overrides ALLOW).
2. Mode C Dry-Run Policy Simulation: Prospective decisions without state mutation.
3. Cryptographically Signed Control Channel: Ed25519 signature and public key validation.
4. Reversible Graduated Containment: Active command tracking and explicit operator rollback.
5. Surgical Capability Revocation: REVOKE_CAPABILITY targeted containment preserving other operations.
"""

import time
import uuid
import unittest
import requests

BASE_URL = "http://localhost:8080"

class TestPhase4ContainmentEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=2)
            if resp.status_code != 200:
                raise RuntimeError(f"Server returned status {resp.status_code}")
        except Exception as e:
            raise unittest.SkipTest(f"Security Control Plane not running on {BASE_URL}: {e}")

    def test_01_capability_policy_crud_and_precedence(self):
        """Deploy declarative policy and assert the core invariant: DENY strictly takes precedence over ALLOW."""
        policy_id = f"test-billing-policy-{uuid.uuid4().hex[:6]}"
        bundle = {
            "policy_id": policy_id,
            "version": 1,
            "target_app": "billing-service",
            "description": "Integration test policy with allow/deny conflict",
            "allow": [
                {
                    "capability": "database.read",
                    "scope": "/app/data/**",
                    "description": "Allow general app data read"
                },
                {
                    "capability": "network.connect",
                    "scope": "*.internal:*",
                    "description": "Allow internal network connections"
                }
            ],
            "deny": [
                {
                    "capability": "database.read",
                    "scope": "/app/data/restricted/**",
                    "description": "Deny sensitive database read (precedence over allow)"
                },
                {
                    "capability": "process.execute",
                    "scope": "/bin/sh",
                    "description": "Deny shell execution"
                }
            ],
            "default_allow": False
        }

        # 1. Create policy bundle
        create_resp = requests.post(f"{BASE_URL}/api/v1/policies", json=bundle, timeout=5)
        self.assertEqual(create_resp.status_code, 201)

        # 2. Evaluate allowed data path -> should ALLOW
        eval_allow = requests.post(
            f"{BASE_URL}/api/v1/policies/evaluate",
            json={
                "app_id": "billing-service",
                "who": "user_finance",
                "capability": "database.read",
                "target_resource": "/app/data/invoices/2026",
            },
            timeout=5
        )
        self.assertEqual(eval_allow.status_code, 200)
        dec_allow = eval_allow.json()
        self.assertEqual(dec_allow["decision"], "allow")

        # 3. Evaluate conflicting path -> MUST DENY because DENY strictly overrides ALLOW
        eval_deny = requests.post(
            f"{BASE_URL}/api/v1/policies/evaluate",
            json={
                "app_id": "billing-service",
                "who": "user_finance",
                "capability": "database.read",
                "target_resource": "/app/data/restricted/salaries",
            },
            timeout=5
        )
        self.assertEqual(eval_deny.status_code, 200)
        dec_deny = eval_deny.json()
        self.assertEqual(dec_deny["decision"], "deny")
        self.assertIn("precedence over allow", dec_deny["reason"].lower())

        print(f"\n[PASS] Test 1: Policy Invariant Verified: DENY overrides ALLOW on {policy_id}")

    def test_02_mode_c_policy_simulation(self):
        """Evaluate events in Mode C simulation mode without state mutation."""
        sim_payload = {
            "app_id": "any-app",
            "who": "operator_alice",
            "capability": "process.execute",
            "target_resource": "/bin/sh",
        }

        sim_resp = requests.post(f"{BASE_URL}/api/v1/policies/simulate", json=sim_payload, timeout=5)
        self.assertEqual(sim_resp.status_code, 200)
        dec = sim_resp.json()

        self.assertTrue(dec["is_simulation"])
        self.assertEqual(dec["decision"], "deny")
        self.assertIsNotNone(dec["matched_rule"])
        print(f"[PASS] Test 2: Mode C Policy Simulation Verified (decision={dec['decision']}, rule={dec['matched_rule']})")

    def test_03_ed25519_signed_containment_dispatch(self):
        """Dispatch Ed25519-signed containment command and verify signature formatting and public key."""
        # 1. Fetch public key
        pk_resp = requests.get(f"{BASE_URL}/api/v1/containment/public-key", timeout=5)
        self.assertEqual(pk_resp.status_code, 200)
        pk_data = pk_resp.json()
        self.assertEqual(pk_data["algorithm"], "Ed25519")
        self.assertEqual(len(pk_data["public_key"]), 64)  # 32 bytes in hex = 64 chars

        # 2. Dispatch signed containment command
        target_session = f"session:sess_malicious_{uuid.uuid4().hex[:6]}"
        dispatch_payload = {
            "action": "REVOKE_SESSION",
            "target_entity": target_session,
            "ttl_seconds": 300,
            "rollback_recipe": "REINSTATE_SESSION_REDIS_SET"
        }

        disp_resp = requests.post(f"{BASE_URL}/api/v1/containment/dispatch", json=dispatch_payload, timeout=5)
        self.assertEqual(disp_resp.status_code, 201)
        cmd = disp_resp.json()

        self.assertEqual(cmd["action"], "REVOKE_SESSION")
        self.assertEqual(cmd["target_entity"], target_session)
        self.assertEqual(cmd["status"], "active")
        self.assertEqual(len(cmd["signature"]), 128)  # 64-byte Ed25519 signature in hex = 128 chars
        self.assertEqual(cmd["signer_public_key"], pk_data["public_key"])
        print(f"[PASS] Test 3: Ed25519 Signed Command Dispatched! (ID: {cmd['command_id'][:8]}..., Sig: {cmd['signature'][:16]}...)")

    def test_04_reversibility_and_rollback(self):
        """Verify dynamic TTL tracking and manual rollback of containment commands."""
        target_ip = f"ip:198.51.100.{int(time.time()) % 150 + 50}"
        disp_resp = requests.post(
            f"{BASE_URL}/api/v1/containment/dispatch",
            json={
                "action": "BLOCK_NETWORK",
                "target_entity": target_ip,
                "ttl_seconds": 600,
                "rollback_recipe": "IPTABLES_DELETE_RULE"
            },
            timeout=5
        )
        self.assertEqual(disp_resp.status_code, 201)
        cmd = disp_resp.json()
        cmd_id = cmd["command_id"]

        # Check in active commands
        active_resp = requests.get(f"{BASE_URL}/api/v1/containment/commands?active_only=true", timeout=5)
        self.assertEqual(active_resp.status_code, 200)
        active_cmds = active_resp.json()
        self.assertTrue(any(c["command_id"] == cmd_id for c in active_cmds))

        # Rollback command
        rb_resp = requests.post(
            f"{BASE_URL}/api/v1/containment/{cmd_id}/rollback",
            json={"reason": "Integration test verified false positive rollback"},
            timeout=5
        )
        self.assertEqual(rb_resp.status_code, 200)
        rolled_back = rb_resp.json()
        self.assertEqual(rolled_back["status"], "rolled_back")

        # Verify no longer active
        active_after = requests.get(f"{BASE_URL}/api/v1/containment/commands?active_only=true", timeout=5)
        self.assertFalse(any(c["command_id"] == cmd_id for c in active_after.json()))
        print(f"[PASS] Test 4: Reversible Containment Verified (Command {cmd_id[:8]}... rolled back)")

    def test_05_graduated_capability_revocation(self):
        """Verify surgical REVOKE_CAPABILITY revokes specific capability while leaving normal operations intact."""
        target_actor = f"entity:attacker_{uuid.uuid4().hex[:6]}"

        # 1. Dispatch surgical REVOKE_CAPABILITY on data.export
        disp_resp = requests.post(
            f"{BASE_URL}/api/v1/containment/dispatch",
            json={
                "action": "REVOKE_CAPABILITY",
                "target_entity": target_actor,
                "capability": "data.export",
                "ttl_seconds": 300,
                "rollback_recipe": "RESTORE_ENTITY_CAPABILITY"
            },
            timeout=5
        )
        self.assertEqual(disp_resp.status_code, 201)

        # 2. Evaluate data.export -> should be REVOKED due to active containment
        eval_export = requests.post(
            f"{BASE_URL}/api/v1/policies/evaluate",
            json={
                "app_id": "*",
                "who": target_actor,
                "actor_entity": target_actor,
                "capability": "data.export",
                "target_resource": "customer_vault",
            },
            timeout=5
        )
        self.assertEqual(eval_export.status_code, 200)
        dec_export = eval_export.json()
        self.assertEqual(dec_export["decision"], "revoke")
        self.assertIn("active signed containment", dec_export["reason"])

        # 3. Evaluate session.authenticate for the same entity -> should be ALLOWED!
        eval_auth = requests.post(
            f"{BASE_URL}/api/v1/policies/evaluate",
            json={
                "app_id": "*",
                "who": target_actor,
                "actor_entity": target_actor,
                "capability": "session.authenticate",
                "target_resource": "/api/v1/login",
            },
            timeout=5
        )
        self.assertEqual(eval_auth.status_code, 200)
        dec_auth = eval_auth.json()
        self.assertEqual(dec_auth["decision"], "allow")
        print(f"[PASS] Test 5: Graduated Containment Verified: data.export REVOKED, session.authenticate ALLOWED for {target_actor}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
