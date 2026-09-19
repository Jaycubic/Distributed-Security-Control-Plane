#!/usr/bin/env python3
"""
Integration Test Suite: Phase 3 Identity Resolution & Multi-Application Correlation Engine
Tests:
1. Canonical Entity Resolution across IP, Session, User ID, and Applications.
2. In-Memory Context Graph and Subgraph query endpoints.
3. Multi-Stage Cross-Application Attack Progression Detection (Recon -> Lateral Move -> Exfil).
4. Deno-inspired Capability Context Inference and Tracking on Canonical Entities.
"""

import time
import uuid
import unittest
import requests

BASE_URL = "http://localhost:8080"

class TestPhase3CorrelationEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=2)
            if resp.status_code != 200:
                raise RuntimeError(f"Server returned status {resp.status_code}")
        except Exception as e:
            raise unittest.SkipTest(f"Security Control Plane not running on {BASE_URL}: {e}")

    def create_event(
        self,
        app_id="app-a",
        ip="198.51.100.10",
        session_id=None,
        user_id=None,
        endpoint="/api/v1/resource",
        method="GET",
        status_code=200,
        is_success=True,
        event_type="http_request",
        resource_id=None,
        resource_type=None,
    ):
        actor = {}
        if user_id:
            actor["user_id"] = user_id
        if session_id:
            actor["session_id"] = session_id

        resource = None
        if resource_id or resource_type:
            resource = {
                "resource_id": resource_id,
                "resource_type": resource_type,
            }

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "app_id": app_id,
            "environment": "production",
            "event_type": event_type,
            "severity": "low" if is_success else "medium",
            "actor": actor if actor else None,
            "source": {
                "ip": ip,
                "port": 49152,
                "user_agent": "IntegrationTestHarness/3.0",
                "sensor": {
                    "sensor_type": "agent",
                    "raw_event_type": "http",
                },
            },
            "action": {
                "method": method,
                "endpoint": endpoint,
                "status_code": status_code,
                "duration_us": 120,
                "is_success": is_success,
            },
            "resource": resource,
            "is_security_significant": not is_success,
        }

    def test_01_canonical_identity_resolution(self):
        """Link IP -> Session -> User across 2 distinct applications into a single CanonicalEntity."""
        test_ip = f"198.51.100.{int(time.time()) % 150 + 20}"
        test_session = f"sess_token_{uuid.uuid4().hex[:8]}"
        test_user = f"user_corp_{uuid.uuid4().hex[:6]}"

        # 1. First event: IP only on store-front
        ev1 = self.create_event(app_id="store-front", ip=test_ip, endpoint="/home")

        # 2. Second event: IP logs in and receives session token on store-front
        ev2 = self.create_event(
            app_id="store-front",
            ip=test_ip,
            session_id=test_session,
            endpoint="/api/v1/auth/login",
            event_type="auth.login",
        )

        # 3. Third event: Same session used from a different IP by user on billing-portal
        pivot_ip = f"203.0.113.{int(time.time()) % 150 + 20}"
        ev3 = self.create_event(
            app_id="billing-portal",
            ip=pivot_ip,
            session_id=test_session,
            user_id=test_user,
            endpoint="/api/v1/invoices",
        )

        resp = requests.post(f"{BASE_URL}/api/v1/telemetry", json=[ev1, ev2, ev3], timeout=5)
        self.assertEqual(resp.status_code, 202)

        time.sleep(0.5)

        # Query canonical entities
        entities_resp = requests.get(f"{BASE_URL}/api/v1/entities", timeout=5)
        self.assertEqual(entities_resp.status_code, 200)
        entities = entities_resp.json()

        # Find entity containing test_user
        matched = [e for e in entities if test_user in e.get("linked_user_ids", [])]
        self.assertTrue(len(matched) >= 1, f"Expected canonical entity linking user {test_user}")

        ent = matched[0]
        self.assertIn(test_session, ent["linked_sessions"])
        self.assertIn(test_ip, ent["linked_ips"])
        self.assertIn(pivot_ip, ent["linked_ips"])
        self.assertIn("store-front", ent["apps_seen"])
        self.assertIn("billing-portal", ent["apps_seen"])
        print(f"\n[PASS] Test 1: Canonical Entity Resolved: {ent['entity_id']} ({len(ent['linked_ips'])} IPs, {len(ent['apps_seen'])} Apps)")

    def test_02_context_graph_topology(self):
        """Verify In-Memory Context Graph exposes connected nodes and edges for apps, endpoints, and entities."""
        graph_resp = requests.get(f"{BASE_URL}/api/v1/correlation/graph", timeout=5)
        self.assertEqual(graph_resp.status_code, 200)
        graph = graph_resp.json()

        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreater(len(graph["nodes"]), 0, "Graph should contain nodes")
        self.assertGreater(len(graph["edges"]), 0, "Graph should contain edges")

        node_categories = {n["category"] for n in graph["nodes"]}
        self.assertIn("entity", node_categories)
        self.assertIn("application", node_categories)
        self.assertIn("endpoint", node_categories)
        print(f"[PASS] Test 2: In-Memory Context Graph active with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")

    def test_03_multi_stage_cross_application_attack_chain(self):
        """Simulate a 3-stage coordinated attack across 3 applications and assert Critical incident."""
        attacker_ip = f"198.51.100.{int(time.time()) % 100 + 100}"
        attacker_session = f"sess_attack_{uuid.uuid4().hex[:6]}"
        attacker_user = f"compromised_{uuid.uuid4().hex[:6]}"

        events = []

        # Stage 1: Reconnaissance / Probing on app-billing (401 failures)
        for i in range(3):
            events.append(self.create_event(
                app_id="app-billing",
                ip=attacker_ip,
                session_id=attacker_session,
                endpoint=f"/admin/v{i}",
                status_code=401,
                is_success=False,
            ))

        # Stage 2: Lateral transition to app-auth (successful request with session)
        events.append(self.create_event(
            app_id="app-auth",
            ip=attacker_ip,
            session_id=attacker_session,
            user_id=attacker_user,
            endpoint="/api/v1/profile",
            status_code=200,
            is_success=True,
        ))

        # Stage 3: High-impact mass export on app-crm
        events.append(self.create_event(
            app_id="app-crm",
            ip=attacker_ip,
            session_id=attacker_session,
            user_id=attacker_user,
            endpoint="/api/v1/records/export",
            event_type="data.export",
            status_code=200,
            is_success=True,
            resource_id="customer_vault",
            resource_type="database_table",
        ))

        resp = requests.post(f"{BASE_URL}/api/v1/telemetry", json=events, timeout=5)
        self.assertEqual(resp.status_code, 202)

        time.sleep(0.6)

        incidents_resp = requests.get(f"{BASE_URL}/api/v1/incidents", timeout=5)
        self.assertEqual(incidents_resp.status_code, 200)
        incidents = incidents_resp.json()

        # Check for Multi-Stage Cross-Application Attack Chain
        cross_app_incidents = [
            inc for inc in incidents
            if any(sig.get("rule_name") == "Multi-Stage Cross-Application Attack Chain" for sig in inc.get("signals", []))
        ]

        self.assertTrue(len(cross_app_incidents) >= 1, "Expected Multi-Stage Cross-Application Attack Chain incident")
        inc = cross_app_incidents[0]
        self.assertEqual(inc["severity"], "critical")
        self.assertGreaterEqual(inc["risk_score"], 75)
        self.assertEqual(inc["status"], "open")
        print(f"[PASS] Test 3: Detected Multi-Stage Cross-App Attack Chain! (Risk: {inc['risk_score']}, Severity: {inc['severity']})")

    def test_04_exercised_capability_tracking(self):
        """Verify Deno-style capability context (e.g. data.export, session.authenticate) is tracked on entities."""
        entities_resp = requests.get(f"{BASE_URL}/api/v1/entities", timeout=5)
        self.assertEqual(entities_resp.status_code, 200)
        entities = entities_resp.json()

        # Find entities with exercised capabilities
        entities_with_caps = [e for e in entities if len(e.get("exercised_capabilities", [])) > 0]
        self.assertTrue(len(entities_with_caps) >= 1, "Expected at least one entity with exercised capabilities")

        sample_ent = entities_with_caps[0]
        print(f"[PASS] Test 4: Capability context enriched on {sample_ent['entity_id']}: {sample_ent['exercised_capabilities']}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
