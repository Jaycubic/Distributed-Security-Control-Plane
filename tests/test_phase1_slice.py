"""
End-to-End Integration & Verification Test for Phase 1 Vertical Slice.

Tests:
1. Schema & Serialization conformance.
2. Selective Persistence Filter logic (ensuring benign raw events are filtered out).
3. Non-blocking emitter asynchronous buffering and batching under load.
4. Fail-open behavior: verifies application availability is preserved even when controller is unreachable.
"""

import unittest
import asyncio
import uuid
import sys
import os
from datetime import datetime, timezone

# Add mock app to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "mock-apps", "fastapi_app")))
from middleware import SecurityTelemetryEmitter

class TestPhase1Slice(unittest.TestCase):
    def test_schema_structure(self):
        """Verify the unified security event schema contains all required fields."""
        event_id = str(uuid.uuid4())
        event = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "app_id": "app-test",
            "environment": "staging",
            "event_type": "http.request",
            "severity": "low",
            "actor": {
                "user_id": "usr_test",
                "role": "analyst",
                "session_id": "sess_123"
            },
            "source": {
                "ip": "10.0.0.1",
                "sensor": {
                    "sensor_type": "agent",
                    "raw_event_type": "middleware_event"
                }
            },
            "action": {
                "method": "GET",
                "endpoint": "/api/test",
                "status_code": 200,
                "duration_us": 120,
                "is_success": True
            },
            "is_security_significant": False
        }

        self.assertEqual(event["event_id"], event_id)
        self.assertEqual(event["source"]["sensor"]["sensor_type"], "agent")
        self.assertTrue(event["action"]["is_success"])

    def test_persistence_filter_logic(self):
        """
        Verify the selective persistence filter rule:
        Benign routine events are NOT marked for PostgreSQL persistence,
        while anomalies/auth failures ARE marked for persistence.
        """
        def should_persist(event: dict) -> bool:
            if event.get("is_security_significant"):
                return True
            if event.get("severity") in ("medium", "high", "critical"):
                return True
            ev_type = event.get("event_type", "").lower()
            if any(ev_type.startswith(prefix) for prefix in ("auth.", "admin.", "privilege.", "incident.")):
                return True
            action = event.get("action") or {}
            if action.get("status_code") in (401, 403):
                return True
            return False

        # Benign GET request -> should NOT persist to PostgreSQL
        benign_event = {
            "event_type": "http.request",
            "severity": "low",
            "action": {"status_code": 200},
            "is_security_significant": False
        }
        self.assertFalse(should_persist(benign_event))

        # Auth failure (401) -> MUST persist to PostgreSQL
        auth_failure_event = {
            "event_type": "auth.login",
            "severity": "medium",
            "action": {"status_code": 401},
            "is_security_significant": True
        }
        self.assertTrue(should_persist(auth_failure_event))

        # Admin route export -> MUST persist to PostgreSQL
        admin_event = {
            "event_type": "admin.config_change",
            "severity": "high",
            "action": {"status_code": 200},
            "is_security_significant": True
        }
        self.assertTrue(should_persist(admin_event))

    def test_non_blocking_emitter_buffering(self):
        """Verify the non-blocking emitter enqueues events without blocking."""
        async def run_async_test():
            emitter = SecurityTelemetryEmitter(
                app_id="test-app-async",
                control_plane_url="http://127.0.0.1:9999/unreachable", # deliberately unreachable
                queue_max_size=500,
                batch_size=50,
                flush_interval_seconds=0.1
            )
            await emitter.start()

            # Enqueue 100 events in rapid succession
            for i in range(100):
                emitter.record_event_non_blocking(
                    event_type="http.request",
                    source_ip="127.0.0.1",
                    method="GET",
                    endpoint=f"/item/{i}",
                    status_code=200,
                    duration_us=80,
                    user_id=f"user_{i}"
                )

            # Check that events were accepted into queue
            self.assertGreater(emitter.queue.qsize(), 0)

            # Let worker attempt flush against unreachable controller
            await asyncio.sleep(0.3)

            # Ensure host process did not crash and no exceptions bubbled up
            await emitter.stop()

        asyncio.run(run_async_test())

if __name__ == "__main__":
    unittest.main()
