"""Phase 10 packet inspection API checks. Start Corvus before running."""

import json
import time
import urllib.request


BASE = "http://localhost:8080"


def post_packet(transport, source_port, payload):
    body = {
        "transport": transport,
        "source_ip": "192.0.2.91",
        "source_port": source_port,
        "payload": list(payload),
    }
    request = urllib.request.Request(
        BASE + "/api/v1/sensors/packet-inspector",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read())


def test_http_path_traversal_is_ingested():
    payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n"
    status, result = post_packet("tcp", 52341, payload)
    assert status == 202, result
    assert "event_id" in result

    deadline = time.time() + 3
    while time.time() < deadline:
        with urllib.request.urlopen(BASE + "/api/v1/incidents", timeout=5) as response:
            incidents = json.loads(response.read())
        if any("HTTP Request Anomaly" in item.get("title", "") for item in incidents):
            break
        time.sleep(0.05)
    assert any("HTTP Request Anomaly" in item.get("title", "") for item in incidents)


if __name__ == "__main__":
    test_http_path_traversal_is_ingested()
    print("PASS Phase 10 packet inspection integration")
