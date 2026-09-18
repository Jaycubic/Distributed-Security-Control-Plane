import asyncio
import time
import uuid
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityTelemetryEmitter:
    """
    Non-blocking, asynchronous security telemetry emitter.
    
    Hard Architectural Invariant:
    Normal application requests never block on telemetry transmission.
    Telemetry events are placed in an in-memory bounded queue and dispatched
    in batches by an independent background worker.
    """
    def __init__(
        self,
        app_id: str,
        environment: str = "production",
        control_plane_url: str = "http://localhost:8080/api/v1/telemetry",
        queue_max_size: int = 10_000,
        batch_size: int = 50,
        flush_interval_seconds: float = 0.5,
    ):
        self.app_id = app_id
        self.environment = environment
        self.control_plane_url = control_plane_url
        self.queue_max_size = queue_max_size
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_max_size)
        self.dropped_events_count = 0
        self._worker_task: Optional[asyncio.Task] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False

    async def start(self):
        self._running = True
        self._client = httpx.AsyncClient(timeout=2.0)
        self._worker_task = asyncio.create_task(self._flush_loop())

    async def stop(self):
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    def record_event_non_blocking(
        self,
        event_type: str,
        source_ip: Optional[str],
        method: str,
        endpoint: str,
        status_code: int,
        duration_us: int,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        role: Optional[str] = None,
        is_security_significant: bool = False,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Record a security event into the local queue in microsecond time.
        Non-blocking: if the queue is full, fails open and increments dropped counter.
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        event_payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp": now_utc,
            "app_id": self.app_id,
            "environment": self.environment,
            "event_type": event_type,
            "severity": "low" if not is_security_significant else "medium",
            "actor": {
                "user_id": user_id,
                "role": role,
                "session_id": session_id,
            } if (user_id or session_id or role) else None,
            "source": {
                "ip": source_ip,
                "sensor": {
                    "sensor_type": "agent",
                    "raw_event_type": "http_request",
                },
            },
            "action": {
                "method": method,
                "endpoint": endpoint,
                "status_code": status_code,
                "duration_us": duration_us,
                "is_success": status_code < 400,
            },
            "is_security_significant": is_security_significant,
            "metadata": extra_metadata or {},
        }
        
        try:
            self.queue.put_nowait(event_payload)
        except asyncio.QueueFull:
            self.dropped_events_count += 1

    async def _flush_loop(self):
        while self._running:
            batch = []
            try:
                # Wait for at least one item or timeout
                first_item = await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval_seconds)
                batch.append(first_item)
                self.queue.task_done()
                
                # Drain remaining available items up to batch size
                while len(batch) < self.batch_size and not self.queue.empty():
                    batch.append(self.queue.get_nowait())
                    self.queue.task_done()
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                break

            if batch:
                await self._send_batch(batch)

    async def _send_batch(self, batch: list):
        if not self._client:
            return
        try:
            # Send batch asynchronously to Control Plane ingestion API
            await self._client.post(self.control_plane_url, json=batch)
        except Exception:
            # Controller outage must NEVER degrade normal application flow
            pass


class SecurityControlPlaneMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, emitter: SecurityTelemetryEmitter):
        super().__init__(app)
        self.emitter = emitter

    async def dispatch(self, request: Request, call_next):
        t_start = time.perf_counter_ns()
        response: Response = await call_next(request)
        duration_us = (time.perf_counter_ns() - t_start) // 1000

        # Extract context
        client_ip = request.client.host if request.client else "unknown"
        user_id = request.headers.get("x-user-id")
        session_id = request.headers.get("x-session-id")
        
        # Check if route is security-significant (e.g. auth, admin, bulk data)
        path = request.url.path
        is_significant = (
            path.startswith("/auth") or
            path.startswith("/admin") or
            response.status_code in (401, 403)
        )

        # Microsecond non-blocking enqueue
        self.emitter.record_event_non_blocking(
            event_type="http.request",
            source_ip=client_ip,
            method=request.method,
            endpoint=path,
            status_code=response.status_code,
            duration_us=duration_us,
            user_id=user_id,
            session_id=session_id,
            is_security_significant=is_significant,
        )

        return response
