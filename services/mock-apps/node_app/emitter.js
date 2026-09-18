const crypto = require('crypto');
const http = require('http');

/**
 * Non-blocking, asynchronous security telemetry emitter for Node.js.
 * 
 * Hard Invariant: Requests never await telemetry transmission.
 */
class SecurityTelemetryEmitter {
  constructor(options = {}) {
    this.appId = options.appId || 'application-b-api';
    this.environment = options.environment || 'production';
    this.controlPlaneUrl = options.controlPlaneUrl || 'http://localhost:8080/api/v1/telemetry';
    this.queueMaxSize = options.queueMaxSize || 10000;
    this.batchSize = options.batchSize || 50;
    this.flushIntervalMs = options.flushIntervalMs || 500;

    this.queue = [];
    this.droppedEvents = 0;
    this.flushTimer = null;
  }

  start() {
    this.flushTimer = setInterval(() => this.flush(), this.flushIntervalMs);
  }

  stop() {
    if (this.flushTimer) clearInterval(this.flushTimer);
    this.flush();
  }

  recordEventNonBlocking(eventData) {
    if (this.queue.length >= this.queueMaxSize) {
      this.droppedEvents++;
      return; // Fail open
    }

    const event = {
      event_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      app_id: this.appId,
      environment: this.environment,
      event_type: eventData.eventType || 'http.request',
      severity: eventData.isSecuritySignificant ? 'medium' : 'low',
      actor: (eventData.userId || eventData.sessionId) ? {
        user_id: eventData.userId,
        session_id: eventData.sessionId,
        role: eventData.role
      } : undefined,
      source: {
        ip: eventData.ip,
        sensor: {
          sensor_type: 'agent',
          raw_event_type: 'express_middleware'
        }
      },
      action: {
        method: eventData.method,
        endpoint: eventData.endpoint,
        status_code: eventData.statusCode,
        duration_us: eventData.durationUs,
        is_success: eventData.statusCode < 400
      },
      is_security_significant: Boolean(eventData.isSecuritySignificant),
      metadata: eventData.metadata || {}
    };

    this.queue.push(event);
  }

  flush() {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.batchSize);
    const payload = JSON.stringify(batch);

    try {
      const url = new URL(this.controlPlaneUrl);
      const req = http.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 2000
      });

      req.on('error', () => {
        // Outage must not crash host application
      });

      req.write(payload);
      req.end();
    } catch (e) {
      // Swallowed silently
    }
  }

  middleware() {
    return (req, res, next) => {
      const startNs = process.hrtime.bigint();

      res.on('finish', () => {
        const durationUs = Number((process.hrtime.bigint() - startNs) / 1000n);
        const isSignificant = req.path.startsWith('/admin') ||
                              req.path.startsWith('/auth') ||
                              res.statusCode === 401 ||
                              res.statusCode === 403;

        this.recordEventNonBlocking({
          eventType: 'http.request',
          ip: req.ip || req.connection.remoteAddress,
          method: req.method,
          endpoint: req.path,
          statusCode: res.statusCode,
          durationUs: durationUs,
          userId: req.headers['x-user-id'],
          sessionId: req.headers['x-session-id'],
          isSecuritySignificant: isSignificant
        });
      });

      next();
    };
  }
}

module.exports = { SecurityTelemetryEmitter };
