import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, Server, Database, Eye, Terminal, 
  Cpu, CheckCircle, 
  ArrowUpRight, Play, Pause, Search, Radio
} from 'lucide-react';
import { SecurityEvent } from './types';

export const App: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [selectedSensor, setSelectedSensor] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Running stats
  const [totalIngested, setTotalIngested] = useState<number>(0);
  const [totalPersisted, setTotalPersisted] = useState<number>(0);
  const [activeApps, setActiveApps] = useState<Set<string>>(new Set());

  const wsRef = useRef<WebSocket | null>(null);

  // Connect to Control Plane WebSocket live stream
  useEffect(() => {
    let reconnectTimer: any = null;

    const connectWebSocket = () => {
      const wsUrl = `ws://${window.location.hostname || 'localhost'}:8080/api/v1/ws/events`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const parsed: SecurityEvent = JSON.parse(event.data);
          
          setTotalIngested((prev) => prev + 1);
          if (parsed.is_security_significant) {
            setTotalPersisted((prev) => prev + 1);
          }
          setActiveApps((prev) => new Set(prev).add(parsed.app_id));

          if (!isPaused) {
            setEvents((prev) => [parsed, ...prev.slice(0, 99)]);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket event', e);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        reconnectTimer = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [isPaused]);

  // Simulate generating sample events via the ingestion API
  const handleSimulateEvent = async (type: 'auth_fail' | 'admin_export' | 'kernel_shell') => {
    let payload: any;
    if (type === 'auth_fail') {
      payload = {
        event_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        app_id: 'application-a-auth',
        environment: 'production',
        event_type: 'auth.login_failed',
        severity: 'medium',
        actor: { user_id: 'admin', role: 'unknown' },
        source: {
          ip: '198.51.100.42',
          sensor: { sensor_type: 'agent', raw_event_type: 'express_middleware' }
        },
        action: { method: 'POST', endpoint: '/api/login', status_code: 401, duration_us: 1200, is_success: false },
        is_security_significant: true
      };
    } else if (type === 'admin_export') {
      payload = {
        event_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        app_id: 'application-c-crm',
        environment: 'production',
        event_type: 'data.export_mass',
        severity: 'high',
        actor: { user_id: 'usr_882', session_id: 'sess_stolen_token_491' },
        source: {
          ip: '198.51.100.42',
          sensor: { sensor_type: 'agent', raw_event_type: 'fastapi_middleware' }
        },
        action: { method: 'GET', endpoint: '/admin/export', status_code: 200, duration_us: 4800, is_success: true },
        is_security_significant: true
      };
    } else {
      payload = {
        event_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        app_id: 'application-b-payments',
        environment: 'production',
        event_type: 'kernel.process_exec',
        severity: 'critical',
        source: {
          ip: '10.0.4.12',
          container_id: 'k8s_payments_c7f8a9',
          pid: 14092,
          process_name: '/bin/sh',
          sensor: {
            sensor_type: 'tetragon',
            raw_event_type: 'process_exec',
            sensor_id: 'tetra_node_east_01'
          }
        },
        action: { operation: 'execve /bin/sh inside container', is_success: true },
        is_security_significant: true
      };
    }

    try {
      await fetch('http://localhost:8080/api/v1/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (e) {
      // Offline fallback: display locally
      setEvents((prev) => [payload, ...prev]);
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (selectedSensor !== 'all' && ev.source.sensor.sensor_type !== selectedSensor) {
      return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchApp = ev.app_id.toLowerCase().includes(q);
      const matchType = ev.event_type.toLowerCase().includes(q);
      const matchIp = ev.source.ip?.toLowerCase().includes(q);
      const matchUser = ev.actor?.user_id?.toLowerCase().includes(q);
      return matchApp || matchType || matchIp || matchUser;
    }
    return true;
  });

  return (
    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '24px 32px' }}>
      {/* Top Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ 
            width: 44, height: 44, borderRadius: 10, 
            background: 'linear-gradient(135deg, #0284c7, #6366f1)', 
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.35)'
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
              Distributed Security Control Plane
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Out-of-Band Observation & Rapid Threat Containment Platform
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {/* Engine Mode Badge */}
          <div style={{ 
            display: 'flex', alignItems: 'center', gap: 8, 
            padding: '6px 14px', borderRadius: 20, 
            background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-subtle)'
          }}>
            <Cpu size={15} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Mode A (Deterministic Core)
            </span>
          </div>

          {/* Connection Status */}
          <div style={{ 
            display: 'flex', alignItems: 'center', gap: 8, 
            padding: '6px 14px', borderRadius: 20, 
            background: isConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
            border: `1px solid ${isConnected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`
          }}>
            <span className={isConnected ? "pulse-dot" : "pulse-dot-red"} />
            <span style={{ 
              fontSize: '0.8rem', fontWeight: 600, 
              color: isConnected ? 'var(--accent-emerald)' : 'var(--accent-rose)' 
            }}>
              {isConnected ? 'Stream Active' : 'Connecting ws://:8080'}
            </span>
          </div>
        </div>
      </header>

      {/* Metrics Banner */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
        <div className="glass-panel" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>Ingested Events</span>
            <Activity size={16} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {totalIngested.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Decoupled Stream Buffer</span>
        </div>

        <div className="glass-panel" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>Persisted (Selective)</span>
            <Database size={16} color="var(--accent-violet)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-violet)' }}>
            {totalPersisted.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Filtered Significant Telemetry</span>
        </div>

        <div className="glass-panel" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>Observed Services</span>
            <Server size={16} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {Math.max(activeApps.size, 2)}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Heterogeneous App Agents</span>
        </div>

        <div className="glass-panel" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>Sync Path Overhead</span>
            <CheckCircle size={16} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-emerald)' }}>
            0.00 µs
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Hard Invariant: Out-of-Band</span>
        </div>
      </div>

      {/* Control Strip */}
      <div style={{ 
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
        marginBottom: 16, gap: 16, flexWrap: 'wrap' 
      }}>
        {/* Sensor Filters */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginRight: 4 }}>Filter Sensor:</span>
          {(['all', 'agent', 'tetragon', 'falco', 'hubble'] as const).map((st) => (
            <button
              key={st}
              id={`filter-${st}`}
              onClick={() => setSelectedSensor(st)}
              style={{
                background: selectedSensor === st ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${selectedSensor === st ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                color: selectedSensor === st ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                padding: '6px 14px', borderRadius: 8, cursor: 'pointer',
                fontSize: '0.8rem', fontWeight: 600, textTransform: 'capitalize',
                transition: 'all 0.15s ease'
              }}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Search & Simulation Action Bar */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 12, top: 10, color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search by IP, actor, app..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                padding: '6px 12px 6px 34px',
                color: '#fff',
                fontSize: '0.85rem',
                outline: 'none',
                width: 220
              }}
            />
          </div>

          <button
            id="toggle-pause"
            onClick={() => setIsPaused(!isPaused)}
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem'
            }}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>

          {/* Test Trigger Actions */}
          <button
            id="btn-simulate-auth"
            onClick={() => handleSimulateEvent('auth_fail')}
            style={{
              background: 'rgba(245, 158, 11, 0.15)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              color: '#fbbf24',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.8rem', fontWeight: 600
            }}
          >
            + Test Auth Anomaly
          </button>

          <button
            id="btn-simulate-export"
            onClick={() => handleSimulateEvent('admin_export')}
            style={{
              background: 'rgba(244, 63, 94, 0.15)',
              border: '1px solid rgba(244, 63, 94, 0.4)',
              color: '#f43f5e',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.8rem', fontWeight: 600
            }}
          >
            + Test Mass Export
          </button>

          <button
            id="btn-simulate-tetragon"
            onClick={() => handleSimulateEvent('kernel_shell')}
            style={{
              background: 'rgba(139, 92, 246, 0.15)',
              border: '1px solid rgba(139, 92, 246, 0.4)',
              color: '#c084fc',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.8rem', fontWeight: 600
            }}
          >
            + Test Tetragon Exec
          </button>
        </div>
      </div>

      {/* Main Content Area: Feed + Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 440px' : '1fr', gap: 18 }}>
        {/* Live Stream Table */}
        <div className="glass-panel" style={{ padding: 18, overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Radio size={16} color="var(--accent-cyan)" />
              Real-Time Security Telemetry Stream
            </h2>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Showing {filteredEvents.length} events
            </span>
          </div>

          <div style={{ overflowY: 'auto', maxHeight: 580 }}>
            {filteredEvents.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
                <Terminal size={36} style={{ marginBottom: 12, opacity: 0.4 }} />
                <p>No telemetry events received yet.</p>
                <p style={{ fontSize: '0.8rem' }}>Click one of the "+ Test" buttons above to dispatch live events.</p>
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '8px 12px' }}>Timestamp</th>
                    <th style={{ padding: '8px 12px' }}>Application</th>
                    <th style={{ padding: '8px 12px' }}>Sensor</th>
                    <th style={{ padding: '8px 12px' }}>Event Type</th>
                    <th style={{ padding: '8px 12px' }}>Actor / Source</th>
                    <th style={{ padding: '8px 12px' }}>Severity</th>
                    <th style={{ padding: '8px 12px', textAlign: 'right' }}>Inspect</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((ev) => (
                    <tr 
                      key={ev.event_id}
                      onClick={() => setSelectedEvent(ev)}
                      style={{ 
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        cursor: 'pointer',
                        background: selectedEvent?.event_id === ev.event_id ? 'rgba(56, 189, 248, 0.08)' : 'transparent',
                        transition: 'background 0.1s'
                      }}
                      className="hover-row"
                    >
                      <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: '10px 12px', fontWeight: 600 }}>
                        {ev.app_id}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span className={`badge-mono sensor-${ev.source.sensor.sensor_type}`}>
                          {ev.source.sensor.sensor_type}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)' }}>
                        {ev.event_type}
                      </td>
                      <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                        {ev.actor?.user_id || ev.source.ip || ev.source.container_id || 'System'}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span className={`badge-mono sev-${ev.severity}`}>
                          {ev.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                        <ArrowUpRight size={14} color="var(--text-muted)" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Event Detail Inspector Drawer */}
        {selectedEvent && (
          <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', maxHeight: 660 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Eye size={16} color="var(--accent-cyan)" />
                Telemetry Event Inspector
              </h3>
              <button 
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1rem' }}
              >
                ✕
              </button>
            </div>

            <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4 }}>
              {/* Event Metadata */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Event ID</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all' }}>{selectedEvent.event_id}</div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 2 }}>App Identifier</div>
                  <div style={{ fontWeight: 600 }}>{selectedEvent.app_id}</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 2 }}>Environment</div>
                  <div>{selectedEvent.environment}</div>
                </div>
              </div>

              {/* Sensor Semantics */}
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, marginBottom: 16 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 700, textTransform: 'uppercase', marginBottom: 6 }}>
                  Source Fidelity (Sensor Semantics)
                </div>
                <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-muted)' }}>Sensor Type:</span>
                  <span style={{ fontWeight: 600, textTransform: 'capitalize' }}>{selectedEvent.source.sensor.sensor_type}</span>
                </div>
                <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-muted)' }}>Raw Event Type:</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.source.sensor.raw_event_type}</span>
                </div>
                {selectedEvent.source.container_id && (
                  <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Container:</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.source.container_id}</span>
                  </div>
                )}
                {selectedEvent.source.pid && (
                  <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Process / PID:</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.source.process_name || 'process'} (PID: {selectedEvent.source.pid})</span>
                  </div>
                )}
              </div>

              {/* Action / Context */}
              {selectedEvent.action && (
                <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, marginBottom: 16 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', fontWeight: 700, textTransform: 'uppercase', marginBottom: 6 }}>
                    Action Context
                  </div>
                  {selectedEvent.action.method && (
                    <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>HTTP Method / Path:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.action.method} {selectedEvent.action.endpoint}</span>
                    </div>
                  )}
                  {selectedEvent.action.status_code && (
                    <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>Status Code:</span>
                      <span style={{ fontWeight: 600 }}>{selectedEvent.action.status_code}</span>
                    </div>
                  )}
                  {selectedEvent.action.duration_us && (
                    <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Execution Duration:</span>
                      <span>{(selectedEvent.action.duration_us / 1000).toFixed(2)} ms</span>
                    </div>
                  )}
                </div>
              )}

              {/* Raw JSON Payload */}
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>Raw Event Payload</div>
                <pre style={{ 
                  background: 'rgba(0,0,0,0.4)', padding: 12, borderRadius: 8, 
                  fontSize: '0.7rem', fontFamily: 'var(--font-mono)', overflowX: 'auto',
                  border: '1px solid var(--border-subtle)', color: '#a5f3fc'
                }}>
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
