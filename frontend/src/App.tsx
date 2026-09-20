import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, Server, Database, Eye, Terminal, 
  Cpu, CheckCircle, AlertTriangle, Flame,
  ArrowUpRight, Play, Pause, Search, Radio, Lock, RefreshCw, XCircle,
  Network, Share2, Layers, GitMerge, Sliders, Key, Zap, Clock, ShieldAlert, FileText
} from 'lucide-react';
import { 
  SecurityEvent, Incident, CanonicalEntity, CorrelationGraphData,
  PolicyBundle, PolicyDecision, SignedContainmentCommand, ContainmentActionType
} from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'telemetry' | 'incidents' | 'correlation' | 'containment'>('telemetry');
  const [policies, setPolicies] = useState<PolicyBundle[]>([]);
  const [containmentCommands, setContainmentCommands] = useState<SignedContainmentCommand[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyBundle | null>(null);
  const [simApp, setSimApp] = useState<string>('billing-service');
  const [simWho, setSimWho] = useState<string>('user_corp_99');
  const [simCap, setSimCap] = useState<string>('process.execute');
  const [simResource, setSimResource] = useState<string>('/bin/sh');
  const [simResult, setSimResult] = useState<PolicyDecision | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [dispatchAction, setDispatchAction] = useState<ContainmentActionType>('REVOKE_SESSION');
  const [dispatchTarget, setDispatchTarget] = useState<string>('session:sess_malicious_99');
  const [dispatchCap, setDispatchCap] = useState<string>('data.export');
  const [dispatchTtl, setDispatchTtl] = useState<number>(300);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [entities, setEntities] = useState<CanonicalEntity[]>([]);
  const [graphData, setGraphData] = useState<CorrelationGraphData>({ nodes: [], edges: [] });
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<CanonicalEntity | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [selectedSensor, setSelectedSensor] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Running stats
  const [totalIngested, setTotalIngested] = useState<number>(0);
  const [totalPersisted, setTotalPersisted] = useState<number>(0);
  const [activeApps, setActiveApps] = useState<Set<string>>(new Set());

  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial incidents from Control Plane REST API
  const fetchIncidents = async () => {
    try {
      const res = await fetch('http://localhost:8080/api/v1/incidents');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setIncidents(data);
        }
      }
    } catch (e) {
      console.log('Control plane REST API not reached yet:', e);
    }
  };

  // Fetch canonical entities and context graph
  const fetchEntitiesAndGraph = async () => {
    try {
      const entRes = await fetch('http://localhost:8080/api/v1/entities');
      if (entRes.ok) {
        const data = await entRes.json();
        if (Array.isArray(data)) setEntities(data);
      }
      const graphRes = await fetch('http://localhost:8080/api/v1/correlation/graph');
      if (graphRes.ok) {
        const data = await graphRes.json();
        if (data && data.nodes) setGraphData(data);
      }
    } catch (e) {
      console.log('Entities/Graph fetch error:', e);
    }
  };

  // Fetch capability policies and signed containment commands
  const fetchPoliciesAndContainment = async () => {
    try {
      const polRes = await fetch('http://localhost:8080/api/v1/policies');
      if (polRes.ok) {
        const data = await polRes.json();
        if (Array.isArray(data)) setPolicies(data);
      }
      const cmdRes = await fetch('http://localhost:8080/api/v1/containment/commands');
      if (cmdRes.ok) {
        const data = await cmdRes.json();
        if (Array.isArray(data)) setContainmentCommands(data);
      }
    } catch (e) {
      console.log('Policies/Containment fetch error:', e);
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchEntitiesAndGraph();
    fetchPoliciesAndContainment();
  }, []);

  // Connect to Control Plane WebSocket live stream (events + incident alerts)
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
          const parsed = JSON.parse(event.data);
          
          // Check if message is an Incident notification
          if (parsed.incident_id) {
            const inc = parsed as Incident;
            setIncidents((prev) => {
              const idx = prev.findIndex((i) => i.incident_id === inc.incident_id);
              if (idx >= 0) {
                const next = [...prev];
                next[idx] = inc;
                return next;
              }
              return [inc, ...prev];
            });
            return;
          }

          // Otherwise it is a SecurityEvent
          const secEvent = parsed as SecurityEvent;
          setTotalIngested((prev) => prev + 1);
          if (secEvent.is_security_significant) {
            setTotalPersisted((prev) => prev + 1);
          }
          setActiveApps((prev) => new Set(prev).add(secEvent.app_id));

          if (!isPaused) {
            setEvents((prev) => [secEvent, ...prev.slice(0, 99)]);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message', e);
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

  // Handle containment status mutation
  const handleUpdateStatus = async (incidentId: string, newStatus: string) => {
    try {
      const res = await fetch(`http://localhost:8080/api/v1/incidents/${incidentId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        setIncidents((prev) =>
          prev.map((i) => (i.incident_id === incidentId ? { ...i, status: newStatus as any } : i))
        );
        if (selectedIncident && selectedIncident.incident_id === incidentId) {
          setSelectedIncident((prev) => prev ? { ...prev, status: newStatus as any } : null);
        }
      }
    } catch (e) {
      console.error('Failed to update incident status', e);
    }
  };

  // Phase 4: Dry-Run Policy Simulation (Mode C)
  const handleSimulatePolicy = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch('http://localhost:8080/api/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          app_id: simApp,
          who: simWho,
          capability: simCap,
          target_resource: simResource,
        })
      });
      if (res.ok) {
        const dec = await res.json();
        setSimResult(dec);
      }
    } catch (e) {
      console.error('Policy simulation error', e);
    } finally {
      setIsSimulating(false);
    }
  };

  // Phase 4: Dispatch Ed25519-Signed Containment Command
  const handleDispatchSignedCommand = async () => {
    try {
      const res = await fetch('http://localhost:8080/api/v1/containment/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: dispatchAction,
          target_entity: dispatchTarget,
          capability: dispatchAction === 'REVOKE_CAPABILITY' ? dispatchCap : undefined,
          ttl_seconds: dispatchTtl,
          rollback_recipe: `REVERSE_${dispatchAction}_ON_${dispatchTarget}`,
        })
      });
      if (res.ok) {
        const cmd = await res.json();
        setContainmentCommands((prev) => [cmd, ...prev]);
      }
    } catch (e) {
      console.error('Failed to dispatch containment command', e);
    }
  };

  // Phase 4: Reversible Containment Rollback
  const handleRollbackCommand = async (commandId: string) => {
    try {
      const res = await fetch(`http://localhost:8080/api/v1/containment/${commandId}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Operator verified resolution' })
      });
      if (res.ok) {
        const updated = await res.json();
        setContainmentCommands((prev) =>
          prev.map((c) => (c.command_id === commandId ? updated : c))
        );
      }
    } catch (e) {
      console.error('Failed to rollback containment command', e);
    }
  };

  // Simulate generating sample events via the ingestion API
  const handleSimulateAttack = async (scenario: 'bruteforce' | 'recon' | 'kernel_shell' | 'multi_app_attack') => {
    if (scenario === 'multi_app_attack') {
      const attackerIp = `198.51.100.${Math.floor(Math.random() * 150 + 20)}`;
      const attackerSession = `sess_${Math.random().toString(36).substring(7)}`;
      const attackerUser = `compromised_user_${Math.floor(Math.random() * 900 + 100)}`;
      const batch = [
        // Stage 1: Recon on billing-service
        {
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          app_id: 'billing-service',
          environment: 'production',
          event_type: 'http.unauthorized',
          severity: 'medium',
          source: { ip: attackerIp, sensor: { sensor_type: 'agent', raw_event_type: 'http' } },
          action: { method: 'GET', endpoint: '/admin/config', status_code: 401, duration_us: 300, is_success: false },
          is_security_significant: true
        },
        // Stage 2: Pivot to auth-portal with active session
        {
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          app_id: 'auth-portal',
          environment: 'production',
          event_type: 'auth.login_success',
          severity: 'low',
          actor: { user_id: attackerUser, session_id: attackerSession },
          source: { ip: attackerIp, sensor: { sensor_type: 'agent', raw_event_type: 'http' } },
          action: { method: 'POST', endpoint: '/api/v1/auth/session', status_code: 200, duration_us: 150, is_success: true },
          is_security_significant: false
        },
        // Stage 3: High impact mass data export on crm-service
        {
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          app_id: 'crm-service',
          environment: 'production',
          event_type: 'data.export',
          severity: 'high',
          actor: { user_id: attackerUser, session_id: attackerSession },
          source: { ip: attackerIp, sensor: { sensor_type: 'agent', raw_event_type: 'http' } },
          action: { method: 'GET', endpoint: '/api/v1/customers/export', status_code: 200, duration_us: 8900, is_success: true },
          resource: { resource_type: 'database', resource_id: 'customer_vault' },
          is_security_significant: true
        }
      ];
      try {
        await fetch('http://localhost:8080/api/v1/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batch)
        });
        setTimeout(fetchEntitiesAndGraph, 500);
        setActiveTab('correlation');
      } catch (e) {
        console.error(e);
      }
    } else if (scenario === 'bruteforce') {
      const attackerIp = `198.51.100.${Math.floor(Math.random() * 200 + 10)}`;
      const batch: any[] = [];
      for (let i = 0; i < 12; i++) {
        batch.push({
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          app_id: 'application-a-auth',
          environment: 'production',
          event_type: 'auth.login_failed',
          severity: 'medium',
          actor: { user_id: 'target_admin', role: 'unknown' },
          source: {
            ip: attackerIp,
            sensor: { sensor_type: 'agent', raw_event_type: 'express_middleware' }
          },
          action: { method: 'POST', endpoint: '/api/v1/auth/login', status_code: 401, duration_us: 1200, is_success: false },
          is_security_significant: true
        });
      }
      try {
        await fetch('http://localhost:8080/api/v1/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batch)
        });
        setActiveTab('incidents');
      } catch (e) {
        console.error(e);
      }
    } else if (scenario === 'recon') {
      const scannerIp = `203.0.113.${Math.floor(Math.random() * 200 + 10)}`;
      const endpoints = ['/admin', '/wp-admin', '/.env', '/config.json', '/actuator/heapdump', '/api/v1/debug', '/backup.zip'];
      const batch: any[] = [];
      for (let i = 0; i < 22; i++) {
        const ep = `${endpoints[i % endpoints.length]}/${Math.random().toString(36).substring(7)}`;
        batch.push({
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          app_id: 'application-c-crm',
          environment: 'production',
          event_type: 'http.not_found',
          severity: 'low',
          source: {
            ip: scannerIp,
            sensor: { sensor_type: 'agent', raw_event_type: 'fastapi_middleware' }
          },
          action: { method: 'GET', endpoint: ep, status_code: 404, duration_us: 450, is_success: false },
          is_security_significant: true
        });
      }
      try {
        await fetch('http://localhost:8080/api/v1/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batch)
        });
        setActiveTab('incidents');
      } catch (e) {
        console.error(e);
      }
    } else {
      const payload = {
        event_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        app_id: 'billing-service',
        environment: 'production',
        event_type: 'kernel.process_exec',
        severity: 'critical',
        source: {
          ip: `10.244.1.${Math.floor(Math.random() * 200 + 10)}`,
          container_id: 'k8s_billing_c7f8a9',
          pid: 14092,
          process_name: '/bin/bash',
          sensor: {
            sensor_type: 'tetragon',
            raw_event_type: 'process_exec',
            sensor_id: 'tetra_node_east_01'
          }
        },
        action: { endpoint: '/bin/bash -i', operation: 'execve', is_success: true },
        is_security_significant: true
      };
      try {
        await fetch('http://localhost:8080/api/v1/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        setActiveTab('incidents');
      } catch (e) {
        console.error(e);
      }
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

  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating');
  const criticalIncidents = incidents.filter((i) => i.severity === 'critical');

  return (
    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '24px 32px' }}>
      {/* Top Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ 
            width: 46, height: 46, borderRadius: 12, 
            background: 'linear-gradient(135deg, #0284c7, #6366f1)', 
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 24px rgba(56, 189, 248, 0.4)'
          }}>
            <Shield size={26} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.45rem', fontWeight: 800, letterSpacing: '-0.02em', margin: 0 }}>
              Distributed Security Control Plane
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '4px 0 0 0' }}>
              Phase 3: Identity Resolution, In-Memory Context Graph & Cross-App Correlation
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {/* Navigation Tabs */}
          <div style={{ 
            display: 'flex', background: 'rgba(255,255,255,0.04)', 
            borderRadius: 10, padding: 3, border: '1px solid var(--border-subtle)' 
          }}>
            <button
              onClick={() => setActiveTab('telemetry')}
              style={{
                background: activeTab === 'telemetry' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                border: activeTab === 'telemetry' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                color: activeTab === 'telemetry' ? '#fff' : 'var(--text-secondary)',
                padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s ease'
              }}
            >
              <Radio size={14} color={activeTab === 'telemetry' ? 'var(--accent-cyan)' : 'inherit'} />
              Telemetry Stream
            </button>
            <button
              onClick={() => setActiveTab('incidents')}
              style={{
                background: activeTab === 'incidents' ? 'rgba(244, 63, 94, 0.2)' : 'transparent',
                border: activeTab === 'incidents' ? '1px solid var(--accent-rose)' : '1px solid transparent',
                color: activeTab === 'incidents' ? '#fff' : 'var(--text-secondary)',
                padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s ease'
              }}
            >
              <Flame size={14} color={openIncidents.length > 0 ? 'var(--accent-rose)' : 'inherit'} />
              Active Incidents
              {openIncidents.length > 0 && (
                <span style={{ 
                  background: 'var(--accent-rose)', color: '#fff', 
                  fontSize: '0.7rem', padding: '1px 6px', borderRadius: 10, fontWeight: 700 
                }}>
                  {openIncidents.length}
                </span>
              )}
            </button>
            <button
              onClick={() => { setActiveTab('correlation'); fetchEntitiesAndGraph(); }}
              style={{
                background: activeTab === 'correlation' ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
                border: activeTab === 'correlation' ? '1px solid #a855f7' : '1px solid transparent',
                color: activeTab === 'correlation' ? '#fff' : 'var(--text-secondary)',
                padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s ease'
              }}
            >
              <Network size={14} color={activeTab === 'correlation' ? '#a855f7' : 'inherit'} />
              Identity & Correlation
              {entities.length > 0 && (
                <span style={{ 
                  background: '#a855f7', color: '#fff', 
                  fontSize: '0.7rem', padding: '1px 6px', borderRadius: 10, fontWeight: 700 
                }}>
                  {entities.length}
                </span>
              )}
            </button>
            <button
              id="tab-containment"
              onClick={() => { setActiveTab('containment'); fetchPoliciesAndContainment(); }}
              style={{
                background: activeTab === 'containment' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                border: activeTab === 'containment' ? '1px solid var(--accent-emerald)' : '1px solid transparent',
                color: activeTab === 'containment' ? '#fff' : 'var(--text-secondary)',
                padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s ease'
              }}
            >
              <Shield size={14} color={activeTab === 'containment' ? 'var(--accent-emerald)' : 'inherit'} />
              Policies & Containment
              {containmentCommands.filter((c) => c.status === 'active').length > 0 && (
                <span style={{ 
                  background: 'var(--accent-emerald)', color: '#000', 
                  fontSize: '0.7rem', padding: '1px 6px', borderRadius: 10, fontWeight: 700 
                }}>
                  {containmentCommands.filter((c) => c.status === 'active').length}
                </span>
              )}
            </button>
          </div>

          {/* Engine Mode Badge */}
          <div style={{ 
            display: 'flex', alignItems: 'center', gap: 8, 
            padding: '6px 14px', borderRadius: 20, 
            background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-subtle)'
          }}>
            <Cpu size={15} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Mode A (Deterministic)
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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        <div className="glass-panel" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, textTransform: 'uppercase' }}>Ingested Events</span>
            <Activity size={16} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {totalIngested.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Decoupled Stream Buffer</span>
        </div>

        <div className="glass-panel" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, textTransform: 'uppercase' }}>Active Threats / Incidents</span>
            <Flame size={16} color={openIncidents.length > 0 ? "var(--accent-rose)" : "var(--text-muted)"} />
          </div>
          <div style={{ 
            fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--font-mono)', 
            color: openIncidents.length > 0 ? 'var(--accent-rose)' : '#fff' 
          }}>
            {openIncidents.length} <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 400 }}>({criticalIncidents.length} Critical)</span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Hot State Evaluated</span>
        </div>

        <div className="glass-panel" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, textTransform: 'uppercase' }}>Observed Services</span>
            <Server size={16} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {Math.max(activeApps.size, 2)}
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Heterogeneous App Agents</span>
        </div>

        <div className="glass-panel" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, textTransform: 'uppercase' }}>Sync Path Overhead</span>
            <CheckCircle size={16} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-emerald)' }}>
            0.00 µs
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Hard Invariant: Out-of-Band</span>
        </div>
      </div>

      {/* Control Strip & Test Simulators */}
      <div style={{ 
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
        marginBottom: 18, gap: 16, flexWrap: 'wrap' 
      }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {activeTab === 'telemetry' ? (
            <>
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
                    padding: '5px 12px', borderRadius: 8, cursor: 'pointer',
                    fontSize: '0.78rem', fontWeight: 600, textTransform: 'capitalize',
                  }}
                >
                  {st}
                </button>
              ))}
            </>
          ) : activeTab === 'incidents' ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Incident Lifecycle & Threat Queue
              </span>
              <button
                onClick={fetchIncidents}
                style={{
                  background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)', padding: '4px 8px', borderRadius: 6, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem'
                }}
              >
                <RefreshCw size={12} /> Refresh
              </button>
            </div>
          ) : activeTab === 'correlation' ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Canonical Identity Directory & Context Graph ({entities.length} Entities, {graphData.nodes.length} Nodes)
              </span>
              <button
                onClick={fetchEntitiesAndGraph}
                style={{
                  background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)', padding: '4px 8px', borderRadius: 6, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem'
                }}
              >
                <RefreshCw size={12} /> Refresh
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Deno Capability Policies & Ed25519 Signed Containment ({policies.length} Policies, {containmentCommands.length} Commands)
              </span>
              <button
                onClick={fetchPoliciesAndContainment}
                style={{
                  background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)', padding: '4px 8px', borderRadius: 6, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem'
                }}
              >
                <RefreshCw size={12} /> Refresh
              </button>
            </div>
          )}
        </div>

        {/* Attack Scenarios Simulation Bar */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Simulate Attack:
          </span>
          <button
            id="btn-sim-bruteforce"
            onClick={() => handleSimulateAttack('bruteforce')}
            style={{
              background: 'rgba(245, 158, 11, 0.15)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              color: '#fbbf24',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.78rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6
            }}
          >
            ⚡ 12x Brute Force
          </button>

          <button
            id="btn-sim-recon"
            onClick={() => handleSimulateAttack('recon')}
            style={{
              background: 'rgba(56, 189, 248, 0.15)',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              color: '#38bdf8',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.78rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6
            }}
          >
            🔍 25x API Scan (404)
          </button>

          <button
            id="btn-sim-kernel"
            onClick={() => handleSimulateAttack('kernel_shell')}
            style={{
              background: 'rgba(244, 63, 94, 0.18)',
              border: '1px solid rgba(244, 63, 94, 0.5)',
              color: '#f43f5e',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.78rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
            }}
          >
            🚨 Kernel eBPF Shell
          </button>

          <button
            id="btn-sim-multi-app"
            onClick={() => handleSimulateAttack('multi_app_attack')}
            style={{
              background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25), rgba(99, 102, 241, 0.25))',
              border: '1px solid #a855f7',
              color: '#d8b4fe',
              padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
              fontSize: '0.78rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
            }}
          >
            <Share2 size={13} /> ⚡ 3-App Attack Chain
          </button>
        </div>
      </div>

      {/* Main Tab Content */}
      {activeTab === 'telemetry' ? (
        /* Telemetry Stream View */
        <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 440px' : '1fr', gap: 18 }}>
          <div className="glass-panel" style={{ padding: 18, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Radio size={16} color="var(--accent-cyan)" />
                Real-Time Security Telemetry Stream
              </h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button
                  id="toggle-pause"
                  onClick={() => setIsPaused(!isPaused)}
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-secondary)',
                    padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem'
                  }}
                >
                  {isPaused ? <Play size={12} /> : <Pause size={12} />}
                  {isPaused ? 'Resume' : 'Pause'}
                </button>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {filteredEvents.length} events
                </span>
              </div>
            </div>

            <div style={{ overflowY: 'auto', maxHeight: 580 }}>
              {filteredEvents.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
                  <Terminal size={36} style={{ marginBottom: 12, opacity: 0.4 }} />
                  <p>No telemetry events received yet.</p>
                  <p style={{ fontSize: '0.8rem' }}>Click one of the attack simulation buttons above to stream events.</p>
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
                  Event Inspector
                </h3>
                <button 
                  onClick={() => setSelectedEvent(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1rem' }}
                >
                  ✕
                </button>
              </div>

              <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4 }}>
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>Event ID</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all' }}>{selectedEvent.event_id}</div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>App</div>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{selectedEvent.app_id}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Environment</div>
                    <div style={{ fontSize: '0.85rem' }}>{selectedEvent.environment}</div>
                  </div>
                </div>

                <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, marginBottom: 14 }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 700, textTransform: 'uppercase', marginBottom: 6 }}>
                    Sensor Semantics
                  </div>
                  <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Type:</span>
                    <span style={{ fontWeight: 600 }}>{selectedEvent.source.sensor.sensor_type}</span>
                  </div>
                  <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Raw Event:</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.source.sensor.raw_event_type}</span>
                  </div>
                  {selectedEvent.source.process_name && (
                    <div style={{ fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Process:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-rose)' }}>{selectedEvent.source.process_name}</span>
                    </div>
                  )}
                </div>

                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>Raw Payload</div>
                  <pre style={{ 
                    background: 'rgba(0,0,0,0.4)', padding: 10, borderRadius: 8, 
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
      ) : activeTab === 'incidents' ? (
        /* Phase 2: Active Incidents & Containment View */
        <div style={{ display: 'grid', gridTemplateColumns: selectedIncident ? '1fr 480px' : '1fr', gap: 18 }}>
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Flame size={18} color="var(--accent-rose)" />
                Detected Security Incidents ({incidents.length})
              </h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Deterministic Correlation & Dynamic Risk Scoring
              </span>
            </div>

            {incidents.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
                <CheckCircle size={42} style={{ marginBottom: 12, color: 'var(--accent-emerald)', opacity: 0.8 }} />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#fff', marginBottom: 6 }}>No Active Incidents</h3>
                <p style={{ fontSize: '0.85rem' }}>All applications are operating within safe deterministic thresholds.</p>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Use the attack buttons above to simulate brute-force or container anomalies.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {incidents.map((inc) => {
                  const isContained = inc.status === 'contained';
                  const isResolved = inc.status === 'resolved';

                  return (
                    <div
                      key={inc.incident_id}
                      onClick={() => setSelectedIncident(inc)}
                      style={{
                        padding: 16, borderRadius: 10,
                        background: selectedIncident?.incident_id === inc.incident_id ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.02)',
                        border: `1px solid ${inc.severity === 'critical' ? 'rgba(244, 63, 94, 0.4)' : inc.severity === 'high' ? 'rgba(245, 158, 11, 0.4)' : 'var(--border-subtle)'}`,
                        boxShadow: inc.severity === 'critical' && !isContained ? '0 0 16px rgba(244, 63, 94, 0.15)' : 'none',
                        cursor: 'pointer', transition: 'all 0.15s ease'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span className={`badge-mono sev-${inc.severity}`}>
                              {inc.severity.toUpperCase()}
                            </span>
                            <span style={{ 
                              fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
                              padding: '2px 8px', borderRadius: 6,
                              background: isContained ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                              color: isContained ? 'var(--accent-emerald)' : 'var(--accent-rose)'
                            }}>
                              {inc.status}
                            </span>
                            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                              Target: <strong style={{ color: '#fff' }}>{inc.target_entity}</strong>
                            </span>
                          </div>
                          <h3 style={{ fontSize: '0.98rem', fontWeight: 700, margin: 0 }}>
                            {inc.title}
                          </h3>
                        </div>

                        {/* Risk Score Pill */}
                        <div style={{ textAlign: 'right' }}>
                          <div style={{ 
                            fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)',
                            color: inc.risk_score >= 100 ? 'var(--accent-rose)' : inc.risk_score >= 50 ? '#fb923c' : 'var(--accent-cyan)'
                          }}>
                            {inc.risk_score}
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}> / 100</span>
                          </div>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Risk Score</span>
                        </div>
                      </div>

                      <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: '0 0 12px 0' }}>
                        {inc.description}
                      </p>

                      {/* Signals & Actions Bar */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {inc.signals.map((sig, idx) => (
                            <span key={idx} style={{ 
                              fontSize: '0.72rem', background: 'rgba(255,255,255,0.04)', 
                              padding: '2px 8px', borderRadius: 6, color: 'var(--accent-cyan)', border: '1px solid var(--border-subtle)'
                            }}>
                              ⚡ {sig.rule_name} (+{sig.risk_weight})
                            </span>
                          ))}
                        </div>

                        <div style={{ display: 'flex', gap: 8 }} onClick={(e) => e.stopPropagation()}>
                          {!isContained && !isResolved && (
                            <button
                              onClick={() => handleUpdateStatus(inc.incident_id, 'contained')}
                              style={{
                                background: 'rgba(244, 63, 94, 0.18)',
                                border: '1px solid rgba(244, 63, 94, 0.5)',
                                color: '#f43f5e',
                                padding: '5px 12px', borderRadius: 6, cursor: 'pointer',
                                fontSize: '0.75rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4
                              }}
                            >
                              <Lock size={12} /> Contain Entity
                            </button>
                          )}
                          {!isResolved && (
                            <button
                              onClick={() => handleUpdateStatus(inc.incident_id, 'resolved')}
                              style={{
                                background: 'rgba(16, 185, 129, 0.15)',
                                border: '1px solid rgba(16, 185, 129, 0.4)',
                                color: 'var(--accent-emerald)',
                                padding: '5px 12px', borderRadius: 6, cursor: 'pointer',
                                fontSize: '0.75rem', fontWeight: 600
                              }}
                            >
                              Resolve
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Incident Detail & Evidence Inspector Drawer */}
          {selectedIncident && (
            <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', maxHeight: 680 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <AlertTriangle size={16} color="var(--accent-rose)" />
                  Incident Evidence & Audit Trail
                </h3>
                <button 
                  onClick={() => setSelectedIncident(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1rem' }}
                >
                  ✕
                </button>
              </div>

              <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4 }}>
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Incident ID</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{selectedIncident.incident_id}</div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Target Entity</div>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--accent-cyan)' }}>{selectedIncident.target_entity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Status</div>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', textTransform: 'uppercase', color: selectedIncident.status === 'contained' ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>
                      {selectedIncident.status}
                    </div>
                  </div>
                </div>

                {/* Risk Gauge */}
                <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, marginBottom: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', fontWeight: 600, marginBottom: 6 }}>
                    <span>Accumulated Risk Score</span>
                    <span>{selectedIncident.risk_score} / 100</span>
                  </div>
                  <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ 
                      width: `${Math.min(selectedIncident.risk_score, 100)}%`, height: '100%',
                      background: selectedIncident.risk_score >= 100 ? 'var(--accent-rose)' : selectedIncident.risk_score >= 50 ? '#fb923c' : 'var(--accent-cyan)' 
                    }} />
                  </div>
                </div>

                {/* Signals Timeline */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8, fontWeight: 700 }}>
                    Triggered Rule Signals ({selectedIncident.signals.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedIncident.signals.map((sig, sIdx) => (
                      <div key={sIdx} style={{ padding: 8, background: 'rgba(0,0,0,0.3)', borderRadius: 6, borderLeft: '3px solid var(--accent-rose)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', fontWeight: 600 }}>
                          <span>{sig.rule_name}</span>
                          <span style={{ color: 'var(--accent-rose)' }}>+{sig.risk_weight} pts</span>
                        </div>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                          {sig.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Attached Evidence Telemetry Events */}
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8, fontWeight: 700 }}>
                    Attached Raw Evidence Events ({selectedIncident.evidence.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedIncident.evidence.slice(0, 10).map((ev, eIdx) => (
                      <div key={eIdx} style={{ padding: 8, background: 'rgba(255,255,255,0.02)', borderRadius: 6, fontSize: '0.75rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 2 }}>
                          <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                          <span className={`badge-mono sev-${ev.severity}`}>{ev.severity}</span>
                        </div>
                        <div style={{ fontWeight: 600 }}>{ev.event_type} - {ev.action?.endpoint || ev.source.process_name || 'N/A'}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      ) : activeTab === 'correlation' ? (
        /* Phase 3: Canonical Identity & Context Graph Explorer */
        <div style={{ display: 'grid', gridTemplateColumns: selectedEntity ? '1fr 480px' : '1fr', gap: 18 }}>
          {/* Left Column: Canonical Entities Table / Cards */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Network size={18} color="#a855f7" />
                Canonical Identities ({entities.length})
              </h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Cross-App Resolved Actors & Capability Context
              </span>
            </div>

            {entities.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)' }}>
                <Network size={36} color="rgba(255,255,255,0.15)" style={{ margin: '0 auto 12px' }} />
                <p style={{ margin: 0, fontSize: '0.9rem', fontWeight: 600 }}>No Canonical Entities Resolved Yet</p>
                <p style={{ margin: '6px 0 0', fontSize: '0.8rem' }}>
                  Click "⚡ 3-App Attack Chain" above to simulate a multi-application compromise and observe identity linking.
                </p>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 14 }}>
                {entities.map((ent) => {
                  const isSelected = selectedEntity?.entity_id === ent.entity_id;
                  return (
                    <div
                      key={ent.entity_id}
                      onClick={() => setSelectedEntity(ent)}
                      style={{
                        padding: 16,
                        borderRadius: 10,
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(168, 85, 247, 0.15)' : 'rgba(255,255,255,0.02)',
                        border: `1px solid ${isSelected ? '#a855f7' : 'var(--border-subtle)'}`,
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{
                              fontSize: '0.68rem', fontWeight: 800, textTransform: 'uppercase',
                              padding: '2px 8px', borderRadius: 10,
                              background: ent.entity_type === 'user' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(168, 85, 247, 0.2)',
                              color: ent.entity_type === 'user' ? 'var(--accent-cyan)' : '#c084fc',
                              border: `1px solid ${ent.entity_type === 'user' ? 'var(--accent-cyan)' : '#a855f7'}`
                            }}>
                              {ent.entity_type}
                            </span>
                            <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>
                              {ent.display_name}
                            </span>
                          </div>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                            {ent.entity_id}
                          </div>
                        </div>

                        <span style={{
                          fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
                          background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: 4,
                          color: 'var(--text-secondary)'
                        }}>
                          {ent.event_count} events
                        </span>
                      </div>

                      {/* Linked Identities details */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: '0.75rem', marginBottom: 12 }}>
                        {ent.linked_ips.length > 0 && (
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', minWidth: 60 }}>IPs ({ent.linked_ips.length}):</span>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                              {ent.linked_ips.map((ip) => (
                                <span key={ip} style={{ background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: 4, fontFamily: 'var(--font-mono)' }}>
                                  {ip}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {ent.linked_sessions.length > 0 && (
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', minWidth: 60 }}>Sessions:</span>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                              {ent.linked_sessions.map((sid) => (
                                <span key={sid} style={{ background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: 4, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                                  {sid}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {ent.apps_seen.length > 0 && (
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', minWidth: 60 }}>Apps:</span>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                              {ent.apps_seen.map((app) => (
                                <span key={app} style={{ background: 'rgba(16, 185, 129, 0.12)', color: 'var(--accent-emerald)', padding: '1px 6px', borderRadius: 4 }}>
                                  {app}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Deno-inspired Exercised Capabilities */}
                      {ent.exercised_capabilities.length > 0 && (
                        <div>
                          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4, fontWeight: 700 }}>
                            Exercised Capabilities
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {ent.exercised_capabilities.map((cap) => (
                              <span
                                key={cap}
                                style={{
                                  fontSize: '0.68rem',
                                  padding: '2px 6px',
                                  borderRadius: 4,
                                  background: cap.includes('export') || cap.includes('execute') || cap.includes('admin')
                                    ? 'rgba(244, 63, 94, 0.15)'
                                    : 'rgba(56, 189, 248, 0.12)',
                                  color: cap.includes('export') || cap.includes('execute') || cap.includes('admin')
                                    ? '#f43f5e'
                                    : 'var(--accent-cyan)',
                                  border: `1px solid ${cap.includes('export') || cap.includes('execute') || cap.includes('admin') ? 'rgba(244, 63, 94, 0.3)' : 'rgba(56, 189, 248, 0.3)'}`
                                }}
                              >
                                {cap}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Entity Graph Inspector */}
          {selectedEntity && (
            <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <GitMerge size={16} color="#a855f7" />
                  Context Graph: {selectedEntity.display_name}
                </h3>
                <button
                  onClick={() => setSelectedEntity(null)}
                  style={{
                    background: 'none', border: 'none', color: 'var(--text-muted)',
                    cursor: 'pointer', padding: 2
                  }}
                >
                  <XCircle size={18} />
                </button>
              </div>

              <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4 }}>
                <div style={{ padding: 12, background: 'rgba(0,0,0,0.3)', borderRadius: 8, marginBottom: 14 }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>Canonical ID</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#c084fc', wordBreak: 'break-all' }}>
                    {selectedEntity.entity_id}
                  </div>
                </div>

                {/* Subgraph Nodes and Edges */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8, fontWeight: 700 }}>
                    Connected Graph Topology
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {graphData.edges
                      .filter((e) => e.source === selectedEntity.entity_id || e.target === selectedEntity.entity_id)
                      .map((edge) => (
                        <div
                          key={edge.id}
                          style={{
                            padding: 8, background: 'rgba(255,255,255,0.02)', borderRadius: 6,
                            borderLeft: '3px solid #a855f7', fontSize: '0.75rem'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', marginBottom: 2 }}>
                            <span style={{ color: '#c084fc', fontWeight: 700 }}>{edge.relation}</span>
                            <span style={{ color: 'var(--text-muted)' }}>{edge.count} hits</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
                            <span style={{ color: 'var(--text-muted)' }}>{edge.source === selectedEntity.entity_id ? 'Target:' : 'Source:'}</span>
                            <span style={{ fontWeight: 600, color: '#fff' }}>
                              {edge.source === selectedEntity.entity_id ? edge.target : edge.source}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>

                {/* All Cross-App Observed Nodes */}
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8, fontWeight: 700 }}>
                    Applications in Attack/Activity Chain ({selectedEntity.apps_seen.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedEntity.apps_seen.map((app) => (
                      <div key={app} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: 8, background: 'rgba(0,0,0,0.25)', borderRadius: 6, fontSize: '0.8rem' }}>
                        <Server size={14} color="var(--accent-emerald)" />
                        <span style={{ fontWeight: 600 }}>{app}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Phase 4: Deno Capability Policies & Graduated Containment Console */
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
          {/* Left Column: Capability Policies & Mode C Dry-Run Simulator */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            {/* Active Policy Bundles */}
            <div className="glass-panel" style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <h2 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
                  <FileText size={18} color="var(--accent-cyan)" />
                  Active Capability Policies ({policies.length})
                </h2>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  DENY strictly overrides ALLOW
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {policies.map((p) => (
                  <div
                    key={p.policy_id}
                    style={{
                      padding: 14,
                      background: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 8
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--accent-cyan)' }}>
                        {p.policy_id} <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>v{p.version}</span>
                      </span>
                      <span className="badge-mono" style={{ background: 'rgba(255,255,255,0.08)' }}>
                        target: {p.target_app}
                      </span>
                    </div>
                    <p style={{ margin: '0 0 10px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {p.description}
                    </p>

                    {/* Deny Rules */}
                    <div style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--accent-rose)', fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                        Explicit Deny Rules ({p.deny.length}) - Precedence Over Allow
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {p.deny.map((r, i) => (
                          <span
                            key={i}
                            style={{
                              background: 'rgba(244, 63, 94, 0.15)',
                              border: '1px solid rgba(244, 63, 94, 0.3)',
                              color: '#fda4af',
                              padding: '2px 8px', borderRadius: 4, fontSize: '0.72rem',
                              fontFamily: 'var(--font-mono)'
                            }}
                          >
                            DENY {r.capability} → {r.scope}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Allow Rules */}
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--accent-emerald)', fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                        Allowed Capabilities ({p.allow.length})
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {p.allow.map((r, i) => (
                          <span
                            key={i}
                            style={{
                              background: 'rgba(16, 185, 129, 0.15)',
                              border: '1px solid rgba(16, 185, 129, 0.3)',
                              color: '#6ee7b7',
                              padding: '2px 8px', borderRadius: 4, fontSize: '0.72rem',
                              fontFamily: 'var(--font-mono)'
                            }}
                          >
                            ALLOW {r.capability} → {r.scope}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Mode C Dry-Run Policy Simulator */}
            <div className="glass-panel" style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Zap size={16} color="var(--accent-amber)" />
                  Mode C: Policy Dry-Run Simulator
                </h3>
                <span style={{ fontSize: '0.72rem', color: 'var(--accent-amber)', background: 'rgba(245, 158, 11, 0.1)', padding: '2px 8px', borderRadius: 4 }}>
                  Zero State Mutation
                </span>
              </div>
              <p style={{ margin: '0 0 14px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Simulate prospective decisions (WOULD_ALLOW / WOULD_DENY) before committing changes.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Application ID</label>
                  <input
                    id="sim-app-input"
                    type="text"
                    value={simApp}
                    onChange={(e) => setSimApp(e.target.value)}
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Actor Entity / Who</label>
                  <input
                    id="sim-who-input"
                    type="text"
                    value={simWho}
                    onChange={(e) => setSimWho(e.target.value)}
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Capability</label>
                  <select
                    id="sim-cap-select"
                    value={simCap}
                    onChange={(e) => setSimCap(e.target.value)}
                    style={{
                      width: '100%', background: '#131a2a', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem'
                    }}
                  >
                    <option value="process.execute">process.execute</option>
                    <option value="database.read">database.read</option>
                    <option value="database.write">database.write</option>
                    <option value="network.connect">network.connect</option>
                    <option value="filesystem.read">filesystem.read</option>
                    <option value="filesystem.write">filesystem.write</option>
                    <option value="admin.operation">admin.operation</option>
                    <option value="session.authenticate">session.authenticate</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Target Resource / Path</label>
                  <input
                    id="sim-resource-input"
                    type="text"
                    value={simResource}
                    onChange={(e) => setSimResource(e.target.value)}
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
              </div>

              <button
                id="btn-run-simulation"
                onClick={handleSimulatePolicy}
                disabled={isSimulating}
                style={{
                  width: '100%', padding: '8px 14px', borderRadius: 6,
                  background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.3), rgba(245, 158, 11, 0.1))',
                  border: '1px solid var(--accent-amber)', color: '#fbbf24', fontWeight: 700,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  fontSize: '0.82rem'
                }}
              >
                <Zap size={14} />
                {isSimulating ? 'Simulating...' : 'Run Policy Simulation (Dry-Run)'}
              </button>

              {simResult && (
                <div
                  style={{
                    marginTop: 14, padding: 14, borderRadius: 8,
                    background: simResult.decision === 'allow' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
                    border: `1px solid ${simResult.decision === 'allow' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <span
                      style={{
                        fontSize: '0.78rem', fontWeight: 800, textTransform: 'uppercase', padding: '3px 10px', borderRadius: 6,
                        background: simResult.decision === 'allow' ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                        color: '#000'
                      }}
                    >
                      PROSPECTIVE: {simResult.decision.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Policy: {simResult.policy_id}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#fff', marginBottom: 4 }}>
                    <strong>Reason:</strong> {simResult.reason}
                  </div>
                  {simResult.matched_rule && (
                    <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      Matched: {simResult.matched_rule}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Graduated Containment Dispatcher & Active Commands */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            {/* Quick Dispatcher */}
            <div className="glass-panel" style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Key size={16} color="var(--accent-emerald)" />
                  Dispatch Signed Containment Command (Ed25519)
                </h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Action Type</label>
                  <select
                    id="dispatch-action-select"
                    value={dispatchAction}
                    onChange={(e) => setDispatchAction(e.target.value as any)}
                    style={{
                      width: '100%', background: '#131a2a', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem'
                    }}
                  >
                    <option value="REVOKE_SESSION">REVOKE_SESSION</option>
                    <option value="BLOCK_NETWORK">BLOCK_NETWORK</option>
                    <option value="REVOKE_CAPABILITY">REVOKE_CAPABILITY</option>
                    <option value="THROTTLE_ACTOR">THROTTLE_ACTOR</option>
                    <option value="RESTRICT_SCOPE">RESTRICT_SCOPE</option>
                    <option value="ISOLATE_SERVICE">ISOLATE_SERVICE</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Target Entity</label>
                  <input
                    id="dispatch-target-input"
                    type="text"
                    value={dispatchTarget}
                    onChange={(e) => setDispatchTarget(e.target.value)}
                    placeholder="session:sess_123 or ip:1.2.3.4"
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Scoped Capability (Optional)</label>
                  <input
                    id="dispatch-cap-input"
                    type="text"
                    value={dispatchCap}
                    onChange={(e) => setDispatchCap(e.target.value)}
                    placeholder="e.g. data.export"
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Mandatory TTL (Seconds)</label>
                  <input
                    id="dispatch-ttl-input"
                    type="number"
                    value={dispatchTtl}
                    onChange={(e) => setDispatchTtl(Number(e.target.value))}
                    style={{
                      width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
                      borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
              </div>

              <button
                id="btn-dispatch-containment"
                onClick={handleDispatchSignedCommand}
                style={{
                  width: '100%', padding: '8px 14px', borderRadius: 6,
                  background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.3), rgba(16, 185, 129, 0.1))',
                  border: '1px solid var(--accent-emerald)', color: '#6ee7b7', fontWeight: 700,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  fontSize: '0.82rem'
                }}
              >
                <Key size={14} />
                Sign & Dispatch Command (Ed25519)
              </button>
            </div>

            {/* Containment Commands Queue */}
            <div className="glass-panel" style={{ padding: 20, flex: 1, display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Clock size={16} color="var(--accent-cyan)" />
                  Signed Commands & Active Containment ({containmentCommands.length})
                </h3>
              </div>

              {containmentCommands.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '36px 0', color: 'var(--text-muted)' }}>
                  <Shield size={32} color="rgba(255,255,255,0.15)" style={{ margin: '0 auto 10px' }} />
                  <p style={{ margin: 0, fontSize: '0.85rem' }}>No containment actions dispatched</p>
                </div>
              ) : (
                <div style={{ overflowY: 'auto', maxHeight: 520, display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {containmentCommands.map((cmd) => {
                    const isActive = cmd.status === 'active';
                    return (
                      <div
                        key={cmd.command_id}
                        style={{
                          padding: 12, borderRadius: 8,
                          background: isActive ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255,255,255,0.02)',
                          border: `1px solid ${isActive ? 'rgba(16, 185, 129, 0.3)' : 'var(--border-subtle)'}`,
                          fontSize: '0.78rem'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                          <div>
                            <span
                              style={{
                                fontSize: '0.72rem', fontWeight: 800, padding: '2px 8px', borderRadius: 4, marginRight: 8,
                                background: isActive ? 'var(--accent-emerald)' : 'rgba(255,255,255,0.1)',
                                color: isActive ? '#000' : 'var(--text-muted)'
                              }}
                            >
                              {cmd.action}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                              {cmd.target_entity}
                            </span>
                          </div>
                          {isActive && (
                            <button
                              id={`btn-rollback-${cmd.command_id}`}
                              onClick={() => handleRollbackCommand(cmd.command_id)}
                              style={{
                                background: 'rgba(244, 63, 94, 0.15)', border: '1px solid var(--accent-rose)',
                                color: 'var(--accent-rose)', padding: '2px 8px', borderRadius: 4,
                                cursor: 'pointer', fontSize: '0.7rem', fontWeight: 700
                              }}
                            >
                              ↩ Rollback
                            </button>
                          )}
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: 4 }}>
                          <span>Status: <strong style={{ color: isActive ? 'var(--accent-emerald)' : 'var(--text-secondary)' }}>{cmd.status}</strong></span>
                          <span>TTL: <strong>{cmd.ttl_seconds}s</strong></span>
                        </div>

                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                          Sig: {cmd.signature.substring(0, 32)}...
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
