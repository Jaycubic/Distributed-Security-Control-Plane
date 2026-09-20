export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type SensorType = 'agent' | 'tetragon' | 'falco' | 'hubble' | 'network' | 'system';

export interface SensorMetadata {
  sensor_type: SensorType;
  raw_event_type: string;
  sensor_id?: string;
  raw_payload?: any;
}

export interface ActorContext {
  user_id?: string;
  role?: string;
  session_id?: string;
  auth_method?: string;
  client_fingerprint?: string;
}

export interface SourceContext {
  ip?: string;
  port?: number;
  user_agent?: string;
  sensor: SensorMetadata;
  container_id?: string;
  pid?: number;
  process_name?: string;
}

export interface ActionContext {
  method?: string;
  endpoint?: string;
  status_code?: number;
  duration_us?: number;
  is_success: boolean;
  operation?: string;
}

export interface ResourceContext {
  resource_type?: string;
  resource_id?: string;
  sensitivity_tier?: string;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  app_id: string;
  environment: string;
  event_type: string;
  severity: Severity;
  actor?: ActorContext;
  source: SourceContext;
  action?: ActionContext;
  resource?: ResourceContext;
  metadata?: Record<string, any>;
  is_security_significant?: boolean;
}

export interface ControlPlaneMetricsData {
  totalIngested: number;
  totalPersisted: number;
  activeApps: Set<string>;
  eventsPerSecond: number;
  connected: boolean;
}

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive';

export interface SecuritySignal {
  signal_id: string;
  rule_name: string;
  severity: Severity;
  description: string;
  risk_weight: number;
  timestamp: string;
  matched_event_ids: string[];
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  target_entity: string;
  app_id: string;
  risk_score: number;
  signals: SecuritySignal[];
  evidence: SecurityEvent[];
  created_at: string;
  updated_at: string;
}

export interface CanonicalEntity {
  entity_id: string;
  entity_type: 'host' | 'session' | 'workload' | 'user';
  display_name: string;
  linked_ips: string[];
  linked_sessions: string[];
  linked_user_ids: string[];
  linked_containers: string[];
  linked_pids: number[];
  apps_seen: string[];
  exercised_capabilities: string[];
  risk_score: number;
  first_seen: string;
  last_seen: string;
  event_count: number;
}

export interface GraphNode {
  id: string;
  category: 'entity' | 'application' | 'resource' | 'endpoint' | 'host';
  label: string;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  metadata: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  count: number;
  first_seen: string;
  last_seen: string;
  weight: number;
}

export interface CorrelationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// Phase 4: Capability Policies & Graduated Containment Types

export interface PolicyRule {
  capability: string;
  scope: string;
  description?: string;
}

export interface PolicyBundle {
  policy_id: string;
  version: number;
  target_app: string;
  description: string;
  allow: PolicyRule[];
  deny: PolicyRule[];
  default_allow: boolean;
}

export type DecisionOutcome = 'allow' | 'deny' | 'revoke' | 'restrict';

export interface PolicyDecision {
  decision_id: string;
  who: string;
  app_id: string;
  capability: string;
  target_resource: string;
  policy_id: string;
  decision: DecisionOutcome;
  reason: string;
  matched_rule?: string;
  is_simulation: boolean;
  evidence_event_ids: string[];
  timestamp: string;
}

export type ContainmentActionType =
  | 'REVOKE_SESSION'
  | 'THROTTLE_ACTOR'
  | 'BLOCK_NETWORK'
  | 'REVOKE_CAPABILITY'
  | 'RESTRICT_SCOPE'
  | 'ISOLATE_SERVICE';

export type ContainmentStatus = 'active' | 'expired' | 'rolled_back';

export interface SignedContainmentCommand {
  command_id: string;
  action: ContainmentActionType;
  target_entity: string;
  capability?: string;
  params: Record<string, string>;
  ttl_seconds: number;
  nonce: string;
  evidence_incident_id?: string;
  issued_at: string;
  expires_at: string;
  signer_public_key: string;
  signature: string;
  status: ContainmentStatus;
  rollback_recipe: string;
}
