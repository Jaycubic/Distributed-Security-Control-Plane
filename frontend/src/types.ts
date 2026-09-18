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
