export type PageKey = "dashboard" | "users" | "inbounds" | "outbounds" | "sections" | "config" | "service" | "settings";

export interface Settings {
  configPath: string;
  grpcEnabled: boolean;
  grpcAddress: string;
  firewallAutoOpen: boolean;
  publicBaseUrl: string;
  subscriptionHost: string;
  enforcementIntervalSeconds: number;
}

export interface Status {
  setupRequired: boolean;
  configPath: string;
  grpcEnabled: boolean;
  grpcAddress: string;
  grpcReachable: boolean;
  inbounds: number;
  outbounds: number;
  users: number;
  activeUsers: number;
  runCommand: string;
}

export interface Inbound {
  id: number;
  tag: string;
  listen: string;
  port: number;
  protocol: string;
  enabled: boolean;
  transport: string;
  settings: string;
  streamSettings: string;
  sniffing: string;
  limits: string;
  createdAt: string;
  updatedAt: string;
}

export interface InboundInput {
  tag: string;
  listen: string;
  port: number;
  protocol: string;
  enabled: boolean;
  transport: string;
  settings?: string;
  streamSettings?: string;
  sniffing?: string;
  limits?: string;
}

export interface Outbound {
  id: number;
  tag: string;
  protocol: string;
  enabled: boolean;
  settings: string;
  streamSettings: string;
  createdAt: string;
  updatedAt: string;
}

export interface OutboundInput {
  tag: string;
  protocol: string;
  enabled: boolean;
  settings?: string;
  streamSettings?: string;
}

export interface ConfigSection {
  name: string;
  enabled: boolean;
  value: string;
  updatedAt: string;
}

export interface ManagedUser {
  id: number;
  inboundId: number;
  email: string;
  uuid: string;
  flow: string;
  credential: Record<string, unknown>;
  note: string;
  enabled: boolean;
  trafficLimitBytes: number | null;
  expiryAt: string | null;
  uploadBytes: number;
  downloadBytes: number;
  subToken: string;
  enforcementStatus: string;
  createdAt: string;
  updatedAt: string;
}

export interface UserInput {
  inboundId: number;
  email: string;
  uuid: string;
  flow?: string;
  credential?: Record<string, unknown>;
  note?: string;
  enabled: boolean;
  trafficLimitBytes?: number | null;
  expiryAt?: string | null;
}

export interface LoginResponse {
  token: string;
  username: string;
}

export interface ApplyResult {
  configValid: boolean;
  configWritten: boolean;
  liveApplied: boolean;
  message: string;
}

export interface TrafficSnapshot {
  users: Array<{ email: string; uploadBytes: number; downloadBytes: number }>;
  inbounds: Array<{ tag: string; uploadBytes: number; downloadBytes: number }>;
}

export interface CapabilityItem {
  key: string;
  label: string;
  status: "supported" | "experimental" | "unsupported";
  notes: string;
}

export interface CapabilityMap {
  protocols: CapabilityItem[];
  transports: CapabilityItem[];
  security: CapabilityItem[];
  config: CapabilityItem[];
  runtime: CapabilityItem[];
}

export interface ServiceStatus {
  systemdAvailable: boolean;
  activeState: string;
  subState: string;
  logs: string[];
}

export interface AppData {
  status: Status | null;
  settings: Settings | null;
  inbounds: Inbound[];
  outbounds: Outbound[];
  sections: ConfigSection[];
  users: ManagedUser[];
  traffic: TrafficSnapshot;
  capabilities: CapabilityMap | null;
  service: ServiceStatus | null;
}
