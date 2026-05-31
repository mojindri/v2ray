import type {
  ApplyResult,
  CapabilityMap,
  ConfigSection,
  Inbound,
  InboundInput,
  LoginResponse,
  ManagedUser,
  Outbound,
  OutboundInput,
  ServiceStatus,
  Settings,
  Status,
  TrafficSnapshot,
  UserInput
} from "./types";

const SESSION_MARKER_KEY = "black-ui-session";

export function getToken(): string {
  return sessionStorage.getItem(SESSION_MARKER_KEY) ?? "";
}

export function setToken(): void {
  sessionStorage.setItem(SESSION_MARKER_KEY, "cookie");
}

export function clearToken(): void {
  sessionStorage.removeItem(SESSION_MARKER_KEY);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  const res = await fetch(path, { ...options, credentials: "same-origin", headers });
  const contentType = res.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const message = typeof payload === "object" && payload && "error" in payload ? String(payload.error) : String(payload);
    throw new Error(message || `${res.status} ${res.statusText}`);
  }
  return payload as T;
}

const body = (value: unknown): RequestInit => ({
  method: "POST",
  body: JSON.stringify(value)
});

export const api = {
  status: () => request<Status>("/api/status"),
  capabilities: () => request<CapabilityMap>("/api/capabilities"),
  me: () => request<{ username: string }>("/api/auth/me"),
  setup: (username: string, password: string) =>
    request<LoginResponse>("/api/auth/setup", body({ username, password })),
  login: (username: string, password: string) =>
    request<LoginResponse>("/api/auth/login", body({ username, password })),
  logout: () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  settings: () => request<Settings>("/api/settings"),
  updateSettings: (settings: Settings) =>
    request<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(settings) }),
  traffic: () => request<TrafficSnapshot>("/api/runtime/traffic"),
  probe: () => request<{ reachable: boolean; address: string }>("/api/runtime/probe", { method: "POST" }),
  inbounds: () => request<Inbound[]>("/api/inbounds"),
  createInbound: (input: InboundInput) => request<ApplyResult>("/api/inbounds", body(input)),
  updateInbound: (id: number, input: InboundInput) =>
    request<ApplyResult>(`/api/inbounds/${id}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteInbound: (id: number) => request<ApplyResult>(`/api/inbounds/${id}`, { method: "DELETE" }),
  outbounds: () => request<Outbound[]>("/api/outbounds"),
  createOutbound: (input: OutboundInput) => request<ApplyResult>("/api/outbounds", body(input)),
  updateOutbound: (id: number, input: OutboundInput) =>
    request<ApplyResult>(`/api/outbounds/${id}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteOutbound: (id: number) => request<ApplyResult>(`/api/outbounds/${id}`, { method: "DELETE" }),
  users: () => request<ManagedUser[]>("/api/users"),
  createUser: (input: UserInput) => request<ApplyResult>("/api/users", body(input)),
  updateUser: (id: number, input: UserInput) =>
    request<ApplyResult>(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteUser: (id: number) => request<ApplyResult>(`/api/users/${id}`, { method: "DELETE" }),
  enableUser: (id: number) => request<ApplyResult>(`/api/users/${id}/enable`, { method: "POST" }),
  disableUser: (id: number) => request<ApplyResult>(`/api/users/${id}/disable`, { method: "POST" }),
  resetUsage: (id: number) => request<ManagedUser>(`/api/users/${id}/reset-usage`, { method: "POST" }),
  rotateUuid: (id: number) => request<ApplyResult>(`/api/users/${id}/rotate-uuid`, { method: "POST" }),
  rotateSubToken: (id: number) => request<ManagedUser>(`/api/users/${id}/rotate-sub-token`, { method: "POST" }),
  bulkUsers: (payload: {
    userIds: number[];
    action: string;
    trafficLimitBytes?: number | null;
    expiryAt?: string | null;
  }) => request<ApplyResult>("/api/users/bulk", body(payload)),
  uuid: () => request<{ uuid: string }>("/api/uuid", { method: "POST" }),
  sections: () => request<ConfigSection[]>("/api/config/sections"),
  updateSection: (name: string, input: { enabled: boolean; value: string }) =>
    request<ApplyResult>(`/api/config/sections/${encodeURIComponent(name)}`, { method: "PUT", body: JSON.stringify(input) }),
  configPreview: () => request<unknown>("/api/config/preview"),
  configImport: (value: unknown) => request<ApplyResult>("/api/config/import", body(value)),
  configValidate: () => request<{ valid: true }>("/api/config/validate", { method: "POST" }),
  configWrite: () => request<ApplyResult>("/api/config/write", { method: "POST" }),
  configApply: () => request<ApplyResult>("/api/config/apply", { method: "POST" }),
  serviceStatus: () => request<ServiceStatus>("/api/service/status"),
  serviceRestartBlackwire: () => request<ServiceStatus>("/api/service/restart-blackwire", { method: "POST" }),
  serviceLogs: () => request<string[]>("/api/service/logs")
};
