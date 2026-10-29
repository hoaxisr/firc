import {
  array,
  boolean,
  fallback,
  length,
  nullable,
  number,
  object,
  optional,
  parse,
  picklist,
  pipe,
  regex,
  string,
  union,
  type InferOutput,
} from "valibot";

import { randomId } from "./utils/random-id";

declare global {
  interface WindowEventMap {
    overlay: CustomEvent<{
      content: string;
      type: "show" | "hide";
    }>;

    toast: CustomEvent<{
      content: string;
      type: "info" | "success" | "error" | "warning";
    }>;
  }
}

export function parseConfig(json: string): Config {
  return configFrom(JSON.parse(json));
}

export function configFrom(value: unknown): Config {
  return parse(ConfigSchema, value);
}

export const RuleSchema = object({
  enable: fallback(boolean(), true),
  /* A function, not a value: a value would give every record the same id. */
  id: fallback(pipe(string(), length(8), regex(/^[0-9a-f]{8}/)), () => randomId()),
  rule: string(),
  type: fallback(string(), "namespace"),
  proto: fallback(optional(picklist(["tcp", "udp"])), undefined),
  ports: fallback(optional(string()), undefined),
  comment: fallback(optional(string()), undefined),
});
export type Rule = InferOutput<typeof RuleSchema>;

export function ruleTakesPorts(type: string): boolean {
  return type === "subnet" || type === "subnet6";
}

export const DeviceSelectorSchema = object({
  allow: fallback(array(string()), []),
  deny: fallback(array(string()), []),
});
export type DeviceSelector = InferOutput<typeof DeviceSelectorSchema>;

export const ListRuleSchema = object({
  enable: fallback(boolean(), true),
  id: fallback(pipe(string(), length(8), regex(/^[0-9a-f]{8}/)), () => randomId()),
  rule: string(),
  type: fallback(string(), "namespace"),
  proto: fallback(optional(string()), undefined),
  ports: fallback(optional(string()), undefined),
});
export type ListRule = InferOutput<typeof ListRuleSchema>;

export const SyncStateSchema = object({
  state: fallback(picklist(["idle", "queued", "fetching", "error"]), "idle"),
  error: fallback(string(), ""),
  lastCheck: fallback(number(), 0),
});
export type SyncState = InferOutput<typeof SyncStateSchema>;

export const syncIdle = (): SyncState => ({ state: "idle", error: "", lastCheck: 0 });

export const GroupListSchema = object({
  url: fallback(string(), ""),
  interval: fallback(optional(number()), 86400),
  lastUpdate: fallback(optional(number()), 0),
  rulesTotal: fallback(number(), 0),
  sync: fallback(SyncStateSchema, syncIdle),
});
export type GroupList = InferOutput<typeof GroupListSchema>;

export const DEFAULT_RESOLVE = (): GroupResolve => ({ tunnel: true, server: "" });

export const GroupResolveSchema = object({
  tunnel: fallback(boolean(), true),
  server: fallback(string(), ""),
});
export type GroupResolve = InferOutput<typeof GroupResolveSchema>;

export const GroupResolverHealthSchema = object({
  window: fallback(number(), 600),
  total: fallback(number(), 0),
  fallbacks: fallback(number(), 0),
  last: fallback(number(), 0),
  reason: fallback(string(), ""),
  resting: fallback(boolean(), false),
  since: fallback(number(), 0),
});
export type GroupResolverHealth = InferOutput<typeof GroupResolverHealthSchema>;

const NO_HEALTH = (): GroupResolverHealth => ({
  window: 600,
  total: 0,
  fallbacks: 0,
  last: 0,
  reason: "",
  resting: false,
  since: 0,
});

export const GroupResolverSchema = object({
  source: fallback(picklist(["group", "firmware", "none", "off"]), "none"),
  servers: fallback(array(string()), []),
  health: fallback(GroupResolverHealthSchema, NO_HEALTH),
});
export type GroupResolver = InferOutput<typeof GroupResolverSchema>;

export type SystemResolvers = {
  resolvers: { interface: string; servers: string[] }[];
};

export const BLOCK_ANSWERS = ["null", "nxdomain", "refused"] as const;
export type BlockAnswer = (typeof BLOCK_ANSWERS)[number];

export const GroupSchema = object({
  id: fallback(pipe(string(), length(8), regex(/^[0-9a-f]{8}/)), () => randomId()),
  name: fallback(string(), ""),
  interface: union([string(), array(string())]),
  enable: fallback(boolean(), true),
  devices: fallback(DeviceSelectorSchema, { allow: [], deny: [] }),
  rules: array(RuleSchema),
  list: optional(nullable(GroupListSchema)),
  resolve: fallback(GroupResolveSchema, DEFAULT_RESOLVE),
  resolver: optional(GroupResolverSchema),
  block: optional(fallback(picklist(BLOCK_ANSWERS), "null")),
});
export type Group = InferOutput<typeof GroupSchema>;

export const ConfigSchema = object({
  groups: array(GroupSchema),
});
export type Config = InferOutput<typeof ConfigSchema>;

export const RULE_TYPES = [
  { value: "namespace", label: "Namespace" },
  { value: "wildcard", label: "Wildcard" },
  { value: "regex", label: "Regex" },
  { value: "domain", label: "Domain" },
  { value: "subnet", label: "IPv4 subnet" },
  { value: "subnet6", label: "IPv6 subnet" },
];

export type IfaceRole = "tunnel" | "wan" | "lan" | "other";

export type Interfaces = {
  interfaces: {
    id: string;
    name?: string;
    ndmsName?: string;
    role?: IfaceRole;
  }[];
};

export type TunnelUplink = { kind: "auto" | "iface" | "tunnel"; ref: string };

export type TunnelSource = {
  id: string;
  kind: "link" | "subscription";
  link?: string;
  name?: string;
  url?: string;
  interval?: number;
  headers?: Record<string, string>;
};

export type TunnelHeader = { name: string; value: string };

export type TunnelHeadersRes = { headers: TunnelHeader[] };

export type TunnelAdvanced = {
  ca: string;
  insecure: boolean;
  timeout: number;
  kernelTcp: boolean;
  fingerprint: "" | "chrome" | "firefox";
};

export type TunnelInbound = {
  port: number;
  listen: string;
  node: string;
  user: string;
  password: string;
};

export type TunnelInboundState = {
  port: number;
  state: "up" | "busy" | "no-node" | "no-address" | "not-lan" | "starting" | "off";
  why: string;
  rxBps: number;
  txBps: number;
};

export type Tunnel = {
  id: string;
  device: string;
  description: string;
  enable: boolean;
  active: number;
  by: "connection" | "site" | "site-client";
  interval: number;
  silence: number;
  filter: string;
  order: string[];
  exclude: string[];
  sources: TunnelSource[];
  uplink: TunnelUplink;
  advanced: TunnelAdvanced;
  inbounds: TunnelInbound[];
};

export type TunnelsRes = { tunnels: Tunnel[]; restarted?: string[]; updated?: string[] };

export type TunnelError = { error: string; field?: string | null; tunnel?: string | null };

export type TunnelStatus =
  | "off"
  | "starting"
  | "up"
  | "no_node"
  | "backoff"
  | "bad_config"
  | "waiting"
  | "uplink_down";

export type TunnelNodeState = {
  key: string;
  name: string;
  source: string;
  state: "active" | "down" | "reserve" | "excluded" | "missing" | "skipped";
  since: number;
  skipReason?: string;
  v6?: boolean;
};

export type TunnelSubUsage = {
  used: number;
  total: number;
  expire: number;
};

export type TunnelSubState = {
  name: string;
  nodes: number;
  fetching: boolean;
  lastOk: number;
  lastTry: number;
  error: string;
  usage?: TunnelSubUsage | null;
};

export type TunnelState = {
  id: string;
  device: string;
  status: TunnelStatus;
  since: number;
  backoffS: number;
  lastExit: number;
  uplinkOk: boolean;
  tcpPort: number;
  tcpSkipped: string[];
  tcpOff: "" | "acl" | "kernel" | "refused";
  active: string[];
  groups: string[];
  nodes: TunnelNodeState[];
  subscriptions: TunnelSubState[];
  rxBps: number;
  txBps: number;
  inbounds: TunnelInboundState[];
};

export type TunnelPreviewRow = {
  key: string;
  name: string;
  source: string;
  isNew: boolean;
  missing: boolean;
  excluded: boolean;
  overCap: boolean;
  skipReason?: string;
};

export type TunnelPreview = {
  total: number;
  matched: number;
  nodes: TunnelPreviewRow[];
  subscriptions: { name: string; cached: boolean }[];
};

export type TunnelProbeRow = {
  key: string;
  ok: boolean;
  why: string;
  handshakeMs: number | null;
  firstByteMs: number | null;
};
