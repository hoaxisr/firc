import { Hono } from "hono";
import { cors } from "hono/cors";
import { serveStatic } from "hono/deno";
import { logger } from "hono/logger";
import { streamSSE } from "hono/streaming";

import type { Interfaces } from "../src/types.ts";

const API_BASE = "/api/v1";

const INTERFACES: Interfaces = {
  interfaces: [
    { id: "nwg0" },
    { id: "longinterf" },
    { id: "eth1" },
    { id: "wg0", name: "WireGuard Interface" },
  ],
};

const RESOLVERS = {
  resolvers: [
    { interface: "nwg0", servers: ["9.9.9.9", "1.0.0.1"] },
    { interface: "wg0", servers: ["1.1.1.1", "1.0.0.1"] },
  ],
};

/* Fallbacks since "start", so the panel's count has something to show. */
const FALLBACKS: Record<string, number> = {};

function resolverOf(group: any) {
  const resolve = group.resolve ?? { tunnel: true, server: "" };
  const fallbacks = FALLBACKS[group.id] ?? 0;
  const live = (servers: string[]) => (group.enable === false ? [] : servers);
  if (!resolve.tunnel) return { source: "off", servers: [], fallbacks };
  if (group.interface === "blackhole") return { source: "none", servers: [], fallbacks };
  if (resolve.server) return { source: "group", servers: live([resolve.server]), fallbacks };
  const fw = RESOLVERS.resolvers.find((r) => r.interface === group.interface)?.servers ?? [];
  return fw.length
    ? { source: "firmware", servers: live(fw), fallbacks }
    : { source: "none", servers: [], fallbacks };
}

function resolveRefusal(group: any): { error: string; field: string; group: string } | null {
  const server: string = group?.resolve?.server ?? "";
  if (!server) return null;
  const host = server.startsWith("[")
    ? server.slice(1, server.indexOf("]"))
    : server.split(":").length === 2
      ? server.split(":")[0]
      : server;
  if (["0.0.0.0", "::", "::1"].includes(host) || host.startsWith("127.")) {
    return {
      error: `resolve.server "${server}" is a sink address`,
      field: "resolve.server",
      group: group.id,
    };
  }
  if (/^198\.(18|19)\./.test(host)) {
    return {
      error: `resolve.server "${server}" is inside firc's address pool`,
      field: "resolve.server",
      group: group.id,
    };
  }
  return null;
}

const DATA = JSON.parse(Deno.readTextFileSync("./dev/groups.json"));
if (DATA.groups[0]) FALLBACKS[DATA.groups[0].id] = 3;

if (!DATA.groups.some((g: any) => g.id === "a1b2c3d4")) {
  DATA.groups.push({
    id: "a1b2c3d4",
    name: "Bad Bad Services",
    interface: "blackhole",
    enable: true,
    devices: { allow: [], deny: [] },
    rules: [],
    list: {
      url: "https://services.should.be.blocked.com",
      interval: 86400,
      lastUpdate: Math.floor(Date.now() / 1000),
      sync: { state: "idle", error: "", lastCheck: 0 },
      syncProgress: null,
      rules: [
        { enable: true, id: "11223344", rule: "google.com", type: "domain" },
        { enable: true, id: "55667788", rule: "facebook.com", type: "domain" },
      ],
    },
  });
}

const LIVE_REASONS: Record<string, string> = {};
let NETFILTER: Record<string, unknown> = { ok: true };

function liveOf(group: any): { live: boolean; liveReason?: string } {
  if (group.enable === false) return { live: false, liveReason: "disabled" };
  const forced = LIVE_REASONS[group.id];
  if (forced && forced !== "not-written") return { live: false, liveReason: forced };
  if (group.interface === "longinterf") return { live: false, liveReason: "no-interface" };
  if (forced === "not-written" || NETFILTER.ok === false) {
    return { live: false, liveReason: "not-written" };
  }
  return { live: true };
}

function groupRes({ list, rules: handRules, ...group }: any, withRules = false) {
  const withResolve = { ...group, resolve: group.resolve ?? { tunnel: true, server: "" } };
  const out: any = withRules ? { ...withResolve, rules: handRules } : { ...withResolve };
  out.resolver = resolverOf(withResolve);
  Object.assign(out, liveOf(withResolve));
  if (!list) return out;
  const { rules, syncProgress: _syncProgress, ...listMeta } = list;
  return { ...out, list: { ...listMeta, rulesTotal: rules?.length ?? 0 } };
}

function syncStage(list: any) {
  const progress = list.syncProgress ?? { stage: "fetch", bytes: 0, total: 0, lines: 0 };
  if (progress.stage === "parse") return { stage: "parse", lines: progress.lines };
  if (progress.stage === "apply") return { stage: "apply" };
  return { stage: "fetch", bytes: progress.bytes, total: progress.total };
}

function runSync(list: any) {
  const total = 7786120;
  let bytes = 0;
  list.sync = { state: "fetching", error: "", lastCheck: list.sync?.lastCheck ?? 0 };
  list.syncProgress = { stage: "fetch", bytes: 0, total, lines: 0 };

  const tick = () => {
    bytes = Math.min(total, bytes + Math.round(total / 6));
    if (bytes < total) {
      list.syncProgress = { stage: "fetch", bytes, total, lines: 0 };
      setTimeout(tick, 400);
      return;
    }

    list.syncProgress = { stage: "parse", bytes, total, lines: 120000 };
    setTimeout(() => {
      list.syncProgress = { stage: "apply", bytes, total, lines: 120000 };
      setTimeout(() => {
        const now = Math.floor(Date.now() / 1000);
        if (Math.random() < 0.2) {
          list.sync = { state: "error", error: "fetch failed: HTTP 404", lastCheck: now };
          return;
        }
        const count = Math.floor(Math.random() * 70) + 5;
        list.rules = Array.from({ length: count }).map((_, i) =>
          i % 5 === 0
            ? {
                enable: true,
                id: Math.random().toString(16).substring(2, 10),
                rule: "66.22.192.0/18",
                type: "subnet",
                proto: "udp",
                ports: "50000-50099",
              }
            : {
                enable: true,
                id: Math.random().toString(16).substring(2, 10),
                rule: `mock.rule.${Math.random().toString(36).substring(7)}.com`,
                type: Math.random() < 0.5 ? "namespace" : "domain",
              },
        );
        list.lastUpdate = now;
        list.sync = { state: "idle", error: "", lastCheck: now };
      }, 400);
    }, 600);
  };

  setTimeout(tick, 400);
}

const EVENTS_RING = 4096;
const EVENTS_BOOT = `${Math.floor(Date.now() / 1000).toString(16)}-${crypto
  .randomUUID()
  .slice(0, 8)}`;
type DnsDecision = "issued" | "not-covered" | "no-match" | "pool-refused" | "passed";
type Event =
  | { seq: number; at: number; kind: "log"; level: string; message: string }
  | {
      seq: number;
      at: number;
      kind: "dns";
      client: string;
      name: string;
      qtype: string;
      rcode: string;
      decision: DnsDecision;
      group?: { id: string; name: string };
      fake?: string;
      reals: string[];
    }
  | {
      seq: number;
      at: number;
      kind: "bypass";
      client: string;
      dst: string;
      port?: number;
      proto: string;
      how: "addr" | "sni";
      name: string;
      group?: { id: string; name: string };
      last?: { decision: DnsDecision; at: number; fake?: string };
      repeats: number;
    };
type Fresh<E> = E extends unknown ? Omit<E, "seq" | "at"> : never;
const EVENTS: Event[] = [];
let eventSeq = 0;
const LOG_SAMPLES: [string, string][] = [
  ["info", "netfilter rebuilt: 3 group(s), 1 subscription(s)"],
  ["debug", "committer: request folded into the running pass"],
  ["info", 'subscription "Bad Bad Services" synced: 1204 rule(s)'],
  ["warn", 'group Example routes nothing: "" is not an interface name'],
  ["debug", "pool: 12 name(s) idle past the window, quarantined"],
  ["error", "upstream 127.0.0.1:53 did not answer within 2s"],
];
function pushEvent(e: Fresh<Event>) {
  eventSeq += 1;
  EVENTS.push({ ...e, seq: eventSeq, at: Math.floor(Date.now() / 1000) });
  if (EVENTS.length > EVENTS_RING) EVENTS.shift();
}
function pushLogLine() {
  const [level, message] = LOG_SAMPLES[Math.floor(Math.random() * LOG_SAMPLES.length)];
  pushEvent({ kind: "log", level, message });
}

const DNS_CLIENTS = ["192.168.1.42", "192.168.1.51"];
const DNS_NAMES = ["youtube.com", "googlevideo.com", "ya.ru", "example.com"];
const ROUTED_NAMES = new Set(["youtube.com", "googlevideo.com"]);
let dnsN = 0;
function pushDnsEvent() {
  const client = DNS_CLIENTS[Math.floor(Math.random() * DNS_CLIENTS.length)];
  const name = DNS_NAMES[Math.floor(Math.random() * DNS_NAMES.length)];
  if (ROUTED_NAMES.has(name)) {
    dnsN += 1;
    pushEvent({
      kind: "dns",
      client,
      name,
      qtype: "A",
      rcode: "NOERROR",
      decision: "issued",
      group:
        dnsN % 4 === 0
          ? { id: "deadbeef", name: "Old Group" }
          : { id: "g1g1g1g1", name: "Example Group" },
      fake: `198.18.0.${dnsN}`,
      reals: [`142.250.1.${dnsN}`],
    });
    return;
  }
  pushEvent({
    kind: "dns",
    client,
    name,
    qtype: "A",
    rcode: "NOERROR",
    decision: "no-match",
    reals: [],
  });
}

const BYPASS_CLIENTS = ["192.168.1.42", "192.168.1.51", "192.168.1.77"];
const BYPASS_ADDR_NAMES = ["cdn.example.net", "edge.example.net"];
const BYPASS_SNI_NAMES = ["news.example.com", "bank.example.org"];
let bypassSeq = 0;
function pushBypassEvent() {
  bypassSeq += 1;
  const how: "addr" | "sni" = bypassSeq % 2 === 0 ? "addr" : "sni";
  const client = BYPASS_CLIENTS[bypassSeq % BYPASS_CLIENTS.length];
  const name =
    how === "addr"
      ? BYPASS_ADDR_NAMES[bypassSeq % BYPASS_ADDR_NAMES.length]
      : BYPASS_SNI_NAMES[bypassSeq % BYPASS_SNI_NAMES.length];
  const withLast = bypassSeq % 3 !== 0;
  const last = withLast
    ? {
        decision: (bypassSeq % 6 === 1 ? "not-covered" : "issued") as DnsDecision,
        at: Math.floor(Date.now() / 1000) - 30,
        ...(bypassSeq % 6 === 1 ? {} : { fake: `198.18.0.${(bypassSeq % 200) + 1}` }),
      }
    : undefined;
  pushEvent({
    kind: "bypass",
    client,
    dst: `104.21.0.${(bypassSeq % 250) + 1}`,
    port: 443,
    proto: bypassSeq % 4 === 0 ? "tcp" : "udp",
    how,
    name,
    group: { id: "g1g1g1g1", name: "Example Group" },
    last,
    repeats: bypassSeq % 5 === 0 ? bypassSeq % 4 : 0,
  });
}

for (let i = 0; i < 20; i++) pushLogLine();
setInterval(pushLogLine, 2000);
setInterval(pushDnsEvent, 1000);

const PORT = 6969;
const STATIC_TOKEN = "firc_mock_token_2026";
const AUTH_ENABLED = true;

const app = new Hono();

app.use(logger());
app.use(cors());

app.use(`${API_BASE}/*`, async (c, next) => {
  if (c.req.path === `${API_BASE}/auth` || !AUTH_ENABLED) {
    await next();
    return;
  }

  const authHeader = c.req.header("Authorization");
  if (authHeader !== `Bearer ${STATIC_TOKEN}` && authHeader !== `Bearer disabled`) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  await next();
});

/* Registered before the routes: Hono runs a middleware only for routes registered after it. */
let RESTART_UNTIL = 0;
let RESTARTING = false;
let BOOT = crypto.randomUUID();
app.use(`${API_BASE}/*`, async (c, next) => {
  if (Date.now() < RESTART_UNTIL) return c.text("", 503);
  if (RESTARTING) {
    RESTARTING = false;
    BOOT = crypto.randomUUID();
    RUNNING = structuredClone(SAVED);
  }
  await next();
});

app.get(`${API_BASE}/auth`, async (c) => {
  return c.json({ enabled: AUTH_ENABLED }, 200);
});

app.post(`${API_BASE}/auth`, async (c) => {
  const body = await c.req.json();
  if (body.login === "root" && body.password === "keenetic") {
    return c.json({ token: STATIC_TOKEN });
  }
  return c.json({ error: "Invalid credentials" }, 403);
});

function portsAreReadable(ports: string): boolean {
  if (!/^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$/.test(ports)) return false;
  let slots = 0;
  for (const entry of ports.split(",")) {
    const [from, to = from] = entry.split("-").map(Number);
    if (from < 1 || from > 65535) return false;
    if (to > 65535 || to < from) return false;
    slots += from === to ? 1 : 2;
  }
  return slots <= 15;
}

function ruleRefusal(rule: any): string | null {
  const rawProto = rule?.proto;
  const rawPorts = rule?.ports;
  const protoGiven = rawProto !== undefined && rawProto !== null;
  const portsGiven = rawPorts !== undefined && rawPorts !== null;
  if (
    (protoGiven && typeof rawProto !== "string") ||
    (portsGiven && typeof rawPorts !== "string")
  ) {
    return "proto and ports are strings";
  }
  const proto: string = protoGiven ? rawProto : "";
  const ports: string = portsGiven ? rawPorts : "";
  if (proto === "" && ports === "") return null;
  if (rule?.type !== "subnet" && rule?.type !== "subnet6") {
    return "proto and ports apply to subnet and subnet6 rules only";
  }
  if (proto === "") return "ports need a protocol (tcp or udp)";
  if (proto !== "tcp" && proto !== "udp") return "proto is tcp or udp";
  if (ports !== "" && !portsAreReadable(ports)) {
    return "ports are a comma-separated list of ports or ranges, like 53,1000-2000 (at most 15 ports, a range counts as two)";
  }
  return null;
}

app.get(`${API_BASE}/groups`, (c) => {
  const withRules = c.req.query("with_rules") === "true";
  return c.json({ groups: DATA.groups.map((g: any) => groupRes(g, withRules)) });
});

function listUrlIsSupported(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function applyListFromReq(
  existing: any,
  body: any,
): { list: any; startSync: boolean; refusal?: string } {
  if (!("list" in body)) return { list: existing?.list, startSync: false };
  if (body.list === null || body.list === undefined) return { list: undefined, startSync: false };

  const incoming = body.list;
  const url = typeof incoming.url === "string" ? incoming.url : (existing?.list?.url ?? "");
  if (!listUrlIsSupported(url)) {
    return { list: existing?.list, startSync: false, refusal: "list url must be http or https" };
  }
  const interval =
    incoming.interval !== undefined ? incoming.interval : (existing?.list?.interval ?? 0);

  if (existing?.list && existing.list.url === url) {
    /* In place: a running sync writes its state onto this very object. */
    Object.assign(existing.list, { url, interval });
    return { list: existing.list, startSync: false };
  }

  return {
    list: {
      url,
      interval,
      lastUpdate: 0,
      sync: { state: "queued", error: "", lastCheck: existing?.list?.sync?.lastCheck ?? 0 },
      syncProgress: null,
      rules: [],
    },
    startSync: true,
  };
}

app.put(`${API_BASE}/groups`, async (c) => {
  const body = await c.req.json();
  console.debug("recieved", body?.groups?.length, "groups");

  for (const group of body?.groups ?? []) {
    for (const rule of group?.rules ?? []) {
      const refusal = ruleRefusal(rule);
      if (refusal) return c.json({ error: refusal }, 400);
    }
  }

  for (const group of body?.groups ?? []) {
    const refusal = resolveRefusal(group);
    if (refusal) return c.json(refusal, 400);
  }

  await new Promise((resolve) => setTimeout(resolve, 2000));
  if (Math.random() < 0.5) {
    return c.json({ error: "random error" }, 500);
  }

  /* Validated in a pass of its own: applyListFromReq mutates lists in place. */
  for (const group of body?.groups ?? []) {
    if (!("list" in group) || group.list === null || group.list === undefined) continue;
    const existing: any = DATA.groups.find((g: any) => g.id === group.id);
    const url = typeof group.list.url === "string" ? group.list.url : (existing?.list?.url ?? "");
    if (!listUrlIsSupported(url)) {
      return c.json({ error: "list url must be http or https" }, 400);
    }
  }

  const toSync: any[] = [];
  const next = (body?.groups ?? []).map((group: any) => {
    const existing: any = DATA.groups.find((g: any) => g.id === group.id);
    const { list: _requestedList, resolver: _requestedResolver, ...rest } = group;
    const { list, startSync } = applyListFromReq(existing, group);
    const merged: any = { ...rest };
    if (list !== undefined) merged.list = list;
    if (startSync) toSync.push(list);
    return merged;
  });

  DATA.groups = next;
  for (const list of toSync) runSync(list);
  return c.json({ groups: DATA.groups.map((g: any) => groupRes(g, true)) });
});

const readSizeParam = (raw: string | undefined, dflt: number): number | null => {
  if (raw === undefined || raw === "") return dflt;
  if (!/^[0-9]+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
};

app.get(`${API_BASE}/groups/:id{[0-9a-f]{8}}/list/rules`, (c) => {
  const group: any = DATA.groups.find((g: any) => g.id === c.req.param("id"));
  if (!group) return c.json({ error: "group not found" }, 404);
  if (!group.list) return c.json({ error: "group has no list" }, 404);
  const offset = readSizeParam(c.req.query("offset"), 0);
  if (offset === null) return c.json({ error: "invalid offset" }, 400);
  const asked = readSizeParam(c.req.query("limit"), 50);
  if (asked === null) return c.json({ error: "invalid limit" }, 400);
  const limit = Math.min(asked || 50, 500);
  const q = (c.req.query("q") ?? "").toLowerCase();
  const matches = (group.list.rules ?? []).filter(
    (r: any) => !q || r.rule.toLowerCase().includes(q),
  );
  return c.json({
    total: group.list.rules?.length ?? 0,
    matched: matches.length,
    offset,
    rules: matches.slice(offset, offset + limit),
  });
});

app.patch(`${API_BASE}/groups/:id/list/rules`, async (c) => {
  const group: any = DATA.groups.find((g: any) => g.id === c.req.param("id"));
  if (!group) return c.json({ error: "group not found" }, 404);
  if (!group.list) return c.json({ error: "group has no list" }, 404);
  const body = await c.req.json();
  const staged: { rule: any; edit: any }[] = [];
  for (const edit of body.rules ?? []) {
    if (edit.rule !== undefined) {
      return c.json({ error: "a list's pattern comes from the list itself" }, 400);
    }
    const rule = (group.list.rules ?? []).find((r: any) => r.id === edit.id);
    if (!rule) return c.json({ error: "rule not found" }, 404);
    staged.push({ rule, edit });
  }
  for (const { rule, edit } of staged) {
    if (edit.type !== undefined) rule.type = edit.type;
    if (edit.enable !== undefined) rule.enable = edit.enable;
  }
  return c.json({ status: "ok" });
});

app.get(`${API_BASE}/groups/list/preview`, (c) => {
  const url = c.req.query("url");
  if (!url) return c.json({ error: "list url is required" }, 400);
  if (Math.random() < 0.5) {
    return c.json({ error: "list fetch failed" }, 502);
  }

  const count = Math.random() < 0.2 ? 0 : Math.floor(Math.random() * 50) + 5;
  const rules = Array.from({ length: count }).map((_, i) =>
    i % 5 === 0
      ? {
          enable: true,
          id: Math.random().toString(16).substring(2, 10),
          rule: "66.22.192.0/18",
          type: "subnet",
          proto: "udp",
          ports: "50000-50099",
        }
      : {
          enable: true,
          id: Math.random().toString(16).substring(2, 10),
          rule: `mock.rule.${Math.random().toString(36).substring(7)}.com`,
          type: Math.random() < 0.5 ? "namespace" : "domain",
        },
  );

  const byType: Record<string, number> = {};
  for (const rule of rules) byType[rule.type] = (byType[rule.type] ?? 0) + 1;
  const dropped = count % 7;
  const unconstrained = count % 3;
  return c.json({
    rules: rules.slice(0, 100),
    total: rules.length,
    byType,
    dropped,
    unconstrained,
  });
});

app.post(`${API_BASE}/groups/:id/list/sync`, async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));
  console.debug("queued a sync", id, body);
  const group: any = DATA.groups.find((g: any) => g.id === id);
  if (!group) return c.json({ error: "group not found" }, 404);
  if (!group.list) return c.json({ error: "group has no list" }, 404);

  if (body?.url) group.list.url = body.url;
  group.list.sync = { state: "queued", error: "", lastCheck: group.list.sync?.lastCheck ?? 0 };
  runSync(group.list);
  return c.json(groupRes(group), 202);
});

app.get(`${API_BASE}/groups/:id/list/sync/events`, (c) => {
  const id = c.req.param("id");
  const group: any = DATA.groups.find((g: any) => g.id === id);
  if (!group) return c.json({ error: "group not found" }, 404);
  if (!group.list) return c.json({ error: "group has no list" }, 404);

  return streamSSE(c, async (stream) => {
    for (;;) {
      const state = group.list.sync?.state ?? "idle";
      if (state === "error") {
        await stream.writeSSE({
          event: "error",
          data: JSON.stringify({ error: group.list.sync.error }),
        });
        return;
      }
      if (state === "idle") {
        await stream.writeSSE({ event: "done", data: JSON.stringify(groupRes(group)) });
        return;
      }
      await stream.writeSSE({ event: "progress", data: JSON.stringify(syncStage(group.list)) });
      await stream.sleep(300);
    }
  });
});

app.get(`${API_BASE}/system/interfaces`, (c) => c.json(INTERFACES));

app.get(`${API_BASE}/system/resolvers`, (c) => c.json(RESOLVERS));

const POLICIES = {
  policies: [
    { name: "Policy0", description: "Kids", devices: 2 },
    { name: "Policy1", devices: 1 },
  ],
};

const HOSTS = {
  hosts: [
    {
      mac: "aa:00:00:00:00:01",
      name: "Living room TV",
      ip: "192.168.1.5",
      ip6: ["fd00::5"],
      active: true,
      registered: true,
      policy: "Policy0",
    },
    {
      mac: "aa:00:00:00:00:02",
      name: "Laptop",
      ip: "192.168.1.6",
      ip6: [],
      active: false,
      registered: true,
      policy: "",
    },
    {
      mac: "aa:00:00:00:00:03",
      name: "Phone",
      ip: "192.168.1.7",
      ip6: ["fd00::7", "2001:db8::7"],
      active: true,
      registered: true,
      policy: "Policy0",
    },
    {
      mac: "aa:00:00:00:00:04",
      name: "",
      ip: "192.168.1.8",
      ip6: [],
      active: true,
      registered: false,
      policy: "Policy1",
    },
  ],
};

app.get(`${API_BASE}/system/policies`, (c) => c.json(POLICIES));

app.get(`${API_BASE}/system/hosts`, (c) => c.json(HOSTS));

const SETTINGS_DEFAULTS: Record<string, unknown> = {
  "app.dnsProxy.upstream.address": "127.0.0.1",
  "app.dnsProxy.upstream.port": 53,
  "app.dnsProxy.disableDropAAAA": false,
  "app.dnsProxy.unmatchedTtl": 60,
  "app.dnsProxy.timeout": 5000,
  "app.dnsProxy.maxConcurrent": 100,
  "app.dnsProxy.maxIdleConns": 10,
  "app.dnsProxy.host.address": "[::]",
  "app.dnsProxy.host.port": 3553,
  "app.dnsProxy.disableRemap53": false,
  "app.addressPool.ttlClamp": 300,
  "app.addressPool.idleWindow": 24,
  "app.addressPool.maxNames": 65536,
  "app.addressPool.v4.pool": "198.18.0.0/15",
  "app.addressPool.v4.chunk": 24,
  "app.addressPool.v6.pool": "",
  "app.addressPool.v6.chunk": 64,
  "app.netfilter.disableIPv4": false,
  "app.netfilter.disableIPv6": false,
  "app.link": ["br0"],
  "app.netfilter.iptables.chainPrefix": "FIRC_",
  "app.netfilter.startMarkTableIndex": "0x66697263",
  "app.showAllInterfaces": false,
  "app.httpWeb.host.address": "[::]",
  "app.httpWeb.host.port": 8080,
  "app.logLevel": "info",
};
const SETTINGS_LIVE = new Set([
  "app.dnsProxy.upstream.address",
  "app.dnsProxy.upstream.port",
  "app.dnsProxy.disableDropAAAA",
  "app.dnsProxy.unmatchedTtl",
  "app.showAllInterfaces",
  "app.logLevel",
]);
let SAVED: Record<string, unknown> = structuredClone(SETTINGS_DEFAULTS);
let RUNNING: Record<string, unknown> = structuredClone(SETTINGS_DEFAULTS);
const sameSetting = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const settingsClasses = () =>
  Object.fromEntries(
    Object.keys(SETTINGS_DEFAULTS).map((k) => [k, SETTINGS_LIVE.has(k) ? "live" : "restart"]),
  );
const pendingRestart = () =>
  Object.keys(SAVED).filter((k) => !SETTINGS_LIVE.has(k) && !sameSetting(SAVED[k], RUNNING[k]));

app.get(`${API_BASE}/system/settings`, (c) =>
  c.json({
    settings: SAVED,
    classes: settingsClasses(),
    pendingRestart: pendingRestart(),
    boot: BOOT,
    restarting: RESTARTING,
  }),
);

const SETTINGS_LEVELS = [
  "trace",
  "debug",
  "info",
  "warn",
  "error",
  "fatal",
  "panic",
  "nolevel",
  "disabled",
];

function settingRefusal(key: string, value: unknown): string | null {
  if (!(key in SETTINGS_DEFAULTS)) return "not a setting";
  const want = SETTINGS_DEFAULTS[key];
  if (Array.isArray(want)) {
    return Array.isArray(value) && value.every((v) => typeof v === "string")
      ? null
      : "must be a list of strings";
  }
  if (typeof want === "boolean") return typeof value === "boolean" ? null : "must be true or false";
  if (typeof want === "number") {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
      return "must be a whole number in the setting's range";
    }
    if (key.endsWith(".port") && (value < 1 || value > 65535)) return "a port is 1-65535";
    return null;
  }
  if (typeof value !== "string") return "must be a string";
  if (key === "app.logLevel" && !SETTINGS_LEVELS.includes(value)) {
    return "one of trace, debug, info, warn, error, fatal, panic, nolevel, disabled";
  }
  return null;
}

app.put(`${API_BASE}/system/settings`, async (c) => {
  const body = await c.req.json().catch(() => null);
  const changes = body?.settings;
  if (typeof changes !== "object" || changes === null || Array.isArray(changes)) {
    return c.json({ error: 'the body is {"settings": {"<yaml path>": <value>}}' }, 400);
  }
  for (const [key, value] of Object.entries(changes)) {
    const refused = settingRefusal(key, value);
    if (refused) return c.json({ error: refused, field: key }, 400);
  }
  const applied: string[] = [];
  for (const [key, value] of Object.entries(changes)) {
    if (sameSetting(SAVED[key], value)) continue;
    SAVED[key] = value;
    if (SETTINGS_LIVE.has(key)) {
      RUNNING[key] = value;
      applied.push(key);
    }
  }
  return c.json({ applied, pendingRestart: pendingRestart() });
});

app.post(`${API_BASE}/system/restart`, (c) => {
  if (RESTARTING) return c.json({ error: "a restart is already under way" }, 409);
  RESTART_UNTIL = Date.now() + 3000;
  RESTARTING = true;
  return c.json({ restarting: true }, 202);
});

const CAPTURE_SECONDS = 300;
let CAPTURE: { token: string; endsAt: number } | null = null;

function captureStatus(withToken: boolean) {
  const now = Math.floor(Date.now() / 1000);
  if (CAPTURE && CAPTURE.endsAt <= now) CAPTURE = null;
  if (!CAPTURE) return { running: false };
  return {
    running: true,
    endsAt: CAPTURE.endsAt,
    secondsLeft: CAPTURE.endsAt - now,
    ...(withToken ? { token: CAPTURE.token } : {}),
  };
}

app.get(`${API_BASE}/system/capture`, (c) => c.json(captureStatus(false)));

app.post(`${API_BASE}/system/capture`, (c) => {
  if (captureStatus(false).running) return c.json({ error: "a capture is already running" }, 409);
  CAPTURE = {
    token: "0123456789abcdef",
    endsAt: Math.floor(Date.now() / 1000) + CAPTURE_SECONDS,
  };
  return c.json(captureStatus(true));
});

app.delete(`${API_BASE}/system/capture`, (c) => {
  const token = c.req.query("token");
  if (!token) {
    return c.json({ error: "token is required: it is what the start returned" }, 400);
  }
  if (CAPTURE && token !== CAPTURE.token) {
    return c.json({ error: "the running capture is not the one this token names" }, 409);
  }
  CAPTURE = null;
  return c.json(captureStatus(false));
});

setInterval(() => {
  if (captureStatus(false).running) pushBypassEvent();
}, 1500);

app.get(`${API_BASE}/system/events`, (c) => {
  const raw = c.req.query("since") ?? "0";
  if (!/^\d+$/.test(raw)) return c.json({ error: "since must be a whole number" }, 400);
  const since = Number(raw);
  const oldest = EVENTS.length > 0 ? EVENTS[0].seq : eventSeq + 1;
  /* A reader at 0 has never asked, so nothing was lost to it. */
  const dropped = since !== 0 && since + 1 < oldest ? oldest - (since + 1) : 0;
  const lines = EVENTS.filter((l) => l.seq > since).slice(0, 1024);
  return c.json({
    events: lines,
    next: lines.length > 0 ? lines[lines.length - 1].seq : since,
    dropped,
    level: "debug",
    boot: EVENTS_BOOT,
  });
});

app.get(`${API_BASE}/system/netfilter`, (c) => c.json(NETFILTER));

app.put("/dev/live", async (c) => {
  const body = await c.req.json();
  if (typeof body?.group === "string") {
    if (body.reason) LIVE_REASONS[body.group] = body.reason;
    else delete LIVE_REASONS[body.group];
  }
  if (body?.netfilter && typeof body.netfilter.ok === "boolean") NETFILTER = body.netfilter;
  return c.json({ reasons: LIVE_REASONS, netfilter: NETFILTER });
});

app.get("*", serveStatic({ root: "./dist" }));

Deno.serve(
  { port: PORT, onListen: () => console.log(`running mock server on port ${PORT}...`) },
  app.fetch,
);
