import { Hono } from "hono";
import { cors } from "hono/cors";
import { serveStatic } from "hono/deno";
import { logger } from "hono/logger";
import { streamSSE } from "hono/streaming";

import type { Interfaces } from "../src/types.ts";
import { activeOf, listOf, moveUp, type MockIfaceState } from "./move-up.ts";

const API_BASE = "/api/v1";

const INTERFACES: Interfaces = {
  interfaces: [
    { id: "blackhole" },
    { id: "block" },
    { id: "nwg0", name: "WARP", ndmsName: "Wireguard0", role: "tunnel" },
    { id: "nwg1", name: "AmneziaWG NL", ndmsName: "Wireguard1", role: "tunnel" },
    { id: "nwg2", ndmsName: "Wireguard2", role: "tunnel" },
    { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
    { id: "opkgtun10", name: "sing-box", role: "tunnel" },
    { id: "tunvless0", role: "tunnel" },
    { id: "ppp0", name: "Broadband connection", ndmsName: "PPPoE0", role: "wan" },
    { id: "eth3", ndmsName: "GigabitEthernet1", role: "wan" },
    { id: "br0", name: "Home network", ndmsName: "Bridge0", role: "lan" },
    { id: "br1", name: "Guest", ndmsName: "Bridge1", role: "lan" },
    { id: "eth1", role: "other" },
    { id: "eth2.1", role: "other" },
    { id: "longinterf", role: "other" },
  ],
};

const RESOLVERS = {
  resolvers: [
    { interface: "nwg0", servers: ["9.9.9.9", "1.0.0.1"] },
    { interface: "wg0", servers: ["1.1.1.1", "1.0.0.1"] },
  ],
};

const NOW = () => Math.floor(Date.now() / 1000);
const CALM = { window: 600, total: 0, fallbacks: 0, last: 0, reason: "", resting: false, since: 0 };
const FLAKY: Record<string, any> = {};

function resolverOf(group: any, active: string) {
  const resolve = group.resolve ?? { tunnel: true, server: "" };
  const health = FLAKY[group.id] ?? CALM;
  const live = (servers: string[]) => (group.enable === false ? [] : servers);
  if (!resolve.tunnel) return { source: "off", servers: [], health: CALM };
  if (active === "blackhole" || active === "block") {
    return { source: "none", servers: [], health: CALM };
  }
  if (resolve.server)
    return { source: "group", servers: live(serverEntries(resolve.server)), health };
  const fw = RESOLVERS.resolvers.find((r) => r.interface === active)?.servers ?? [];
  return fw.length
    ? { source: "firmware", servers: live(fw), health }
    : { source: "none", servers: [], health: CALM };
}

function serverEntries(server: string): string[] {
  return server.split(",").map((e) => e.trim());
}

function resolveRefusal(group: any): { error: string; field: string; group: string } | null {
  const value: string = group?.resolve?.server ?? "";
  if (!value) return null;
  const refuse = (why: string) => ({
    error: `resolve.server "${value}" ${why}`,
    field: "resolve.server",
    group: group.id,
  });
  const seen: string[] = [];
  for (const [i, server] of serverEntries(value).entries()) {
    if (server === "") return refuse("has an empty entry");
    if (i === 4) return refuse("names more than 4 servers");
    const refusal = entryRefusal(server, group.id);
    if (refusal) return refusal;
    const key = server.replace(/^\[(.*)\]:53$|^([^:]*):53$/, "$1$2");
    if (seen.includes(key)) return refuse(`names "${server}" twice`);
    seen.push(key);
  }
  return null;
}

function entryRefusal(server: string, id: string) {
  const host = server.startsWith("[")
    ? server.slice(1, server.indexOf("]"))
    : server.split(":").length === 2
      ? server.split(":")[0]
      : server;
  if (["0.0.0.0", "::", "::1"].includes(host) || host.startsWith("127.")) {
    return {
      error: `resolve.server "${server}" is a sink address`,
      field: "resolve.server",
      group: id,
    };
  }
  if (/^198\.(18|19)\./.test(host)) {
    return {
      error: `resolve.server "${server}" is inside firc's address pool`,
      field: "resolve.server",
      group: id,
    };
  }
  return null;
}

function loadGroups() {
  try {
    return JSON.parse(Deno.readTextFileSync("./dev/groups.json"));
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return { groups: [] };
    throw e;
  }
}

const DATA = loadGroups();
if (DATA.groups[0]) {
  FLAKY[DATA.groups[0].id] = {
    window: 600,
    total: 37,
    fallbacks: 4,
    last: NOW() - 90,
    reason: "fallback_timeout",
    resting: false,
    since: 0,
  };
}

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

if (!DATA.groups.some((g: any) => g.id === "ad5ad5ad")) {
  DATA.groups.push({
    id: "ad5ad5ad",
    name: "Ads",
    interface: "block",
    block: "nxdomain",
    enable: true,
    devices: { allow: [], deny: [] },
    rules: [
      { enable: true, id: "ad5ad501", rule: "doubleclick.net", type: "namespace" },
      { enable: true, id: "ad5ad502", rule: "tracker.example.com", type: "domain" },
    ],
  });
}

if (!DATA.groups.some((g: any) => g.id === "g1g1g1g1")) {
  DATA.groups.unshift({
    id: "g1g1g1g1",
    name: "Example Group",
    interface: "nwg0",
    enable: true,
    devices: { allow: [], deny: [] },
    rules: [
      { enable: true, id: "e1e1e101", rule: "facebook.com", type: "namespace" },
      { enable: true, id: "e1e1e102", rule: "youtube.com", type: "namespace" },
      {
        enable: true,
        id: "e1e1e103",
        rule: "googlevideo.com",
        type: "namespace",
        autolist: "rr3---sn-4g5e6nsz.googlevideo.com",
        autolistByDomain: true,
      },
    ],
  });
}
if (!DATA.groups.some((g: any) => g.id === "4d5b10c0")) {
  DATA.groups.push({
    id: "4d5b10c0",
    name: "Kids block",
    interface: "block",
    block: "null",
    enable: true,
    devices: { allow: ["mac:aa:00:00:00:00:03"], deny: [] },
    rules: [{ enable: true, id: "4d5b1001", rule: "tiktok.com", type: "namespace" }],
  });
}
if (!DATA.groups.some((g: any) => g.id === "7ac7e125")) {
  DATA.groups.push({
    id: "7ac7e125",
    name: "Trackers",
    interface: "block",
    block: "null",
    enable: true,
    devices: { allow: [], deny: [] },
    rules: [{ enable: true, id: "7ac7e101", rule: "app-measurement.com", type: "namespace" }],
  });
}

const LIVE_REASONS: Record<string, string> = {};
let NETFILTER: Record<string, unknown> = { ok: true };

const IFACE_STATES: Record<string, MockIfaceState> = {};
const ACTIVE: Record<string, number> = {};

function liveOf(group: any, active: string): { live: boolean; liveReason?: string } {
  if (group.enable === false) return { live: false, liveReason: "disabled" };
  const forced = LIVE_REASONS[group.id];
  if (forced && forced !== "not-written") return { live: false, liveReason: forced };
  const tunnel = TUNNELS.find((tn) => tn.device === active);
  if (tunnel && tunnelStatus(tunnel) !== "up") return { live: false, liveReason: "tunnel-down" };
  if (active === "longinterf") return { live: false, liveReason: "no-interface" };
  if (forced === "not-written" || NETFILTER.ok === false) {
    return { live: false, liveReason: "not-written" };
  }
  return { live: true };
}

function groupRes({ list, rules: handRules, block, ...group }: any, withRules = false) {
  const withResolve = {
    ...group,
    resolve: group.resolve ?? { tunnel: true, server: "" },
    ...(group.interface === "block" ? { block: block ?? "null" } : {}),
  };
  const out: any = withRules ? { ...withResolve, rules: handRules } : { ...withResolve };
  const names = listOf(withResolve);
  out.active = activeOf(withResolve, ACTIVE[group.id]);
  out.resolver = resolverOf(withResolve, out.active);
  Object.assign(out, liveOf(withResolve, out.active));
  if (names.length > 1) {
    out.interfaces = names.map((name: string) => ({
      name,
      ...(IFACE_STATES[name] ?? { state: "unknown", since: 0, error: "" }),
    }));
  }
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
type DnsDecision = "issued" | "not-covered" | "no-match" | "pool-refused" | "passed" | "blocked";
type Event =
  | { seq: number; at: number; kind: "log"; level: string; source: string; message: string }
  | {
      seq: number;
      at: number;
      kind: "dns";
      client: string;
      name: string;
      qtype: string;
      rcode: string;
      decision: DnsDecision;
      resolver?: string;
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
const LOG_SAMPLES: [string, string, string][] = [
  ["info", "fircd", "netfilter rebuilt: 3 group(s), 1 subscription(s)"],
  ["debug", "fircd", "committer: request folded into the running pass"],
  ["info", "fircd", 'subscription "Bad Bad Services" synced: 1204 rule(s)'],
  ["warn", "fircd", 'group Example routes nothing: "" is not an interface name'],
  ["debug", "fircd", "pool: 12 name(s) idle past the window, quarantined"],
  ["error", "fircd", "upstream 127.0.0.1:53 did not answer within 2s"],
  ["info", "tunvless0", "active Amsterdam-1"],
  ["warn", "tunvless0", "Frankfurt-2 does not answer (timeout)"],
  ["error", "tunvless1", "no usable VLESS node"],
  ["debug", "tunvless0", "tun: rx 40"],
];
function pushEvent(e: Fresh<Event>) {
  if (e.kind === "dns") tally(e.name, e.client, e.group?.id ?? "", e.decision === "blocked");
  eventSeq += 1;
  EVENTS.push({ ...e, seq: eventSeq, at: Math.floor(Date.now() / 1000) });
  if (EVENTS.length > EVENTS_RING) EVENTS.shift();
}
function pushLogLine() {
  const [level, source, message] = LOG_SAMPLES[Math.floor(Math.random() * LOG_SAMPLES.length)];
  pushEvent({ kind: "log", level, source, message });
}

const DNS_CLIENTS = ["192.168.1.42", "192.168.1.51", "192.168.1.7", "fd00::5"];
const DNS_NAMES = ["youtube.com", "googlevideo.com", "ya.ru", "example.com"];
const ROUTED_NAMES = new Set(["youtube.com", "googlevideo.com"]);
const BLOCKED_NAMES: [string, string][] = [
  ["ads.doubleclick.net", "A"],
  ["tracker.example.com", "AAAA"],
  ["stats.doubleclick.net", "HTTPS"],
];
let dnsN = 0;
let blockedN = 0;
function pushBlockedEvent(client: string) {
  const ads = DATA.groups.find((g: any) => g.interface === "block" && g.enable !== false);
  if (!ads) return false;
  const [name, qtype] = BLOCKED_NAMES[blockedN % BLOCKED_NAMES.length];
  blockedN += 1;
  const code = ads.block ?? "null";
  pushEvent({
    kind: "dns",
    client,
    name,
    qtype,
    rcode: code === "nxdomain" ? "NXDOMAIN" : code === "refused" ? "REFUSED" : "NOERROR",
    decision: "blocked",
    resolver: "local",
    group: { id: ads.id, name: ads.name },
    reals: [],
  });
  return true;
}
function pushDnsEvent() {
  const client = DNS_CLIENTS[Math.floor(Math.random() * DNS_CLIENTS.length)];
  if ((client === "192.168.1.7" || client === "fd00::5") && pushBlockedEvent(client)) return;
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

const BYPASS_CLIENTS = ["192.168.1.42", "192.168.1.51", "192.168.1.77", "192.168.1.7"];
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

const PORT = Number(Deno.env.get("MOCK_PORT") ?? 6969);
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

  const authHeader = c.req.header("X-Firc-Token");
  if (authHeader !== STATIC_TOKEN && authHeader !== "disabled") {
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

function commentRefusal(rule: any): string | null {
  const raw = rule?.comment;
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") return "comment is a string";
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(raw)) {
    return "comment is one line without control characters";
  }
  const trimmed = raw.replace(/^ +| +$/g, "");
  if (new TextEncoder().encode(trimmed).length > 256) return "comment is at most 256 bytes";
  if (trimmed === "") delete rule.comment;
  else rule.comment = trimmed;
  return null;
}

function ruleRefusal(rule: any): string | null {
  const comment = commentRefusal(rule);
  if (comment) return comment;
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
    if (
      group?.block !== undefined &&
      ![null, "null", "nxdomain", "refused"].includes(group.block)
    ) {
      return c.json(
        { error: `block "${group.block}" is not an answer`, field: "block", group: group.id },
        400,
      );
    }
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
    if (rest.interface !== "block") delete merged.block;
    else if (rest.block === undefined) merged.block = existing?.block ?? "null";
    else if (rest.block === null) merged.block = "null";
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
    if (edit.comment !== undefined) {
      return c.json({ error: "a list's rules carry no comment" }, 400);
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

app.get(`${API_BASE}/groups/list/catalog`, (c) =>
  c.json({
    generated: "2026-10-22T00:00:00Z",
    fetchedAt: Math.floor(Date.now() / 1000),
    stale: false,
    sources: [
      {
        id: "sagernet",
        url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs",
        names: ["youtube", "youtube@cn", "google", "google@cn", "telegram", "netflix", "openai"],
      },
      {
        id: "hoaxisr",
        url: "https://raw.githubusercontent.com/hoaxisr/rulesets/master/srs/{}.srs",
        names: ["youtube", "discord", "telegram-ip", "meta"],
      },
    ],
  }),
);

app.get(`${API_BASE}/groups/list/preview`, (c) => {
  const url = c.req.query("url");
  if (!url) return c.json({ error: "list url is required" }, 400);
  if (Math.random() < 0.5) {
    return c.json({ error: "the server answered 404" }, 502);
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

app.post(`${API_BASE}/groups/:id/move-up`, (c) => {
  const group = DATA.groups.find((g: any) => g.id === c.req.param("id"));
  const answer = moveUp(group, group ? ACTIVE[group.id] : undefined, IFACE_STATES);
  if (answer.status !== 200)
    return c.json({ error: answer.error }, answer.status as 400 | 404 | 409);
  ACTIVE[group.id] = 0;
  return c.json(groupRes(group));
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

const TUNNEL_LINK =
  "vless://00000000-0000-4000-8000-000000000001@a.example.invalid:443?security=none#A";
const TUNNEL_HEADERS = [
  { name: "User-Agent", value: "firc/0.4.1" },
  { name: "X-HWID", value: "3f9c2a71d04be658" },
  { name: "X-Device-OS", value: "KeeneticOS" },
  { name: "X-Ver-OS", value: "5.01.C.6.0-1" },
  { name: "X-Device-Model", value: "Ultra (KN-1810)" },
];
let TUNNELS: any[] = [
  {
    id: "main",
    device: "tunvless0",
    description: "PRAW-1",
    enable: true,
    active: 1,
    by: "connection",
    interval: 60,
    silence: 20,
    filter: "",
    order: [],
    exclude: [],
    sources: [
      { id: "0000000a", kind: "link", link: TUNNEL_LINK },
      {
        id: "0000000b",
        kind: "subscription",
        name: "Provider",
        url: "https://sub.example.invalid/feed",
        interval: 21600,
      },
      {
        id: "0000000c",
        kind: "subscription",
        name: "Reborn VPN",
        url: "https://panel.example.invalid/au9P",
        interval: 21600,
      },
      {
        id: "0000000d",
        kind: "subscription",
        name: "Office",
        url: "https://office.example.invalid/sub",
        interval: 21600,
        headers: {
          "User-Agent": "sing-box/1.12.0",
          "X-Device-Model": "",
          Authorization: "Bearer 7f3a…",
        },
      },
    ],
    uplink: { kind: "auto", ref: "" },
    advanced: { ca: "", insecure: false, timeout: 8, kernelTcp: false, fingerprint: "" },
    inbounds: [
      { port: 1080, listen: "br0", node: "0000000a:A", user: "", password: "" },
      { port: 1081, listen: "br0", node: "0000000a:A", user: "bob", password: "s3cret" },
    ],
  },
];

const TUNNEL_STATUS_CYCLE = ["up", "up", "up", "no_node", "backoff", "starting"];
let TUNNEL_TICK = 0;

const derivedId = (text: string) => {
  let h = 0x811c9dc5;
  for (const ch of text) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h.toString(16).padStart(8, "0");
};

const tunnelRefusal = (tunnels: any[]) => {
  if (tunnels.length > 8) return { error: "at most 8 tunnels", field: null, tunnel: null };
  const ids = new Set<string>();
  const devices = new Set<string>();
  for (const tn of tunnels) {
    if (!/^[A-Za-z0-9_-]{1,15}$/.test(tn?.id ?? "")) {
      return {
        error: "id: letters, digits, - and _, under 16 bytes",
        field: "id",
        tunnel: tn?.id ?? null,
      };
    }
    if (ids.has(tn.id)) return { error: "id is used twice", field: "id", tunnel: tn.id };
    ids.add(tn.id);
    if (!/^tunvless([0-9]|[1-9][0-9])$/.test(tn.device ?? "")) {
      return { error: "device must be tunvless0..tunvless99", field: "device", tunnel: tn.id };
    }
    const description = String(tn.description ?? "");
    if (
      new TextEncoder().encode(description).length > 63 ||
      /[\u0000-\u001f\u007f-\u009f]/.test(description)
    ) {
      return {
        error: "up to 63 bytes, no control characters",
        field: "description",
        tunnel: tn.id,
      };
    }
    if (devices.has(tn.device))
      return { error: "device is used twice", field: "device", tunnel: tn.id };
    devices.add(tn.device);
    for (const [i, src] of (tn.sources ?? []).entries()) {
      if (src.kind === "link" && !String(src.link ?? "").startsWith("vless://")) {
        return {
          error: "link must be a vless:// link",
          field: `sources[${i}].link`,
          tunnel: tn.id,
        };
      }
      if (src.kind === "subscription" && !/^https?:\/\//.test(String(src.url ?? ""))) {
        return { error: "url must be http or https", field: `sources[${i}].url`, tunnel: tn.id };
      }
    }
  }
  return null;
};

const tunnelNodes = (tn: any) =>
  (tn.sources ?? [])
    .flatMap((src: any, i: number) =>
      [1, 2].map((n) => {
        const name = src.kind === "link" ? "A" : `${src.name ?? "Sub"}-${n}`;
        return {
          src,
          name: src.kind === "link" && n === 2 ? null : name,
          key: `${src.id}:${name}`,
          i,
        };
      }),
    )
    .filter((row: any) => row.name !== null);

const tunnelStatus = (tn: any) =>
  !tn.enable
    ? "off"
    : TUNNEL_STATUS_CYCLE[Math.floor(TUNNEL_TICK / 3) % TUNNEL_STATUS_CYCLE.length];

const tunnelState = (tn: any) => {
  const status = tunnelStatus(tn);
  const nodes: any[] = tunnelNodes(tn).map((row: any, k: number) => ({
    key: row.key,
    name: row.name,
    source: row.src.kind === "link" ? "link" : row.src.name,
    state: tn.exclude.includes(row.key)
      ? "excluded"
      : k === 0 && status === "up"
        ? "active"
        : "reserve",
    since: 0,
  }));
  const first = nodes[0];
  if (TUNNELS[0]?.id === tn.id && first?.state === "active") first.v6 = true;
  return {
    id: tn.id,
    device: tn.device,
    status,
    since: Math.floor(Date.now() / 1000) - 60,
    backoffS: status === "backoff" || status === "no_node" ? 12 : 0,
    lastExit: 0,
    uplinkOk: true,
    tcpPort: 0,
    tcpSkipped: [],
    tcpOff: "",
    active: nodes.filter((n: any) => n.state === "active").map((n: any) => n.name),
    groups: [],
    nodes,
    subscriptions: (tn.sources ?? [])
      .filter((src: any) => src.kind === "subscription")
      .map((src: any) => ({
        name: src.name,
        nodes: src.name === "Reborn VPN" ? 0 : 2,
        fetching: false,
        lastOk: src.name === "Reborn VPN" ? 0 : Math.floor(Date.now() / 1000) - 300,
        lastTry: Math.floor(Date.now() / 1000) - 300,
        error:
          src.name === "Reborn VPN"
            ? "the server answered: Please turn on HWID in your app, or find the new one"
            : "",
        usage:
          src.name === "Reborn VPN"
            ? null
            : {
                used: 87 * 2 ** 30,
                total: 100 * 2 ** 30,
                expire: Math.floor(Date.now() / 1000) + 2 * 86400,
              },
      })),
    rxBps: status === "up" ? 1200 : 0,
    txBps: status === "up" ? 300 : 0,
    inbounds: (tn.inbounds ?? []).map((ib: any) => ({
      port: ib.port,
      state: !tn.enable ? "off" : status === "up" ? "up" : "starting",
      why: "",
      rxBps: status === "up" ? 600 : 0,
      txBps: status === "up" ? 150 : 0,
    })),
  };
};

app.get(`${API_BASE}/tunnels`, (c) => c.json({ tunnels: TUNNELS }));

app.put(`${API_BASE}/tunnels`, async (c) => {
  const body = await c.req.json();
  const tunnels = Array.isArray(body?.tunnels) ? body.tunnels : [];
  const refusal = tunnelRefusal(tunnels);
  if (refusal) return c.json(refusal, 400);
  const runOf = (tn: any) =>
    JSON.stringify([
      tn.device,
      tn.enable,
      tn.active,
      tn.by,
      tn.interval,
      tn.silence,
      tn.uplink,
      tn.advanced,
    ]);
  const before = new Map(TUNNELS.map((tn: any) => [tn.id, tn]));
  TUNNELS = tunnels.map((tn: any) => ({
    ...tn,
    description: tn.description ?? "",
    advanced: {
      ca: "",
      insecure: false,
      timeout: 8,
      kernelTcp: false,
      fingerprint: "",
      ...tn.advanced,
    },
    inbounds: (tn.inbounds ?? []).map((ib: any) => ({
      port: ib.port,
      listen: ib.listen,
      node: ib.node,
      user: ib.user ?? "",
      password: ib.password ?? "",
    })),
    sources: (tn.sources ?? []).map((src: any) => ({
      ...src,
      id: src.id || derivedId(src.link ?? src.url ?? ""),
    })),
  }));
  const restarted = TUNNELS.filter(
    (tn: any) => !before.has(tn.id) || runOf(before.get(tn.id)) !== runOf(tn),
  ).map((tn: any) => tn.device);
  const updated = TUNNELS.filter(
    (tn: any) =>
      before.has(tn.id) &&
      runOf(before.get(tn.id)) === runOf(tn) &&
      JSON.stringify({ ...before.get(tn.id), description: "" }) !==
        JSON.stringify({ ...tn, description: "" }),
  ).map((tn: any) => tn.device);
  return c.json({ tunnels: TUNNELS, restarted, updated });
});

app.get(`${API_BASE}/tunnels/headers`, (c) => c.json({ headers: TUNNEL_HEADERS }));

app.get(`${API_BASE}/tunnels/state`, (c) => {
  TUNNEL_TICK++;
  return c.json({ tunnels: TUNNELS.map(tunnelState) });
});

app.post(`${API_BASE}/tunnels/preview`, async (c) => {
  const body = await c.req.json();
  const draft = body?.tunnel;
  if (!draft) return c.json({ error: "tunnel is required", field: null, tunnel: null }, 400);
  const rows = tunnelNodes(draft).map((row: any) => ({
    key: row.key,
    name: row.name,
    source: row.src.kind === "link" ? "link" : row.src.name,
    isNew: !(draft.order ?? []).includes(row.key),
    excluded: (draft.exclude ?? []).includes(row.key),
    overCap: false,
    skipReason: "",
  }));
  return c.json({
    total: rows.length,
    matched: rows.filter((r: any) => !r.excluded).length,
    nodes: rows,
    subscriptions: (draft.sources ?? [])
      .filter((src: any) => src.kind === "subscription")
      .map((src: any) => ({ name: src.name, cached: true })),
  });
});

app.post(`${API_BASE}/tunnels/probe`, async (c) => {
  const body = await c.req.json();
  const target = body?.id ? TUNNELS.find((tn: any) => tn.id === body.id) : body?.tunnel;
  if (!target) return c.json({ error: "no tunnel with this id" }, 404);
  await new Promise((resolve) => setTimeout(resolve, 500));
  return c.json({
    nodes: tunnelNodes(target).map((row: any, k: number) =>
      k % 3 === 2
        ? { key: row.key, ok: false, why: "timeout", handshakeMs: null, firstByteMs: null }
        : { key: row.key, ok: true, why: "", handshakeMs: 40 + k, firstByteMs: 60 + k },
    ),
  });
});

app.post(`${API_BASE}/tunnels/:id/refresh`, (c) => {
  const tn = TUNNELS.find((x: any) => x.id === c.req.param("id"));
  if (!tn) return c.json({ error: "no such tunnel" }, 404);
  const has = (tn.sources ?? []).some((src: any) => src.kind === "subscription");
  return c.json({ queued: has }, 202);
});

app.post(`${API_BASE}/tunnels/:id/restart`, (c) => {
  const tn = TUNNELS.find((x: any) => x.id === c.req.param("id"));
  if (!tn) return c.json({ error: "no such tunnel" }, 404);
  if (!tn.enable) return c.json({ error: "the tunnel is off" }, 409);
  return c.json({ queued: true }, 202);
});

app.get(`${API_BASE}/system/interfaces`, (c) =>
  c.json({
    interfaces: INTERFACES.interfaces.map((item) => {
      const description = TUNNELS.find((tn: any) => tn.device === item.id)?.description;
      return description ? { ...item, name: description } : item;
    }),
  }),
);

app.get(`${API_BASE}/system/resolvers`, (c) => c.json(RESOLVERS));

const POLICIES = {
  policies: [
    { name: "Policy0", description: "Kids", devices: 3 },
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
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:02",
      name: "Laptop",
      ip: "192.168.1.6",
      ip6: [],
      active: false,
      registered: true,
      policy: "",
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:03",
      name: "Phone",
      ip: "192.168.1.7",
      ip6: ["fd00::7", "2001:db8::7"],
      active: true,
      registered: true,
      policy: "Policy0",
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:05",
      name: "iPad",
      ip: "192.168.1.51",
      ip6: [],
      active: true,
      registered: true,
      policy: "",
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:06",
      name: "Desktop",
      ip: "192.168.1.42",
      ip6: [],
      active: true,
      registered: true,
      policy: "",
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:04",
      name: "",
      ip: "192.168.1.8",
      ip6: [],
      active: true,
      registered: false,
      policy: "Policy1",
      segment: "br0",
      intercepted: true,
    },
    {
      mac: "aa:00:00:00:00:07",
      name: "Console",
      ip: "192.168.2.20",
      ip6: [],
      active: true,
      registered: true,
      policy: "Policy0",
      segment: "br1",
      intercepted: false,
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
  "app.dnsProxy.disableStats": false,
  "app.addressPool.ttlClamp": 300,
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
  "app.httpWeb.host.address": "[::]",
  "app.httpWeb.host.port": 666,
  "app.update.check": false,
  "app.check.url": "http://cp.cloudflare.com/generate_204",
  "app.check.wanUrl": "",
  "app.check.interval": 30,
  "app.check.timeout": 5,
  "app.autolist.enabled": false,
  "app.autolist.mode": "candidates",
  "app.autolist.group": "",
  "app.autolist.failThreshold": 3,
  "app.autolist.failTime": 60,
  "app.autolist.retransThreshold": 3,
  "app.autolist.exclude": [],
  "app.autolist.recheck": false,
  "app.autolist.recheckInterval": 21600,
  "app.autolist.checkInterface": "",
};
const SETTINGS_LIVE = new Set([
  "app.dnsProxy.upstream.address",
  "app.dnsProxy.upstream.port",
  "app.dnsProxy.disableDropAAAA",
  "app.dnsProxy.unmatchedTtl",
  "app.dnsProxy.disableStats",
  "app.update.check",
  "app.check.url",
  "app.check.wanUrl",
  "app.check.interval",
  "app.check.timeout",
  "app.autolist.enabled",
  "app.autolist.mode",
  "app.autolist.group",
  "app.autolist.failThreshold",
  "app.autolist.failTime",
  "app.autolist.retransThreshold",
  "app.autolist.exclude",
  "app.autolist.recheck",
  "app.autolist.recheckInterval",
  "app.autolist.checkInterface",
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
    webUi: { port: RUNNING["app.httpWeb.host.port"], movedFrom: 0, lanAddress: "192.168.1.1" },
  }),
);

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
  if (updateBusy()) return c.json({ error: "an update is being installed" }, 409);
  if (RESTARTING) return c.json({ error: "a restart is already under way" }, 409);
  RESTART_UNTIL = Date.now() + 3000;
  RESTARTING = true;
  return c.json({ restarting: true }, 202);
});

const UPDATE_LATEST = {
  version: "0.3.0",
  revision: 1,
  tag: "0.3.0",
  publishedAt: "2026-10-12T10:00:00Z",
  notes: "добавлена проверка обновлений\nисправлено окно устройств",
  asset: { name: "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk", size: 830112 },
};
let UPDATE_CHECKED_AT: number | null = null;
let UPDATE_INSTALLED = { version: "0.2.0", revision: 1 };
let UPDATE_STATE: "idle" | "downloading" | "verifying" | "installing" | "failed" = "idle";
let UPDATE_STARTED = 0;
let UPDATE_CHECKING = false;
const updateBusy = () =>
  UPDATE_STATE === "downloading" || UPDATE_STATE === "verifying" || UPDATE_STATE === "installing";
let UPDATE_RESULT: { version: string; opkgExit: number; finishedAt: number; log: string } | null =
  null;

function updateProgress() {
  if (UPDATE_STATE !== "downloading") return null;
  const total = UPDATE_LATEST.asset.size;
  return {
    bytes: Math.min(total, Math.floor(((Date.now() - UPDATE_STARTED) / 2000) * total)),
    total,
  };
}

function updateStatus() {
  const now = Math.floor(Date.now() / 1000);
  const newer = UPDATE_INSTALLED.version !== UPDATE_LATEST.version;
  return {
    installed: { ...UPDATE_INSTALLED, target: "mipsel-3.4_kn" },
    canInstall: true,
    reason: null,
    check:
      UPDATE_CHECKED_AT === null
        ? null
        : {
            checkedAt: UPDATE_CHECKED_AT,
            ageS: now - UPDATE_CHECKED_AT,
            latest: UPDATE_LATEST,
            newer,
            installable: true,
            reason: null,
            error: null,
          },
    state: UPDATE_STATE,
    progress: updateProgress(),
    error: null,
    result: UPDATE_RESULT,
  };
}

app.get(`${API_BASE}/system/update`, (c) => c.json(updateStatus()));

app.post(`${API_BASE}/system/update/check`, async (c) => {
  if (updateBusy()) return c.json({ error: "an install is under way" }, 409);
  UPDATE_CHECKING = true;
  await new Promise((r) => setTimeout(r, 700));
  UPDATE_CHECKING = false;
  UPDATE_CHECKED_AT = Math.floor(Date.now() / 1000);
  return c.json(updateStatus());
});

app.post(`${API_BASE}/system/update/install`, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { version?: unknown } | null;
  if (typeof body?.version !== "string")
    return c.json({ error: 'body must be {"version": "<tag>"}' }, 400);
  if (RESTARTING) return c.json({ error: "a restart is under way" }, 409);
  if (updateBusy()) return c.json({ error: "an install is under way" }, 409);
  if (UPDATE_CHECKING) return c.json({ error: "a check is under way; try again in a moment" }, 409);
  if (UPDATE_CHECKED_AT === null || body.version !== UPDATE_LATEST.tag)
    return c.json({ error: `check again: the last check did not offer ${body.version}` }, 409);
  if (UPDATE_INSTALLED.version === UPDATE_LATEST.version)
    return c.json({ error: `${body.version} is not newer than ${UPDATE_INSTALLED.version}` }, 400);
  UPDATE_STATE = "downloading";
  UPDATE_STARTED = Date.now();
  setTimeout(() => (UPDATE_STATE = "verifying"), 2000);
  setTimeout(() => (UPDATE_STATE = "installing"), 2500);
  setTimeout(() => {
    RESTART_UNTIL = Date.now() + 3000;
    RESTARTING = true;
    UPDATE_STATE = "idle";
    UPDATE_INSTALLED = { version: UPDATE_LATEST.version, revision: UPDATE_LATEST.revision };
    UPDATE_RESULT = {
      version: UPDATE_LATEST.version,
      opkgExit: 0,
      finishedAt: Math.floor(Date.now() / 1000) + 3,
      log: `Upgrading firc on root from ${UPDATE_INSTALLED.version} to ${UPDATE_LATEST.version}...\n`,
    };
  }, 3500);
  return c.json(
    {
      version: UPDATE_LATEST.version,
      asset: UPDATE_LATEST.asset.name,
      size: UPDATE_LATEST.asset.size,
    },
    202,
  );
});

const CAPTURE_SECONDS = 300;
let CAPTURE: { token: string; endsAt: number } | null = null;
let CAPTURE_LAST: {
  startedAt: number;
  endedAt: number;
  ended: "reached-end" | "stopped";
  leaks: number;
  summary: string[];
} | null = null;

function endCapture(endedAt: number, ended: "reached-end" | "stopped") {
  if (!CAPTURE) return;
  const startedAt = CAPTURE.endsAt - CAPTURE_SECONDS;
  const leaks = EVENTS.filter(
    (e) => e.kind === "bypass" && e.at >= startedAt && e.at <= endedAt,
  ).length;
  CAPTURE_LAST = {
    startedAt,
    endedAt,
    ended,
    leaks,
    summary: [
      `${leaks * 23 + 4} packets read, ${leaks} bypasses reported.`,
      "3 packets carried no server name this reader could take: a hello spanning segments reads the same as a client that sent none.",
    ],
  };
  CAPTURE = null;
}

function captureStatus(withToken: boolean) {
  const now = Math.floor(Date.now() / 1000);
  if (CAPTURE && CAPTURE.endsAt <= now) endCapture(CAPTURE.endsAt, "reached-end");
  const last = CAPTURE_LAST ? { last: CAPTURE_LAST } : {};
  if (!CAPTURE) return { running: false, ...last };
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
  CAPTURE_LAST = null;
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
  endCapture(Math.floor(Date.now() / 1000), "stopped");
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
    boot: EVENTS_BOOT,
  });
});

type StatKey = {
  name: string;
  client: string;
  hours: number[];
  blocked: number[];
  last: number;
  owner: string;
  ownerBlocked: boolean;
};
const STATS_SINCE = NOW() - 3 * 86400;
const STATS = new Map<string, StatKey>();

function tally(name: string, client: string, owner: string, blocked: boolean, at = NOW()) {
  const id = `${name}|${client}`;
  let k = STATS.get(id);
  if (!k) {
    k = { name, client, hours: [], blocked: [], last: 0, owner: "", ownerBlocked: false };
    STATS.set(id, k);
  }
  k.hours.push(at);
  if (blocked) k.blocked.push(at);
  if (at >= k.last) {
    k.last = at;
    k.owner = owner;
    k.ownerBlocked = blocked;
  }
}

const STATS_SEED: [string, string, number, number, string][] = [
  ["googlevideo.com", "192.168.1.51", 120, 0, ""],
  ["googlevideo.com", "fd00::5", 60, 0, ""],
  ["googlevideo.com", "192.168.1.7", 31, 0, ""],
  ["googlevideo.com", "192.168.1.8", 12, 0, ""],
  ["youtube.com", "192.168.1.42", 70, 0, "g1g1g1g1"],
  ["youtube.com", "192.168.1.7", 42, 0, "g1g1g1g1"],
  ["youtube.com", "192.168.1.51", 29, 0, "g1g1g1g1"],
  ["connectivitycheck.gstatic.com", "fd00::5", 80, 0, ""],
  ["connectivitycheck.gstatic.com", "192.168.1.8", 21, 0, ""],
  ["connectivitycheck.gstatic.com", "192.168.1.7", 35, 0, ""],
  ["ya.ru", "fd00::5", 60, 0, ""],
  ["ya.ru", "192.168.1.8", 39, 0, ""],
  ["ya.ru", "192.168.1.7", 16, 0, ""],
  ["api.telegram.org", "192.168.1.7", 56, 0, ""],
  ["api.telegram.org", "192.168.1.42", 49, 0, ""],
  ["i.ytimg.com", "fd00::5", 50, 0, ""],
  ["i.ytimg.com", "192.168.1.7", 23, 0, ""],
  ["i.ytimg.com", "192.168.1.51", 19, 0, ""],
  ["mc.yandex.ru", "192.168.1.51", 50, 30, "ad5ad5ad"],
  ["mc.yandex.ru", "192.168.1.7", 12, 4, "ad5ad5ad"],
  ["mc.yandex.ru", "fd00::5", 29, 9, "ad5ad5ad"],
  ["ads.doubleclick.net", "192.168.1.51", 40, 40, "ad5ad5ad"],
  ["ads.doubleclick.net", "192.168.1.42", 32, 32, "ad5ad5ad"],
  ["ads.doubleclick.net", "192.168.1.7", 16, 16, "ad5ad5ad"],
  ["github.com", "192.168.1.42", 71, 0, ""],
  ["medium.com", "192.168.1.7", 40, 0, ""],
  ["some-vps.de", "192.168.1.42", 33, 0, ""],
  ["tiny-api.io", "192.168.1.51", 12, 0, ""],
  ["icloud.com", "192.168.1.7", 34, 0, ""],
  ["icloud.com", "192.168.1.51", 29, 0, ""],
  ["graph.facebook.com", "192.168.1.51", 30, 0, "g1g1g1g1"],
  ["graph.facebook.com", "192.168.1.8", 20, 0, "g1g1g1g1"],
  ["mail.yandex.ru", "192.168.1.8", 32, 0, ""],
  ["mail.yandex.ru", "192.168.1.51", 10, 0, ""],
  ["mail.yandex.ru", "192.168.1.7", 10, 0, ""],
  ["tracker.example.com", "192.168.1.7", 30, 30, "ad5ad5ad"],
  ["tracker.example.com", "192.168.1.42", 20, 20, "ad5ad5ad"],
  ["time.apple.com", "192.168.1.7", 22, 0, ""],
  ["app-measurement.com", "192.168.1.51", 14, 10, "7ac7e125"],
  ["web.whatsapp.com", "192.168.1.42", 8, 0, ""],
  ["example.com", "192.168.1.8", 4, 0, ""],
  [
    "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
    "fd00::5",
    40,
    0,
    "",
  ],
  ["7.1.168.192.in-addr.arpa", "192.168.1.7", 25, 0, ""],
];
for (const [i, [name, client, n, blocked, owner]] of STATS_SEED.entries()) {
  const lastAgo = [0, 600, 1200, 2400, 5 * 3600][i % 5];
  for (let j = 0; j < n; j++) {
    tally(name, client, owner, j < blocked, NOW() - lastAgo - (n - 1 - j) * 97);
  }
}

function statsAnswer(
  device: string[] | null,
  q: string,
  arpa: boolean,
  offset: number,
  limit: number,
) {
  const from = NOW() - 86400;
  const keys = [...STATS.values()].filter(
    (k) =>
      (arpa || !k.name.endsWith(".arpa")) &&
      (!device || device.includes(k.client)) &&
      k.hours.some((at) => at > from),
  );
  const byName = new Map<string, StatKey[]>();
  for (const k of keys) byName.set(k.name, [...(byName.get(k.name) ?? []), k]);
  const count = (k: StatKey) => k.hours.filter((at) => at > from).length;
  const countBlocked = (k: StatKey) => k.blocked.filter((at) => at > from).length;
  const rows = [...byName.entries()].map(([name, ks]) => {
    const latest = ks.reduce((a, b) => (b.last > a.last ? b : a));
    const g = DATA.groups.find((x: any) => x.id === latest.owner);
    const clients = ks
      .map((k) => ({ address: k.client, queries: count(k) }))
      .sort((a, b) => b.queries - a.queries);
    return {
      name,
      queries: clients.reduce((a, c) => a + c.queries, 0),
      blocked: ks.reduce((a, k) => a + countBlocked(k), 0),
      last: latest.last,
      owner: g
        ? {
            id: g.id,
            name: g.name,
            interface: activeOf(g, ACTIVE[g.id]),
            blocked: latest.ownerBlocked,
          }
        : null,
      clients: clients.slice(0, 16),
      clientsTotal: clients.length,
    };
  });
  const matched = rows
    .filter((r) => r.name.includes(q))
    .sort((a, b) => b.queries - a.queries || a.name.localeCompare(b.name));
  return {
    window: 86400,
    now: NOW(),
    since: STATS_SINCE,
    queries: keys.reduce((a, k) => a + count(k), 0),
    blocked: keys.reduce((a, k) => a + countBlocked(k), 0),
    domains: byName.size,
    rows: matched.slice(offset, offset + limit),
    matched: matched.length,
    offset,
  };
}

app.get(`${API_BASE}/system/dnsstats`, (c) => {
  const offset = Number(c.req.query("offset") ?? 0);
  let limit = Number(c.req.query("limit") ?? 50) || 50;
  if (limit > 500) limit = 500;
  if (!Number.isInteger(offset) || offset < 0 || offset + limit > 550) {
    return c.json({ error: "invalid offset: offset + limit is at most 550" }, 400);
  }
  const raw = c.req.query("device");
  const device = raw ? raw.split(",").map((a) => a.toLowerCase()) : null;
  if (device && device.length > 12) {
    return c.json({ error: "device: at most 12 addresses" }, 400);
  }
  const arpa = c.req.query("arpa") === "1";
  const q = (c.req.query("q") ?? "").toLowerCase();
  if (SAVED["app.dnsProxy.disableStats"]) {
    const now = Math.floor(Date.now() / 1000);
    return c.json({
      enabled: false,
      window: 86400,
      now,
      since: now,
      queries: 0,
      blocked: 0,
      domains: 0,
      rows: [],
      matched: 0,
      offset,
    });
  }
  return c.json({ enabled: true, ...statsAnswer(device, q, arpa, offset, limit) });
});

app.get(`${API_BASE}/system/netfilter`, (c) => c.json(NETFILTER));

let AUTOLIST_CHECKED_AT = 0;
const AUTOLIST_ADDED_HOUR = 2;
const autolistAgo = (s: number) => NOW() - s;
const autolistSeed = () => [
  {
    domain: "rutracker.org",
    host: "rutracker.org",
    why: "no-answer",
    fails: 3,
    clients: ["192.168.1.51"],
    lastAt: autolistAgo(120),
    state: "candidate",
    notes: 0,
  },
  {
    domain: "linkedin.com",
    host: "www.linkedin.com",
    why: "reset",
    fails: 5,
    clients: ["192.168.1.42", "192.168.1.7"],
    lastAt: autolistAgo(5),
    state: "candidate",
    notes: 0,
  },
  {
    domain: "some-vps.de",
    host: "cdn.some-vps.de",
    why: "freeze",
    fails: 0,
    clients: ["192.168.1.42"],
    lastAt: autolistAgo(360),
    state: "candidate",
    notes: 0,
  },
  {
    domain: "medium.com",
    host: "medium.com",
    why: "freeze",
    fails: 0,
    clients: ["192.168.1.7"],
    lastAt: autolistAgo(60),
    state: "checking",
    notes: 2,
  },
  {
    domain: "instagram.com",
    host: "www.instagram.com",
    why: "no-connect",
    fails: 0,
    clients: ["192.168.1.51"],
    lastAt: autolistAgo(30),
    state: "candidate",
    notes: 0,
  },
];
let AUTOLIST_CANDS: any[] = autolistSeed();
let AUTOLIST_RESULTS: any[] = [
  {
    host: "cdn.some-vps.de",
    verdict: "blocked",
    why: "freeze",
    bytes: 15360,
    at: autolistAgo(900),
    error: "",
  },
  {
    host: "www.instagram.com",
    verdict: "blocked",
    why: "no-connect",
    bytes: 0,
    at: autolistAgo(40),
    error: "Connection timed out after 30001 milliseconds · wan cp.cloudflare.com: 204",
  },
];
const AUTOLIST_VERDICTS: Record<string, [string, string, number, string]> = {
  "some-vps.de": ["blocked", "freeze", 15360, ""],
  "api.telegram.org": ["open", "", 65536, ""],
  "tiny-api.io": ["short", "", 3072, ""],
  "github.com": ["unknown", "", 0, "no route to host"],
  "www.instagram.com": [
    "blocked",
    "no-connect",
    0,
    "Connection timed out after 30001 milliseconds · wan cp.cloudflare.com: 204",
  ],
};
const AUTOLIST_PROBE_MS = 2500;
let AUTOLIST_RUNNING: string | null = null;
let AUTOLIST_WAN_WARNING = false;
const autolistOn = () => SAVED["app.autolist.enabled"] === true;
const autolistState = () => ({
  enabled: autolistOn(),
  running: autolistOn(),
  mode: SAVED["app.autolist.mode"],
  group: SAVED["app.autolist.group"] || null,
  failures: autolistOn() ? 40 : 0,
  failuresDay: autolistOn() ? 23 : 0,
  ambiguousDay: autolistOn() ? 1 : 0,
  ...(autolistOn() && AUTOLIST_WAN_WARNING
    ? { wanWarning: "the check interface has no route: the WAN check cannot pass" }
    : {}),
  listed: autolistOn() ? AUTOLIST_CANDS.length : 0,
  addedHour: autolistOn() ? AUTOLIST_ADDED_HOUR : 0,
  checking: false,
  checkedAt: AUTOLIST_CHECKED_AT,
  switchedOff: 0,
  switchedOn: 0,
  bypassed: autolistOn() ? [{ client: "192.168.1.5", fails: 6 }] : [],
  candidates: autolistOn() ? AUTOLIST_CANDS : [],
  probes: {
    usedHour: autolistOn() ? 4 : 0,
    queued: autolistOn() ? 2 : 0,
    running: AUTOLIST_RUNNING,
    results: autolistOn() ? AUTOLIST_RESULTS : [],
  },
});

app.get(`${API_BASE}/system/autolist`, (c) => c.json(autolistState()));

app.post(`${API_BASE}/system/autolist/check`, (c) => {
  if (!autolistOn()) {
    return c.json({ error: "the automatic list is not running" }, 409);
  }
  AUTOLIST_CHECKED_AT = Math.floor(Date.now() / 1000);
  return c.json(autolistState());
});

app.post(`${API_BASE}/system/autolist/candidates/:domain/:action{add|dismiss}`, (c) => {
  if (!autolistOn()) return c.json({ error: "the automatic list is not running" }, 409);
  const domain = c.req.param("domain");
  const action = c.req.param("action");
  const cand = AUTOLIST_CANDS.find((x) => x.domain === domain);
  if (!cand) return c.json({ error: "no such candidate" }, 404);
  if (action === "dismiss") {
    AUTOLIST_CANDS = AUTOLIST_CANDS.filter((x) => x.domain !== domain);
    return c.json(autolistState());
  }
  const group = DATA.groups.find((g: any) => g.id === SAVED["app.autolist.group"]);
  if (!group) return c.json({ error: "the rule could not be added" }, 500);
  if (group.rules.some((r: any) => r.rule === domain)) {
    return c.json({ error: "the domain is already a rule of the group" }, 409);
  }
  group.rules.unshift({
    id: Math.random().toString(16).slice(2, 10).padEnd(8, "0"),
    enable: true,
    rule: domain,
    type: "namespace",
    autolist: cand.host,
  });
  cand.state = "added";
  cand.lastAt = NOW();
  return c.json(autolistState());
});

app.post(`${API_BASE}/system/autolist/probe`, async (c) => {
  if (!autolistOn()) return c.json({ error: "the automatic list is not running" }, 409);
  const body = await c.req.json().catch(() => null);
  const host = typeof body?.host === "string" ? body.host : "";
  if (!/^[a-z0-9.-]+$/i.test(host)) return c.json({ error: "not a host name" }, 400);
  if (AUTOLIST_RUNNING) return c.json({ error: "another check is running" }, 409);
  if (AUTOLIST_RESULTS.length >= 30) {
    return c.json({ error: "the hourly limit of router checks is used up" }, 429);
  }
  const cand = AUTOLIST_CANDS.find((x) => x.host === host);
  if (cand && cand.state === "candidate") cand.state = "checking";
  AUTOLIST_RUNNING = host;
  setTimeout(() => {
    const [verdict, why, bytes, error] = AUTOLIST_VERDICTS[host] ?? ["open", "", 65536, ""];
    AUTOLIST_RESULTS = [
      { host, verdict, why, bytes, at: NOW(), error },
      ...AUTOLIST_RESULTS.filter((r) => r.host !== host),
    ];
    const c2 = AUTOLIST_CANDS.find((x) => x.host === host);
    if (c2 && c2.state === "checking") c2.state = "candidate";
    if (verdict === "blocked" && !c2) {
      AUTOLIST_CANDS.push({
        domain: host.split(".").slice(-2).join("."),
        host,
        why,
        fails: 0,
        clients: [],
        lastAt: NOW(),
        state: "candidate",
        notes: 0,
      });
    }
    AUTOLIST_RUNNING = null;
  }, AUTOLIST_PROBE_MS);
  return c.json(autolistState(), 202);
});

app.delete(`${API_BASE}/groups/:id/rules/:ruleId`, (c) => {
  const group = DATA.groups.find((g: any) => g.id === c.req.param("id"));
  const at = group?.rules.findIndex((r: any) => r.id === c.req.param("ruleId")) ?? -1;
  if (!group || at < 0) return c.json({ error: "not found" }, 404);
  group.rules.splice(at, 1);
  return c.json({});
});

app.put("/dev/live", async (c) => {
  const body = await c.req.json();
  if (typeof body?.group === "string") {
    if (body.reason) LIVE_REASONS[body.group] = body.reason;
    else delete LIVE_REASONS[body.group];
  }
  if (body?.netfilter && typeof body.netfilter.ok === "boolean") NETFILTER = body.netfilter;
  return c.json({ reasons: LIVE_REASONS, netfilter: NETFILTER });
});

app.put("/dev/autolist", async (c) => {
  const body = await c.req.json();
  if (typeof body?.wanWarning === "boolean") AUTOLIST_WAN_WARNING = body.wanWarning;
  return c.json({ wanWarning: AUTOLIST_WAN_WARNING });
});

app.put("/dev/ifaces", async (c) => {
  const body = await c.req.json();
  for (const [name, s] of Object.entries(body?.states ?? {})) IFACE_STATES[name] = s as any;
  for (const [id, at] of Object.entries(body?.active ?? {})) ACTIVE[id] = at as number;
  return c.json({ states: IFACE_STATES, active: ACTIVE });
});

app.get("*", serveStatic({ root: "./dist" }));

Deno.serve(
  { port: PORT, onListen: () => console.log(`running mock server on port ${PORT}...`) },
  app.fetch,
);
