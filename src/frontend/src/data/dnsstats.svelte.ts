import type { Group, Rule } from "../types";
import { entryKey, type Host } from "../utils/device-picker";
import { fetcher } from "../utils/fetcher";

export type DnsStatsOwner = { id: string; name: string; interface: string; blocked: boolean };

export type DnsStatsRow = {
  name: string;
  queries: number;
  blocked: number;
  last: number;
  owner: DnsStatsOwner | null;
  clients: { address: string; queries: number }[];
  clientsTotal: number;
};

export type DnsStatsRes = {
  window: number;
  now: number;
  since: number;
  queries: number;
  blocked: number;
  domains: number;
  rows: DnsStatsRow[];
  matched: number;
  offset: number;
};

export type StatsQuery = { addresses: string[]; q: string; arpa: boolean };

export type StatsDevice = { key: string; label: string; entry: string; addresses: string[] };

export type RowDevice = { key: string; label: string; address: string; queries: number };

export type BlockScope = "all" | "device";

export const STATS_REFRESH_MS = 10_000;
export const STATS_LIMIT = 500;
export const DEVICE_ADDRESSES_MAX = 12;

export const dnsStats = $state({
  data: null as DnsStatsRes | null,
  failed: false,
});

export const statsFilter = $state({ device: "", q: "", arpa: false, seen: [] as string[] });

let generation = 0;

export function statsPath(query: StatsQuery): string {
  const params = new URLSearchParams({ limit: String(STATS_LIMIT) });
  if (query.addresses.length) {
    params.set("device", query.addresses.join(","));
  }
  if (query.q.trim()) params.set("q", query.q.trim());
  if (query.arpa) params.set("arpa", "1");
  return `/system/dnsstats?${params}`;
}

export async function fetchDnsStats(query: StatsQuery): Promise<void> {
  const gen = ++generation;
  try {
    const data = await fetcher.get<DnsStatsRes>(statsPath(query), { quiet: true });
    if (gen !== generation) return;
    dnsStats.data = data;
    dnsStats.failed = false;
  } catch (error) {
    if (gen !== generation) return;
    console.error("Failed to read the DNS stats:", error);
    dnsStats.failed = true;
  }
}

export function statsDevices(hosts: Host[], seen: string[]): StatsDevice[] {
  const out: StatsDevice[] = [];
  const byMac = new Map<string, StatsDevice>();
  const claimed = new Set<string>();
  for (const h of hosts) {
    const addresses = [h.ip, ...h.ip6].filter(Boolean).map((a) => a.toLowerCase());
    const known = h.mac ? byMac.get(h.mac) : undefined;
    if (known) {
      for (const a of addresses) if (!known.addresses.includes(a)) known.addresses.push(a);
      if (!known.label || known.label === known.addresses[0]) known.label = h.name || known.label;
    } else {
      if (!addresses.length) continue;
      const entry = h.mac ? `mac:${h.mac}` : addresses[0];
      const device = { key: entry, label: h.name || addresses[0], entry, addresses };
      out.push(device);
      if (h.mac) byMac.set(h.mac, device);
    }
    for (const a of addresses) claimed.add(a);
  }
  for (const raw of seen) {
    const a = raw.toLowerCase();
    if (claimed.has(a)) continue;
    claimed.add(a);
    out.push({ key: a, label: a, entry: a, addresses: [a] });
  }
  return out;
}

export function rowDevices(
  clients: { address: string; queries: number }[],
  devices: StatsDevice[],
): RowDevice[] {
  const owner = new Map<string, StatsDevice>();
  for (const d of devices) for (const a of d.addresses) owner.set(a, d);
  const merged = new Map<string, RowDevice & { top: number }>();
  for (const c of clients) {
    const a = c.address.toLowerCase();
    const d = owner.get(a);
    const key = d?.key ?? a;
    const kept = merged.get(key);
    if (!kept) {
      merged.set(key, {
        key,
        label: d?.label ?? c.address,
        address: c.address,
        queries: c.queries,
        top: c.queries,
      });
      continue;
    }
    kept.queries += c.queries;
    if (c.queries > kept.top) {
      kept.top = c.queries;
      kept.address = c.address;
    }
  }
  return [...merged.values()].sort((a, b) => b.queries - a.queries).map(({ top: _top, ...d }) => d);
}

export function relativeTime(at: number, now: number, t: (s: string) => string): string {
  const s = now - at;
  if (s < 60) return t("just now");
  if (s < 3600) return t("{n} min ago").replace("{n}", String(Math.floor(s / 60)));
  return t("{n} h ago").replace("{n}", String(Math.floor(s / 3600)));
}

export function deviceAddresses(device: StatsDevice, seen: string[]): string[] {
  const asked = new Set(seen.map((a) => a.toLowerCase()));
  const first = device.addresses.filter((a) => asked.has(a));
  const rest = device.addresses.filter((a) => !asked.has(a));
  return [...first, ...rest].slice(0, DEVICE_ADDRESSES_MAX);
}

const isBlock = (g: Group) => g.interface === "block";

const sameEntry = (a: string, b: string) =>
  (entryKey(a) ?? a.trim().toLowerCase()) === (entryKey(b) ?? b.trim().toLowerCase());

function admitsOnly(g: Group, entry: string): boolean {
  return g.devices.allow.length === 1 && sameEntry(g.devices.allow[0], entry);
}

export function blockTargets(groups: Group[], entry: string | null): Group[] {
  return groups.filter((g) => {
    if (!isBlock(g) || g.enable === false) return false;
    if (g.devices.deny.length > 0) return false;
    if (entry === null) return g.devices.allow.length === 0;
    return admitsOnly(g, entry);
  });
}

function appliesInView(g: Group, entry: string | null): boolean {
  if (!isBlock(g) || g.enable === false || g.devices.deny.length > 0) return false;
  return g.devices.allow.length === 0 || (entry !== null && admitsOnly(g, entry));
}

export type HeldIndex = Map<string, { group: Group; rule: Rule }[]>;

export function heldIndex(groups: Group[], entry: string | null): HeldIndex {
  const index: HeldIndex = new Map();
  for (const g of groups) {
    if (!appliesInView(g, entry)) continue;
    for (const rule of g.rules) {
      if (!rule.enable || rule.type !== "domain") continue;
      const list = index.get(rule.rule) ?? [];
      if (!list.some((h) => h.group === g)) list.push({ group: g, rule });
      index.set(rule.rule, list);
    }
  }
  return index;
}

export function rowStatus(
  row: DnsStatsRow,
  groups: Group[],
  entry: string | null,
  isDirty: (rule: Rule) => boolean,
  index: HeldIndex = heldIndex(groups, entry),
): { group: string; unsaved: boolean } | null {
  const held = index.get(row.name) ?? [];
  const fresh = held.find((h) => isDirty(h.rule));
  if (fresh) return { group: fresh.group.name, unsaved: true };
  const owner = row.owner ? groups.find((g) => g.id === row.owner?.id) : undefined;
  if (owner && isBlock(owner) && owner.enable !== false && ownerApplies(owner, entry)) {
    return { group: owner.name, unsaved: false };
  }
  const saved = held.find((h) => !ownerAbove(groups, row.owner?.id ?? null, h.group.id));
  return saved ? { group: saved.group.name, unsaved: false } : null;
}

function ownerApplies(g: Group, entry: string | null): boolean {
  return entry !== null || (g.devices.allow.length === 0 && g.devices.deny.length === 0);
}

export function rowAbove(
  row: DnsStatsRow,
  groups: Group[],
  entry: string | null,
  index: HeldIndex = heldIndex(groups, entry),
): string {
  for (const h of index.get(row.name) ?? []) {
    const above = ownerAbove(groups, row.owner?.id ?? null, h.group.id);
    if (above) return above.name;
  }
  return "";
}

export function ownerAbove(
  groups: Group[],
  ownerId: string | null,
  targetId: string | null,
): Group | null {
  if (!ownerId || !targetId) return null;
  const oi = groups.findIndex((g) => g.id === ownerId);
  const ti = groups.findIndex((g) => g.id === targetId);
  if (oi < 0 || ti < 0 || oi >= ti || isBlock(groups[oi])) return null;
  return groups[oi];
}
