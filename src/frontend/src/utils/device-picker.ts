import type { DeviceSelector } from "../types";
import {
  isValidDeviceEntry,
  MAC_PREFIX,
  normalizeMac,
  parseV4,
  parseV6,
  POLICY_PREFIX,
} from "./device-validators";
import { counted } from "./plural";

export type Side = "allow" | "deny";

export type Host = {
  mac: string;
  name: string;
  ip: string;
  ip6: string[];
  active: boolean;
  registered: boolean;
  policy: string;
};

/* One policy of GET /api/v1/system/policies; `devices` counts hosts. */
export type PickerPolicy = { name: string; description?: string; devices: number };

export type Translate = (key: string) => string;

export type Picked = {
  policies: Map<string, Side>;
  macs: Map<string, Side>;
  manual: { allow: string[]; deny: string[] };
};

function entryKey(entry: string): string | null {
  if (entry.startsWith(POLICY_PREFIX) && isValidDeviceEntry(entry)) return entry;
  const mac = entry.startsWith(MAC_PREFIX) ? normalizeMac(entry.slice(MAC_PREFIX.length)) : null;
  return mac === null ? null : `${MAC_PREFIX}${mac}`;
}

export function splitSelector(sel: DeviceSelector | undefined): Picked {
  const picked: Picked = { policies: new Map(), macs: new Map(), manual: { allow: [], deny: [] } };
  const allow = sel?.allow ?? [];
  const deny = sel?.deny ?? [];
  const denied = new Set(deny.map(entryKey));
  const both = new Set(allow.map(entryKey).filter((k) => k !== null && denied.has(k)));
  const take = (entries: string[], side: Side) => {
    for (const entry of entries) {
      const key = entryKey(entry);
      if (key === null || both.has(key)) {
        picked.manual[side].push(entry);
      } else if (key.startsWith(POLICY_PREFIX)) {
        picked.policies.set(key.slice(POLICY_PREFIX.length), side);
      } else {
        picked.macs.set(key.slice(MAC_PREFIX.length), side);
      }
    }
  };
  take(allow, "allow");
  take(deny, "deny");
  return picked;
}

export function foldManual(p: Picked): Picked {
  const typed = splitSelector({ allow: p.manual.allow, deny: p.manual.deny });
  const policies = new Map(p.policies);
  const macs = new Map(p.macs);
  for (const [k, side] of typed.policies)
    if (side === "deny" || !policies.has(k)) policies.set(k, side);
  for (const [k, side] of typed.macs) if (side === "deny" || !macs.has(k)) macs.set(k, side);
  return { policies, macs, manual: typed.manual };
}

export function joinSelector(p: Picked): DeviceSelector {
  const folded = foldManual(p);
  const out: DeviceSelector = { allow: [], deny: [] };
  for (const [name, side] of folded.policies) out[side].push(`${POLICY_PREFIX}${name}`);
  for (const [mac, side] of folded.macs) out[side].push(`${MAC_PREFIX}${mac}`);
  out.allow.push(...folded.manual.allow);
  out.deny.push(...folded.manual.deny);
  return out;
}

export function setEntry(
  p: Picked,
  kind: "policy" | "mac",
  key: string,
  side: Side | null,
): Picked {
  const next: Picked = {
    policies: new Map(p.policies),
    macs: new Map(p.macs),
    manual: { allow: [...p.manual.allow], deny: [...p.manual.deny] },
  };
  const map = kind === "policy" ? next.policies : next.macs;
  if (side === null) map.delete(key);
  else map.set(key, side);
  return next;
}

const policyLabel = (pol: PickerPolicy) => pol.description || pol.name;

function routerPolicy(key: string, policies: PickerPolicy[]): PickerPolicy | undefined {
  return (
    policies.find((pol) => (pol.description || pol.name) === key) ??
    policies.find((pol) => pol.name === key)
  );
}

function namesPolicy(key: string, id: string, policies: PickerPolicy[]): boolean {
  const pol = routerPolicy(key, policies);
  return pol ? pol.name === id : key === id;
}

function policySide(p: Picked, id: string, policies: PickerPolicy[]): Side | null {
  const sides: Side[] = [];
  for (const [k, side] of p.policies) if (namesPolicy(k, id, policies)) sides.push(side);
  for (const side of ["allow", "deny"] as Side[])
    for (const e of p.manual[side])
      if (e.startsWith(POLICY_PREFIX) && namesPolicy(e.slice(POLICY_PREFIX.length), id, policies))
        sides.push(side);
  return sides.includes("deny") ? "deny" : sides.includes("allow") ? "allow" : null;
}

function writeKey(p: Picked, id: string, policies: PickerPolicy[]): string | null {
  const pol = policies.find((x) => x.name === id);
  if (pol === undefined) return id;
  const stored = [...p.policies.keys()].find((k) => namesPolicy(k, id, policies));
  const spelled = [pol.name, pol.description ?? ""].find(
    (k) => k !== "" && routerPolicy(k, policies) === pol,
  );
  return stored ?? spelled ?? null;
}

export type PolicyChip = {
  id: string;
  key: string;
  label: string;
  devices: number | null;
  side: Side | null;
  takenBy: string | null;
};

export function policyChips(p: Picked, policies: PickerPolicy[]): PolicyChip[] {
  const chips: PolicyChip[] = [];
  const claimed = new Set<string>();
  for (const pol of policies) {
    for (const k of p.policies.keys()) if (namesPolicy(k, pol.name, policies)) claimed.add(k);
    const key = writeKey(p, pol.name, policies);
    chips.push({
      id: pol.name,
      key: key ?? pol.name,
      label: policyLabel(pol),
      devices: pol.devices,
      side: policySide(p, pol.name, policies),
      takenBy: key === null ? (routerPolicy(pol.name, policies)?.name ?? null) : null,
    });
  }
  for (const [key, side] of p.policies) {
    if (!claimed.has(key))
      chips.push({ id: key, key, label: key, devices: null, side, takenBy: null });
  }
  return chips;
}

export type HostRow = Host & { side: Side | null; unknown: boolean };

function oneHostPerMac(hosts: Host[]): Host[] {
  const byMac = new Map<string, Host>();
  for (const h of hosts) {
    const kept = byMac.get(h.mac);
    if (kept === undefined || (h.active && !kept.active)) byMac.set(h.mac, h);
  }
  return [...byMac.values()];
}

export function hostRows(listed: Host[], p: Picked, keep: Iterable<string> = []): HostRow[] {
  const hosts = oneHostPerMac(listed);
  const rows: HostRow[] = hosts.map((h) => ({
    ...h,
    side: p.macs.get(h.mac) ?? null,
    unknown: false,
  }));
  const known = new Set(hosts.map((h) => h.mac));
  for (const mac of [...p.macs.keys(), ...keep]) {
    if (known.has(mac)) continue;
    known.add(mac);
    rows.push({
      mac,
      name: "",
      ip: "",
      ip6: [],
      active: false,
      registered: false,
      policy: "",
      side: p.macs.get(mac) ?? null,
      unknown: true,
    });
  }
  return rows;
}

export type Mode = "all" | "only";

export function hasAllow(p: Picked): boolean {
  return (
    [...p.policies.values(), ...p.macs.values()].includes("allow") || p.manual.allow.length > 0
  );
}

export function selectorMode(p: Picked): Mode {
  return hasAllow(p) ? "only" : "all";
}

export function setMode(p: Picked, mode: Mode): Picked {
  if (mode === "only") return p;
  const keepDeny = <K>(m: Map<K, Side>) => new Map([...m].filter(([, s]) => s === "deny"));
  return {
    policies: keepDeny(p.policies),
    macs: keepDeny(p.macs),
    manual: { allow: [], deny: [...p.manual.deny] },
  };
}

export function policyOn(side: Side | null, mode: Mode): boolean {
  return side === "deny" ? false : side === "allow" ? true : mode === "all";
}

export function flipPolicy(p: Picked, id: string, policies: PickerPolicy[], mode: Mode): Picked {
  const key = writeKey(p, id, policies);
  if (key === null) return p;
  const target = !policyOn(policySide(p, id, policies), mode);
  const names = (k: string) => namesPolicy(k, id, policies);
  const nameless = (entries: string[]) =>
    entries.filter((e) => !(e.startsWith(POLICY_PREFIX) && names(e.slice(POLICY_PREFIX.length))));
  const cleared: Picked = {
    policies: new Map([...p.policies].filter(([k]) => !names(k))),
    macs: new Map(p.macs),
    manual: { allow: nameless(p.manual.allow), deny: nameless(p.manual.deny) },
  };
  if (policyOn(null, mode) === target) return cleared;
  return setEntry(cleared, "policy", key, target ? "allow" : "deny");
}

export type RowNote =
  | { kind: "policy-off"; policy: string }
  | { kind: "manual-off" }
  | { kind: "excluded-from"; policy: string }
  | { kind: "excluded" }
  | { kind: "via"; policy: string }
  | { kind: "manual-on" }
  | null;

export type RowState = { on: boolean; locked: boolean; note: RowNote };

function rowPolicy(
  row: HostRow,
  p: Picked,
  policies: PickerPolicy[],
): { label: string; side: Side | null } | null {
  if (row.policy === "") return null;
  const pol = policies.find((x) => x.name === row.policy);
  const side = [...p.policies]
    .filter(([k]) => namesPolicy(k, row.policy, policies))
    .map(([, s]) => s)
    .reduce<Side | null>((acc, s) => (acc === "deny" || s === "deny" ? "deny" : s), null);
  return { label: pol ? policyLabel(pol) : row.policy, side };
}

function manualCovers(entry: string, row: HostRow, policies: PickerPolicy[]): boolean {
  if (entry.startsWith(MAC_PREFIX)) return normalizeMac(entry.slice(MAC_PREFIX.length)) === row.mac;
  if (entry.startsWith(POLICY_PREFIX))
    return (
      row.policy !== "" && namesPolicy(entry.slice(POLICY_PREFIX.length), row.policy, policies)
    );
  return [row.ip, ...row.ip6].some((a) => a !== "" && addressCovers(entry, a));
}

export function rowState(row: HostRow, p: Picked, policies: PickerPolicy[], mode: Mode): RowState {
  const pol = rowPolicy(row, p, policies);
  if (pol?.side === "deny")
    return { on: false, locked: true, note: { kind: "policy-off", policy: pol.label } };
  if (p.manual.deny.some((e) => manualCovers(e, row, policies)))
    return { on: false, locked: true, note: { kind: "manual-off" } };
  if (row.side === "deny") {
    const note: RowNote =
      pol?.side === "allow" ? { kind: "excluded-from", policy: pol.label } : { kind: "excluded" };
    return { on: false, locked: false, note };
  }
  if (mode === "all" || row.side === "allow") return { on: true, locked: false, note: null };
  if (pol?.side === "allow")
    return { on: true, locked: false, note: { kind: "via", policy: pol.label } };
  if (p.manual.allow.some((e) => manualCovers(e, row, policies)))
    return { on: true, locked: false, note: { kind: "manual-on" } };
  return { on: false, locked: false, note: null };
}

export function flipRow(p: Picked, row: HostRow, policies: PickerPolicy[], mode: Mode): Picked {
  const now = rowState(row, p, policies, mode);
  if (now.locked) return p;
  const cleared = setEntry(p, "mac", row.mac, null);
  const plain = rowState({ ...row, side: null }, cleared, policies, mode);
  if (plain.on !== now.on) return cleared;
  return setEntry(p, "mac", row.mac, now.on ? "deny" : "allow");
}

export function visibleRows(rows: HostRow[], query: string): HostRow[] {
  const q = query.trim().toLowerCase();
  const qMac = q.replaceAll("-", ":");
  const hit = (r: HostRow) =>
    q === "" ||
    [r.name, r.ip, ...r.ip6].some((f) => f.toLowerCase().includes(q)) ||
    r.mac.includes(qMac);
  return rows
    .filter(hit)
    .sort(
      (a, b) =>
        Number(b.active) - Number(a.active) ||
        Number(a.name === "") - Number(b.name === "") ||
        a.name.localeCompare(b.name) ||
        a.mac.localeCompare(b.mac),
    );
}

/* Whether an address or prefix entry covers `addr`; families never cross. */
export function addressCovers(entry: string, addr: string): boolean {
  const slash = entry.indexOf("/");
  const netText = slash === -1 ? entry : entry.slice(0, slash);
  const net = netText.includes(":") ? parseV6(netText) : parseV4(netText);
  const ip = addr.includes(":") ? parseV6(addr) : parseV4(addr);
  if (net === null || ip === null || net.length !== ip.length) return false;
  const prefix = slash === -1 ? net.length * 8 : Number(entry.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > net.length * 8) return false;
  const full = Math.floor(prefix / 8);
  for (let i = 0; i < full; i++) if (net[i] !== ip[i]) return false;
  const rest = prefix % 8;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (net[full] & mask) === (ip[full] & mask);
}

function coveredKeys(entries: string[], hosts: Host[], policies: PickerPolicy[]): Set<string> {
  const keys = new Set<string>();
  for (const entry of entries) {
    if (entry.startsWith(MAC_PREFIX)) {
      const mac = normalizeMac(entry.slice(MAC_PREFIX.length));
      if (mac !== null) keys.add(mac);
      continue;
    }
    if (entry.startsWith(POLICY_PREFIX)) {
      const pol = routerPolicy(entry.slice(POLICY_PREFIX.length), policies);
      if (pol === undefined) continue;
      if (hosts.length === 0) {
        for (let i = 0; i < pol.devices; i++) keys.add(`${entry}#${i}`);
        continue;
      }
      for (const h of hosts) if (h.policy === pol.name) keys.add(h.mac);
      continue;
    }
    const covered = hosts.filter((h) =>
      [h.ip, ...h.ip6].some((a) => a !== "" && addressCovers(entry, a)),
    );
    if (covered.length === 0) keys.add(`entry:${entry}`);
    for (const h of covered) keys.add(h.mac);
  }
  return keys;
}

export function coverageLabel(
  sel: DeviceSelector | undefined,
  hosts: Host[],
  policies: PickerPolicy[],
  t: Translate,
  locale: string,
): string {
  const allowEntries = sel?.allow ?? [];
  const denyEntries = sel?.deny ?? [];
  const deny = coveredKeys(denyEntries, hosts, policies);
  if (allowEntries.length === 0) {
    if (denyEntries.length === 0) return t("Every device");
    return t("All but {n}").replace("{n}", String(deny.size));
  }
  let n = 0;
  for (const k of coveredKeys(allowEntries, hosts, policies)) if (!deny.has(k)) n++;
  return counted(n, locale, t("{n} device"), t("{n} devices (2-4)"), t("{n} devices"));
}
