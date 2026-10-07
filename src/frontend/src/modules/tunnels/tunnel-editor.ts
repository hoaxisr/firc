import type { Tunnel, TunnelProbeRow, TunnelUplink } from "../../types";
import { intervalLabel } from "../groups/intervals";

type T = (key: string) => string;

export type UplinkOption = {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
  hint?: string;
};

export type NodeDnD = { scope: string; key: string; edge?: "before" | "after" };

export const DEVICE_PATTERN = /^tunvless([0-9]|[1-9][0-9])$/;

export function orderAfterDrop(
  visible: string[],
  moved: string,
  target: string,
  edge: "before" | "after",
): string[] {
  if (moved === target || !visible.includes(moved) || !visible.includes(target)) {
    return [...visible];
  }
  const rest = visible.filter((key) => key !== moved);
  const at = rest.indexOf(target) + (edge === "after" ? 1 : 0);
  rest.splice(at, 0, moved);
  return rest;
}

export function keepHidden(newVisible: string[], order: string[]): string[] {
  return [...newVisible, ...order.filter((key) => !newVisible.includes(key))];
}

export function latencyOf(row: TunnelProbeRow | undefined): number | null {
  return row && row.ok && row.handshakeMs !== null ? row.handshakeMs : null;
}

export function orderByLatency(
  visible: string[],
  probes: Record<string, TunnelProbeRow | undefined>,
): string[] {
  const rank = (key: string) => {
    const row = probes[key];
    if (!row) return 1;
    return latencyOf(row) === null ? 2 : 0;
  };
  return visible
    .map((key, index) => ({ key, index, rank: rank(key), ms: latencyOf(probes[key]) ?? 0 }))
    .sort((a, b) => a.rank - b.rank || a.ms - b.ms || a.index - b.index)
    .map((row) => row.key);
}

export function toggleExclude(exclude: string[], key: string): string[] {
  return exclude.includes(key) ? exclude.filter((k) => k !== key) : [...exclude, key];
}

export function wouldCycle(
  tunnels: Pick<Tunnel, "id" | "uplink">[],
  selfId: string,
  targetId: string,
): boolean {
  const seen = new Set<string>();
  let cur: string | undefined = targetId;
  while (cur !== undefined && !seen.has(cur)) {
    if (cur === selfId) return true;
    seen.add(cur);
    const next = tunnels.find((tn) => tn.id === cur);
    cur = next?.uplink.kind === "tunnel" ? next.uplink.ref : undefined;
  }
  return false;
}

export function uplinkValue(uplink: TunnelUplink): string {
  return uplink.kind === "auto" ? "auto" : `${uplink.kind}:${uplink.ref}`;
}

export function parseUplink(value: string): TunnelUplink {
  const at = value.indexOf(":");
  const kind = value.slice(0, at);
  if (at > 0 && (kind === "iface" || kind === "tunnel")) {
    return { kind, ref: value.slice(at + 1) };
  }
  return { kind: "auto", ref: "" };
}

export function uplinkOptions(
  self: Tunnel,
  tunnels: Tunnel[],
  ifaces: { id: string; name?: string }[],
  t: T,
): UplinkOption[] {
  const devices = new Set(tunnels.map((tn) => tn.device));
  const usable = ifaces.filter(
    (i) => i.id !== "blackhole" && !DEVICE_PATTERN.test(i.id) && !devices.has(i.id),
  );
  const options: UplinkOption[] = [{ value: "auto", label: t("Auto") }];
  for (const i of usable) {
    options.push({ value: `iface:${i.id}`, label: i.id, description: i.name });
  }
  if (self.uplink.kind === "iface" && !usable.some((i) => i.id === self.uplink.ref)) {
    options.push({ value: `iface:${self.uplink.ref}`, label: self.uplink.ref });
  }
  for (const other of tunnels) {
    if (other.id === self.id) continue;
    const cycle = wouldCycle(tunnels, self.id, other.id);
    options.push({
      value: `tunnel:${other.id}`,
      label: t("Through tunnel {name}").replace("{name}", other.device || other.id),
      disabled: cycle,
      hint: cycle ? t("This tunnel already goes out through this one: a loop") : undefined,
    });
  }
  return options;
}

const RUN_FIELDS = [
  "device",
  "enable",
  "active",
  "by",
  "interval",
  "silence",
  "uplink",
  "advanced",
] as const;

function runShape(tunnel: Tunnel): string {
  return JSON.stringify(RUN_FIELDS.map((field) => tunnel[field]));
}

export function restartingDevices(before: Tunnel[], after: Tunnel[]): string[] {
  const saved = new Map(before.map((tn) => [tn.id, tn]));
  const out: string[] = [];
  for (const tn of after) {
    const old = saved.get(tn.id);
    if (!old || (!old.enable && !tn.enable)) continue;
    if (runShape(old) !== runShape(tn)) out.push(tn.device);
  }
  return out;
}

export function deviceProblem(
  device: string,
  tunnels: Tunnel[],
  selfId: string,
  t: T = (key) => key,
): string | null {
  if (!DEVICE_PATTERN.test(device)) return t("Device must be tunvless0 to tunvless99");
  if (tunnels.some((tn) => tn.id !== selfId && tn.device === device)) {
    return t("Another tunnel uses this device");
  }
  return null;
}

export function linkName(link: string): string {
  const hash = link.indexOf("#");
  if (hash >= 0 && hash < link.length - 1) {
    const raw = link.slice(hash + 1);
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  const host = /^[a-z]+:\/\/(?:[^@/]*@)?(\[[^\]]*\]|[^:/?#]+)/i.exec(link);
  return host ? host[1] : link;
}

export function middleEllipsis(text: string, max: number): string {
  if (text.length <= max) return text;
  const room = Math.max(0, max - 1);
  const head = Math.ceil(room / 2);
  return `${text.slice(0, head)}…${text.slice(text.length - (room - head))}`;
}

function oneDecimal(n: number): string {
  return n.toFixed(1).replace(/\.0$/, "");
}

export function formatRate(bytesPerS: number, t: T): string {
  const bits = Math.max(0, bytesPerS) * 8;
  return bits >= 1e6
    ? t("{n} Mbit/s").replace("{n}", oneDecimal(bits / 1e6))
    : t("{n} Kbit/s").replace("{n}", oneDecimal(bits / 1e3));
}

export function agoText(now: number, since: number, t: T): string {
  const s = Math.max(0, Math.floor(now - since));
  if (s < 60) return t("{n} s").replace("{n}", String(s));
  if (s < 3600) return t("{n} min").replace("{n}", String(Math.floor(s / 60)));
  if (s < 86400) return t("{n} h").replace("{n}", String(Math.floor(s / 3600)));
  return t("{n} d").replace("{n}", String(Math.floor(s / 86400)));
}

export function subscriptionIntervals(current: number, t: T): { value: string; label: string }[] {
  const options = [
    { value: "0", label: t("manually") },
    { value: "3600", label: t("once an hour") },
    { value: "21600", label: t("every 6 hours") },
    { value: "43200", label: t("every 12 hours") },
    { value: "86400", label: t("once a day") },
    { value: "604800", label: t("once a week") },
  ];
  if (!options.some((o) => o.value === String(current))) {
    options.push({ value: String(current), label: intervalLabel(current, t) });
  }
  return options;
}

export function subscriptionProblem(
  name: string,
  url: string,
  taken: string[],
  t: T,
): string | null {
  if (!/^[A-Za-z0-9 ._-]{1,63}$/.test(name)) {
    return t("Name: 1 to 63 Latin letters, digits, spaces, dots, _ or -");
  }
  if (taken.includes(name)) return t("Another subscription of this tunnel has this name");
  if (!/^https?:\/\/\S+$/.test(url)) return t("The URL must start with http:// or https://");
  return null;
}

export function linkProblem(link: string, t: T): string | null {
  return /^vless:\/\/\S+$/.test(link) ? null : t("One vless:// link");
}
