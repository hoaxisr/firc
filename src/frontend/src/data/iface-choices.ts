import type { Interfaces } from "../types";
import { counted } from "../utils/plural";

export type IfaceItem = Interfaces["interfaces"][number];

export const BLACKHOLE = "blackhole";
export const BLOCK = "block";
export const DNS = "dns";
export const isSink = (id: string) => id === BLACKHOLE || id === BLOCK;
export const isSynthetic = (id: string) => isSink(id) || id === DNS;
export const DEVICE_PREFIXES = ["tunvless", "opkgtun"] as const;

export const isTunnelDevice = (id: string, tunnels: readonly { device: string }[]) =>
  tunnels.some((tn) => tn.device === id);

export function splitDevice(device: string): { prefix: string; num: string } {
  const prefix = DEVICE_PREFIXES.find((p) => device.startsWith(p)) ?? DEVICE_PREFIXES[0];
  return { prefix, num: device.startsWith(prefix) ? device.slice(prefix.length) : device };
}
const REST_ORDER: Record<string, number> = { wan: 0, lan: 1 };

export function ifaceTitle(i: IfaceItem): { title: string; sub: string | undefined } {
  const title = i.name || i.ndmsName;
  return title ? { title, sub: i.id } : { title: i.id, sub: undefined };
}

export function groupChoices(list: IfaceItem[], chosen: string[]) {
  const missing = chosen.filter((id) => !list.some((i) => i.id === id)).map((id) => ({ id }));
  const head = [...list.filter((i) => i.role === "tunnel"), ...missing];
  const blackhole = list.find((i) => i.id === BLACKHOLE);
  const block = list.find((i) => i.id === BLOCK);
  const dns = list.find((i) => i.id === DNS);
  const rest = list
    .filter((i) => !isSynthetic(i.id) && i.role !== "tunnel")
    .sort((a, b) => (REST_ORDER[a.role ?? ""] ?? 2) - (REST_ORDER[b.role ?? ""] ?? 2));
  const expanded = chosen.some((id) => rest.some((r) => r.id === id));
  return { head, blackhole, block, dns, rest, expanded };
}

export function lanChoices<T extends IfaceItem>(
  list: T[],
  query: string,
  tunnels: readonly { device: string }[],
): T[] {
  const q = query.trim().toLowerCase();
  const usable = list.filter((i) => !isSynthetic(i.id) && !isTunnelDevice(i.id, tunnels));
  if (q === "") return usable.filter((i) => i.role === "lan");
  return usable.filter((i) =>
    [i.id, i.name, i.ndmsName].some((s) => s !== undefined && s.toLowerCase().includes(q)),
  );
}

export function moreText(n: number, locale: string, t: (key: string) => string): string {
  return counted(
    n,
    locale,
    t("{n} more interface"),
    t("{n} more interfaces (2-4)"),
    t("{n} more interfaces"),
  );
}
