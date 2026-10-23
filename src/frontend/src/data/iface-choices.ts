import type { Interfaces } from "../types";
import { counted } from "../utils/plural";

export type IfaceItem = Interfaces["interfaces"][number];

export const BLACKHOLE = "blackhole";
export const BLOCK = "block";
export const isSink = (id: string) => id === BLACKHOLE || id === BLOCK;
export const TUNVLESS_DEVICE = /^tunvless([0-9]|[1-9][0-9])$/;
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
  const rest = list
    .filter((i) => !isSink(i.id) && i.role !== "tunnel")
    .sort((a, b) => (REST_ORDER[a.role ?? ""] ?? 2) - (REST_ORDER[b.role ?? ""] ?? 2));
  const expanded = chosen.some((id) => rest.some((r) => r.id === id));
  return { head, blackhole, block, rest, expanded };
}

export function lanChoices<T extends IfaceItem>(list: T[], query: string): T[] {
  const q = query.trim().toLowerCase();
  const usable = list.filter((i) => !isSink(i.id) && !TUNVLESS_DEVICE.test(i.id));
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
