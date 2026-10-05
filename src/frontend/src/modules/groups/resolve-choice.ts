import {
  DEFAULT_RESOLVE,
  type GroupResolve,
  type GroupResolver,
  type SystemResolvers,
} from "../../types";

export type DnsMode = "auto" | "own" | "off";

export const WELL_KNOWN_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

export function modeOf(r: GroupResolve | undefined): DnsMode {
  if (r && !r.tunnel) return "off";
  if (r && r.server !== "") return "own";
  return "auto";
}

/* "off" and "auto" carry no server: the choice is the whole setting. */
export function resolveOf(mode: DnsMode, server: string): GroupResolve {
  if (mode === "off") return { tunnel: false, server: "" };
  if (mode === "own") return { tunnel: true, server: server.trim() };
  return { tunnel: true, server: "" };
}

export function firmwareServersFor(list: SystemResolvers["resolvers"], iface: string): string[] {
  return list.find((r) => r.interface === iface)?.servers ?? [];
}

export function serverSuggestions(list: SystemResolvers["resolvers"]): string[] {
  const out: string[] = [];
  for (const s of [...list.flatMap((r) => r.servers), ...WELL_KNOWN_RESOLVERS]) {
    if (!out.includes(s)) out.push(s);
  }
  return out;
}

export function isSavedAutoUnchanged(
  group: { interface: string; resolve: GroupResolve } | null | undefined,
  dialogMode: "create" | "edit",
  selectedInterface: string,
  dnsMode: DnsMode,
): boolean {
  if (dialogMode !== "edit" || !group) return false;
  if (modeOf(group.resolve) !== "auto") return false;
  if (selectedInterface !== group.interface) return false;
  return dnsMode === "auto";
}

export function autoEffectiveServers(params: {
  isEditingSavedAuto: boolean;
  resolver: GroupResolver | undefined;
  firmwareServers: string[];
}): string[] {
  const { isEditingSavedAuto, resolver, firmwareServers } = params;
  if (isEditingSavedAuto && resolver?.source === "firmware") return resolver.servers;
  return firmwareServers;
}

export function submittedResolve(
  isBlackhole: boolean,
  original: GroupResolve | undefined,
  mode: DnsMode,
  server: string,
): GroupResolve {
  if (isBlackhole) return original ?? DEFAULT_RESOLVE();
  return resolveOf(mode, server);
}

export function resolverTag(r: GroupResolver | undefined, t: (s: string) => string): string | null {
  if (!r) return null;
  if (r.source === "off") return t("DNS: not through the tunnel");
  if (r.servers.length === 0) return t("DNS: common upstream");
  return `${t("DNS")} ${r.servers.join(", ")}`;
}

export function fallbackCountText(
  r: GroupResolver | undefined,
  t: (s: string) => string,
): string | null {
  if (!r || r.fallbacks <= 0) return null;
  return t("fallbacks: {n}").replace("{n}", String(r.fallbacks));
}
