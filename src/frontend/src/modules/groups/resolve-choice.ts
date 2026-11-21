import type { DnsResolverSource } from "../../data/events.svelte";

import { BLOCK, DNS, isSink } from "../../data/iface-choices";
import {
  DEFAULT_RESOLVE,
  type BlockAnswer,
  type GroupResolve,
  type GroupResolver,
  type SystemResolvers,
} from "../../types";
import type { ResolverListProblem } from "../../utils/resolver-validators";
import { failureNote, resolverNote } from "../logs/journal";
import { ifaceList } from "./iface-list";
import { clockMinutes } from "./live-state";

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

export function sharedResolve(
  groups: readonly { interface: string | string[]; resolve: GroupResolve }[],
): GroupResolve | null {
  const open = groups.filter((g) => !ifaceList(g).some(isSink));
  if (open.length === 0) return null;
  const { tunnel, server } = open[0].resolve;
  const same = open.every((g) => g.resolve.tunnel === tunnel && g.resolve.server === server);
  return same ? { tunnel, server } : null;
}

export function serverProblemText(
  check: { problem: ResolverListProblem; entry: string } | null,
  raw: string,
  t: (k: string) => string,
): string {
  const problem = check?.problem ?? null;
  const entry = check?.entry ?? "";
  const named = (text: string) => (raw.includes(",") ? `${entry}: ${text}` : text);
  if (problem === "port") return named(t("The port must be between 1 and 65535"));
  if (problem === "sink")
    return named(t("This address cannot be a DNS server (0.0.0.0, 127.x, ::, ::1)"));
  if (problem === "mapped") return named(t("Write the IPv4 address itself"));
  if (problem === "url")
    return named(t("A link must look like https://host/path, without a query"));
  if (problem === "duplicate") return t("{entry} is written twice").replace("{entry}", entry);
  if (problem === "too-many") return t("At most four servers");
  if (problem === "syntax" && entry.includes(" "))
    return named(t("Separate the servers with commas"));
  if (problem === "syntax" || problem === "empty")
    return t(
      "One to four servers separated by commas: address, address:port, [IPv6]:port or https://host/path",
    );
  return "";
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
  group: { interface: string | string[]; resolve: GroupResolve } | null | undefined,
  dialogMode: "create" | "edit",
  selectedInterface: string,
  dnsMode: DnsMode,
): boolean {
  if (dialogMode !== "edit" || !group) return false;
  if (modeOf(group.resolve) !== "auto") return false;
  if (selectedInterface !== ifaceList(group)[0]) return false;
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
  iface: string,
  original: GroupResolve | undefined,
  mode: DnsMode,
  server: string,
  fallbackOn = true,
): GroupResolve {
  if (iface === DNS) return { tunnel: true, server: server.trim(), fallback: fallbackOn };
  if (isSink(iface)) return original ?? DEFAULT_RESOLVE();
  return resolveOf(mode, server);
}

const BLOCK_CODE: Record<BlockAnswer, string> = {
  null: "0.0.0.0",
  nxdomain: "NXDOMAIN",
  refused: "REFUSED",
};

export function blockCode(answer: BlockAnswer | undefined): string {
  return BLOCK_CODE[answer ?? "null"];
}

export function resolverTag(
  group:
    | {
        interface: string | string[];
        block?: BlockAnswer;
        resolve?: GroupResolve;
        resolver?: GroupResolver;
      }
    | undefined,
  t: (s: string) => string,
): string | null {
  if (group?.interface === BLOCK) {
    return t("DNS: blocking · {code}").replace("{code}", blockCode(group.block));
  }
  const r = group?.resolver;
  if (group?.interface === DNS) {
    const servers = r?.servers.length ? r.servers.join(", ") : (group.resolve?.server ?? "");
    return servers === "" ? null : `${t("DNS")} ${servers}`;
  }
  if (!r) return null;
  if (r.source === "off") return t("DNS: not through the tunnel");
  if (r.servers.length === 0) return t("DNS: common upstream");
  return `${t("DNS")} ${r.servers.join(", ")}`;
}

export type HealthTag = { kind: "amber" | "red"; text: string; tip: string };

export function healthTag(
  r: GroupResolver | undefined,
  t: (s: string) => string,
  withoutFallback = false,
): HealthTag | null {
  if (!r || r.source === "off") return null;
  const h = r.health;
  const open = t("Click to open the group's journal.");
  if (h.resting) {
    const since = withoutFallback
      ? t(
          "Since {time} the group's DNS is not answering, the group's names get SERVFAIL. firc checks it every 30 s.",
        )
      : t(
          "Since {time} the group's DNS is not answering, the common upstream answers. firc checks it every 30 s.",
        );
    return {
      kind: "red",
      text: t("The group's DNS is not answering"),
      tip: `${since.replace("{time}", clockMinutes(h.since))} ${open}`,
    };
  }
  if (h.fallbacks <= 0) return null;
  const note = withoutFallback
    ? failureNote(h.reason as DnsResolverSource, t)
    : resolverNote(h.reason as DnsResolverSource, t);
  return {
    kind: "amber",
    text: t("The group's DNS is failing: {fallbacks} of {total} in {minutes} min")
      .replace("{fallbacks}", String(h.fallbacks))
      .replace("{total}", String(h.total))
      .replace("{minutes}", String(Math.round(h.window / 60))),
    tip: `${t("Last failure at {time}: {note}.").replace("{time}", clockMinutes(h.last)).replace("{note}", note)} ${open}`,
  };
}
