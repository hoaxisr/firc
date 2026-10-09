import type {
  BypassEvent,
  DnsEvent,
  DnsResolverSource,
  JournalEvent,
  LogLevel,
} from "../../data/events.svelte";

export type Kind = "log" | "dns" | "bypass";

export type JournalFilter = {
  kinds: Set<Kind>;
  minLevel: LogLevel;
  group: string;
};

const ORDER: LogLevel[] = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];

export function levelRank(l: LogLevel): number {
  const i = ORDER.indexOf(l);
  return i < 0 ? 0 : i;
}

export type GroupRef = { id: string; name: string };
export type FilterOption = { value: string; label: string };

export function groupFilterOptions(
  known: GroupRef[] | null,
  seen: GroupRef[],
  t: (s: string) => string,
): FilterOption[] {
  const out: FilterOption[] = [{ value: "", label: t("any group") }];
  const ids = new Set<string>();
  for (const g of known ?? []) {
    if (ids.has(g.id)) continue;
    ids.add(g.id);
    out.push({ value: g.id, label: g.name || g.id });
  }
  for (const g of seen) {
    if (ids.has(g.id)) continue;
    ids.add(g.id);
    const name = g.name || g.id;
    out.push({ value: g.id, label: known ? `${name} ${t("(deleted)")}` : name });
  }
  return out;
}

export function matches(e: JournalEvent, f: JournalFilter): boolean {
  if (!f.kinds.has(e.kind)) return false;
  if (e.kind === "log") {
    if (f.group) return false;
    return levelRank(e.level) >= levelRank(f.minLevel);
  }
  if (f.group && e.group?.id !== f.group) return false;
  return true;
}

export function matchesQuery(e: JournalEvent, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  if (e.kind === "log") return e.message.toLowerCase().includes(q);
  return e.client.toLowerCase().includes(q) || e.name.toLowerCase().includes(q);
}

export function describeDns(e: DnsEvent, t: (s: string) => string): string {
  return `${e.name} ${describeDnsTail(e, t)}`;
}

export function resolverNote(r: DnsResolverSource | undefined, t: (s: string) => string): string {
  switch (r) {
    case "group":
      return t("via the group's DNS");
    case "fallback_unreachable":
      return t("the group's DNS could not be reached; the common upstream answered");
    case "fallback_timeout":
      return t("the group's DNS did not answer in time; the common upstream answered");
    case "fallback_servfail":
      return t("the group's DNS answered SERVFAIL; the common upstream answered");
    case "fallback_refused":
      return t("the group's DNS refused; the common upstream answered");
    case "fallback_sink":
      return t("the group's DNS answered a sink address; the common upstream answered");
    case "health_skip":
      return t("the group's DNS is resting after failures; the common upstream answered");
    case "cache":
      return t("from the group's DNS cache");
    default:
      return "";
  }
}

export function describeDnsTail(e: DnsEvent, t: (s: string) => string): string {
  const note = resolverNote(e.resolver, t);
  const tail = decisionTail(e, t);
  return note ? `${tail} · ${note}` : tail;
}

function decisionTail(e: DnsEvent, t: (s: string) => string): string {
  const head = `${e.qtype} →`;
  const group = e.group ? `${e.group.name} · ` : "";
  switch (e.decision) {
    case "issued": {
      if (e.fake === undefined) {
        return `${head} ${group}${t("issued, but no address of this family in the answer")}`;
      }
      const reals = e.reals.length ? ` (${e.reals.join(", ")})` : "";
      return `${head} ${group}${t("issued")} ${e.fake}${reals}`;
    }
    case "no-match":
      return `${head} ${t("no group, answered as is")}`;
    case "not-covered":
      return `${head} ${group}${t("this client is not in the group's devices")}`;
    case "pool-refused":
      return `${head} ${group}${t("pool refused, answered")} ${e.fake ?? ""}`;
    case "passed":
      if (e.rcode !== "NOERROR") return `${head} ${group}${t("passed")}, ${e.rcode}`;
      if (e.group && (e.qtype === "HTTPS" || e.qtype === "SVCB"))
        return `${head} ${group}${t("address hints removed")}`;
      return `${head} ${group}${t("passed, no address in the answer")}`;
  }
}

function describeBypassLast(
  e: BypassEvent,
  t: (s: string) => string,
  stamp: (at: number) => string,
): string {
  if (!e.last)
    return t("firc remembers no question from this address (it keeps 30 minutes at most)");
  const at = stamp(e.last.at);
  if (e.last.decision === "issued" && e.last.fake !== undefined) {
    return `${t("firc issued")} ${e.last.fake} ${t("at")} ${at}` + t(", the client did not use it");
  }
  if (e.last.decision === "issued") {
    return `${t("firc issued, but no address of this family")} ${t("at")} ${at}`;
  }
  return `${t("firc answered")} ${e.last.decision} ${t("at")} ${at}`;
}

export function describeBypassTail(
  e: BypassEvent,
  t: (s: string) => string,
  stamp: (at: number) => string,
): string {
  const port = e.port !== undefined ? `:${e.port}` : "";
  const group = e.group ? `${e.group.name} · ` : "";
  const how = e.how === "addr" ? t("by address") : t("by SNI");
  const times = e.repeats > 0 ? ` (×${e.repeats})` : "";
  return `→ ${e.dst}${port}/${e.proto} · ${group}${how} · ${describeBypassLast(e, t, stamp)}${times}`;
}
