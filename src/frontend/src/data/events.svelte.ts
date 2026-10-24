import { fetcher } from "../utils/fetcher";
import { trimHeld } from "./journal-held";

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogEvent = {
  seq: number;
  at: number;
  kind: "log";
  level: LogLevel;
  source: string;
  message: string;
};

export type DnsDecision =
  | "issued"
  | "not-covered"
  | "no-match"
  | "pool-refused"
  | "passed"
  | "blocked";

export type DnsResolverSource =
  | "upstream"
  | "group"
  | "fallback_unreachable"
  | "fallback_timeout"
  | "fallback_servfail"
  | "fallback_refused"
  | "fallback_sink"
  | "health_skip"
  | "cache"
  | "local";

export type DnsEvent = {
  seq: number;
  at: number;
  kind: "dns";
  client: string;
  name: string;
  qtype: string;
  rcode: string;
  decision: DnsDecision;
  resolver?: DnsResolverSource;
  group?: { id: string; name: string };
  fake?: string;
  reals: string[];
};

export type BypassEvent = {
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

export type JournalEvent = LogEvent | DnsEvent | BypassEvent;

type EventsRes = {
  events: JournalEvent[];
  next: number;
  dropped: number;
  boot: string;
};

export const PAGE = 1024;

class Journal {
  events = $state.raw<JournalEvent[]>([]);
  /* The cursor. 0 asks for everything the daemon still holds. */
  cursor = $state(0);
  /* How many events the daemon's ring overwrote before we asked for them. */
  dropped = $state(0);
  /* The daemon run the cursor belongs to; "" before the first answer. */
  boot = $state("");
  seenGroups = $state.raw<{ id: string; name: string }[]>([]);
  failed = $state(false);
}

export const journal = new Journal();

/* One poll at a time: two polls on the same cursor append the same page twice. */
let inflight = false;

export async function pollEvents() {
  if (inflight) return;
  inflight = true;
  let catchingUp = journal.cursor === 0;
  try {
    for (;;) {
      const data = await fetcher.get<EventsRes>(`/system/events?since=${journal.cursor}`, {
        quiet: true,
      });
      journal.failed = false;
      if (journal.boot !== "" && data.boot !== journal.boot) {
        journal.boot = data.boot;
        journal.events = [];
        journal.dropped = 0;
        journal.cursor = 0;
        catchingUp = true;
        continue;
      }
      journal.boot = data.boot;
      if (data.dropped > 0 && !catchingUp) journal.dropped += data.dropped;
      if (data.events.length > 0) {
        journal.cursor = data.next;
        journal.events = trimHeld(journal.events.concat(data.events));
        noteGroups(data.events);
      }
      if (data.events.length < PAGE) return;
    }
  } catch (error) {
    console.error("Failed to fetch the journal:", error);
    journal.failed = true;
  } finally {
    inflight = false;
  }
}

function noteGroups(events: JournalEvent[]) {
  let next: { id: string; name: string }[] | null = null;
  for (const e of events) {
    if (e.kind === "log" || !e.group) continue;
    const list = next ?? journal.seenGroups;
    const at = list.findIndex((g) => g.id === e.group!.id);
    if (at >= 0 && list[at].name === e.group.name) continue;
    next ??= [...journal.seenGroups];
    if (at >= 0) next[at] = { ...e.group };
    else next.push({ ...e.group });
  }
  if (next) journal.seenGroups = next;
}
