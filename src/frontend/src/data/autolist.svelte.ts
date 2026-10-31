import type { AutolistProbeResult, AutolistRes, Group, Rule } from "../types";
import { fetcher } from "../utils/fetcher";

export const AUTOLIST_REFRESH_MS = 5000;
export const AUTOLIST_BUSY_MS = 2000;
export const PROBES_PER_HOUR = 30;

export const autolistState = $state({
  data: null as AutolistRes | null,
  failed: false,
  asked: {} as Record<string, number>,
});

let generation = 0;

function take(data: AutolistRes) {
  generation++;
  autolistState.data = data;
  autolistState.failed = false;
  for (const host of Object.keys(autolistState.asked)) {
    if ((latestResult(data.probes.results, host)?.at ?? 0) > autolistState.asked[host]) {
      delete autolistState.asked[host];
    }
  }
}

export function whyClass(why: string): string {
  if (why === "no-answer" || why === "no-connect") return "drop";
  if (why === "reset") return "rst";
  if (why === "freeze") return "frz";
  return "off";
}

export function whyLabel(why: string, bytes: number, t: (s: string) => string): string {
  if (why === "no-answer") return t("no answer to ClientHello");
  if (why === "reset") return t("reset before the server answered");
  if (why === "no-connect") return t("no connection (SYN unanswered)");
  if (why === "freeze") {
    const kb = Math.round(bytes / 1024);
    return kb > 0 ? t("freeze at {n} KB").replace("{n}", String(kb)) : t("freeze");
  }
  return why;
}

export function latestResult(
  results: AutolistProbeResult[],
  host: string,
): AutolistProbeResult | null {
  let best: AutolistProbeResult | null = null;
  for (const r of results) {
    if (r.host === host && (!best || r.at > best.at)) best = r;
  }
  return best;
}

export function ruleOf(groups: Group[], groupId: string | null, domain: string): Rule | null {
  const group = groups.find((g) => g.id === groupId);
  return group?.rules.find((r) => r.rule === domain) ?? null;
}

export const autolist = {
  get data() {
    return autolistState.data;
  },
  get failed() {
    return autolistState.failed;
  },
  get asking() {
    return Object.keys(autolistState.asked).length > 0;
  },
  get busy() {
    return autolistState.data?.probes.running != null || this.asking;
  },
  async ensure(): Promise<void> {
    if (autolistState.data) return;
    await this.poll();
  },
  async poll(): Promise<void> {
    const gen = generation;
    try {
      const data = await fetcher.get<AutolistRes>("/system/autolist", { quiet: true });
      if (gen !== generation) return;
      take(data);
    } catch (error) {
      if (gen !== generation) return;
      console.error("Failed to read the automatic list:", error);
      autolistState.failed = true;
    }
  },
  async add(domain: string): Promise<void> {
    take(
      await fetcher.post<AutolistRes>(
        `/system/autolist/candidates/${encodeURIComponent(domain)}/add`,
        undefined,
      ),
    );
  },
  async dismiss(domain: string): Promise<void> {
    take(
      await fetcher.post<AutolistRes>(
        `/system/autolist/candidates/${encodeURIComponent(domain)}/dismiss`,
        undefined,
      ),
    );
  },
  async probe(host: string): Promise<void> {
    take(await fetcher.post<AutolistRes>("/system/autolist/probe", { host }));
  },
  async ask(host: string): Promise<void> {
    autolistState.asked[host] = this.resultFor(host)?.at ?? 0;
    try {
      await this.probe(host);
    } catch {
      delete autolistState.asked[host];
    }
  },
  pending(host: string): boolean {
    return (
      autolistState.data?.probes.running === host ||
      (host in autolistState.asked && (this.resultFor(host)?.at ?? 0) <= autolistState.asked[host])
    );
  },
  resultFor(host: string): AutolistProbeResult | null {
    return latestResult(autolistState.data?.probes.results ?? [], host);
  },
};
