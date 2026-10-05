import { array, nullable, object, optional, parse, string } from "valibot";

import { token } from "../../data/auth.svelte";
import { locale, t } from "../../data/locale.svelte";

import { GroupListSchema, syncIdle, type Group, type ListRule, type SyncState } from "../../types";
import { toast } from "../../utils/events";
import { API_BASE, fetcher } from "../../utils/fetcher";
import { readEvents } from "../../utils/sse";

const DEV = Boolean((import.meta as ImportMeta & { env?: { DEV?: boolean } }).env?.DEV);

export type SyncProgress = {
  stage: "fetch" | "parse" | "apply";
  bytes: number;
  total: number;
  lines: number;
};

const megabytes = (bytes: number) =>
  new Intl.NumberFormat(locale.current, {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(bytes / 1e6);

const count = (value: number) => new Intl.NumberFormat(locale.current).format(value);

export function syncProgressLabel(progress: SyncProgress): string {
  if (progress.stage === "parse") {
    return `${t("parsing")} ${count(progress.lines)} ${t("lines")}`;
  }
  if (progress.stage === "apply") {
    return t("applying");
  }
  const arrived = megabytes(progress.bytes);
  return progress.total > 0
    ? `${t("fetching")} ${arrived} / ${megabytes(progress.total)} ${t("MB")}`
    : `${t("fetching")} ${arrived} ${t("MB")}`;
}

export type ListPageState = {
  offset: number;
  matched: number;
  q: string;
  loaded: boolean;
  failed: boolean;
  rules: ListRule[];
};

type ListRuleEdit = { type?: string; enable?: boolean };

export class ListsController {
  #getGroup: (id: string) => Group | undefined;
  #listGroups: () => Group[];
  #isOpen: (id: string) => boolean;
  #query: () => string;

  pageState = $state<Record<string, ListPageState>>({});

  syncProgress = $state<Record<string, SyncProgress>>({});

  syncReopenMs = 1000;

  pageSize = 50;

  pendingEdits = new Map<string, Map<string, ListRuleEdit>>();

  #ruleBaseline = new Map<string, Map<string, { type: string; enable: boolean }>>();

  #ruleRequestSeq = new Map<string, number>();

  #requestedQ = new Map<string, string>();

  #searchSeq = 0;

  #syncFollows = new Map<string, Promise<void>>();

  #syncAborts = new Map<string, AbortController>();

  #followedUrl = new Map<string, string>();

  #stopped = false;

  #acknowledgeListSaved: (id: string) => void;
  #isSaved: (id: string) => boolean;

  constructor(
    getGroup: (id: string) => Group | undefined,
    deps: {
      listGroups: () => Group[];
      isOpen: (id: string) => boolean;
      query: () => string;
      acknowledgeListSaved: (id: string) => void;
      isSaved: (id: string) => boolean;
    },
  ) {
    this.#getGroup = getGroup;
    this.#listGroups = deps.listGroups;
    this.#isOpen = deps.isOpen;
    this.#query = deps.query;
    this.#acknowledgeListSaved = deps.acknowledgeListSaved;
    this.#isSaved = deps.isSaved;
  }

  destroy() {
    this.#stopped = true;
    for (const abort of this.#syncAborts.values()) abort.abort();
    this.#syncAborts.clear();
  }

  get syncBlockingSave(): Group | undefined {
    const candidates = new Set([...this.pendingEdits.keys(), ...Object.keys(this.pageState)]);
    for (const id of candidates) {
      const group = this.#getGroup(id);
      const state = group?.list?.sync?.state;
      if (state !== "queued" && state !== "fetching") continue;
      if (this.ruleEdits(id).length > 0) return group;
    }
    return undefined;
  }

  get hasPendingEdits(): boolean {
    const candidates = new Set([...this.pendingEdits.keys(), ...Object.keys(this.pageState)]);
    for (const id of candidates) {
      if (this.ruleEdits(id).length > 0) return true;
    }
    return false;
  }

  baselineOf(groupId: string, ruleId: string): { type: string; enable: boolean } | undefined {
    return this.#ruleBaseline.get(groupId)?.get(ruleId);
  }

  #normalize(q: string) {
    return q.trim().toLowerCase();
  }

  #bumpRuleRequest(groupId: string, query: string): number {
    const next = (this.#ruleRequestSeq.get(groupId) ?? 0) + 1;
    this.#ruleRequestSeq.set(groupId, next);
    this.#requestedQ.set(groupId, query);
    return next;
  }

  #isLatestRuleRequest(groupId: string, requestId: number): boolean {
    return this.#ruleRequestSeq.get(groupId) === requestId;
  }

  #foldPageIntoPendingEdits(groupId: string) {
    const baseline = this.#ruleBaseline.get(groupId);
    const page = this.pageState[groupId]?.rules;
    if (!baseline || !page) return;

    let pending = this.pendingEdits.get(groupId);
    for (const rule of page) {
      const was = baseline.get(rule.id);
      if (!was) continue;

      const diff: ListRuleEdit = {};
      let changed = false;
      if (rule.type !== was.type) {
        diff.type = rule.type;
        changed = true;
      }
      if (rule.enable !== was.enable) {
        diff.enable = rule.enable;
        changed = true;
      }

      if (changed) {
        if (!pending) {
          pending = new Map();
          this.pendingEdits.set(groupId, pending);
        }
        pending.set(rule.id, diff);
      } else {
        pending?.delete(rule.id);
      }
    }

    if (pending && pending.size === 0) this.pendingEdits.delete(groupId);
  }

  async loadRules(groupId: string, offset: number): Promise<boolean> {
    const group = this.#getGroup(groupId);
    if (!group?.list || !this.#isSaved(groupId)) return true;

    this.#foldPageIntoPendingEdits(groupId);

    const query = this.#normalize(this.#query());
    const qParam = query ? `&q=${encodeURIComponent(query)}` : "";
    const requestId = this.#bumpRuleRequest(groupId, query);

    /* Seeded before the request: else the panel's open-effect sees nothing loaded and sends a second GET. */
    const previous = this.pageState[groupId];
    this.pageState[groupId] = {
      offset: previous?.offset ?? offset,
      matched: previous?.matched ?? group.list.rulesTotal ?? 0,
      q: previous?.q ?? query,
      loaded: true,
      failed: false,
      rules: previous?.rules ?? [],
    };

    let answer: { total: number; matched: number; offset: number; rules: ListRule[] };
    try {
      answer = await fetcher.get<{
        total: number;
        matched: number;
        offset: number;
        rules: ListRule[];
      }>(`/groups/${groupId}/list/rules?offset=${offset}&limit=${this.pageSize}${qParam}`);
    } catch (error) {
      console.error(error);
      if (this.#isLatestRuleRequest(groupId, requestId)) {
        const seeded = this.pageState[groupId];
        /* failed: true stops the open-effect retrying this failure forever. */
        this.pageState[groupId] = { ...seeded, loaded: false, failed: true };
      }
      return false;
    }

    if (!this.#isLatestRuleRequest(groupId, requestId)) return true;

    const target = this.#getGroup(groupId);
    if (!target?.list) return true;

    const page = answer.rules ?? [];

    let baseline = this.#ruleBaseline.get(groupId);
    if (!baseline) {
      baseline = new Map();
      this.#ruleBaseline.set(groupId, baseline);
    }
    for (const rule of page) {
      baseline.set(rule.id, { type: rule.type, enable: rule.enable });
    }

    target.list.rulesTotal = answer.total;

    const pending = this.pendingEdits.get(groupId);
    if (pending) {
      for (const rule of page) {
        const edit = pending.get(rule.id);
        if (!edit) continue;
        if (edit.type !== undefined) rule.type = edit.type;
        if (edit.enable !== undefined) rule.enable = edit.enable;
      }
    }

    this.pageState[groupId] = {
      offset: answer.offset,
      matched: answer.matched,
      q: query,
      loaded: true,
      failed: false,
      rules: page,
    };
    return true;
  }

  async countMatches(groupId: string): Promise<boolean> {
    if (!this.#getGroup(groupId)?.list) return true;

    const query = this.#normalize(this.#query());
    const qParam = query ? `&q=${encodeURIComponent(query)}` : "";
    const requestId = this.#bumpRuleRequest(groupId, query);

    let answer: { total: number; matched: number; offset: number; rules: ListRule[] };
    try {
      answer = await fetcher.get<{
        total: number;
        matched: number;
        offset: number;
        rules: ListRule[];
      }>(`/groups/${groupId}/list/rules?offset=0&limit=1${qParam}`);
    } catch (error) {
      console.error(error);
      return false;
    }

    if (!this.#isLatestRuleRequest(groupId, requestId)) return true;

    const existing = this.pageState[groupId];
    this.pageState[groupId] = {
      offset: existing?.offset ?? 0,
      q: query,
      loaded: existing?.loaded ?? false,
      failed: false,
      matched: answer.matched,
      rules: existing?.rules ?? [],
    };
    return true;
  }

  #pageIsStale(groupId: string, query: string): boolean {
    if (!(this.#isOpen(groupId) || this.pageState[groupId]?.loaded)) return false;
    /* #requestedQ, not pageState.q: the latter lags behind a request still in flight. */
    return (this.#requestedQ.get(groupId) ?? "") !== query;
  }

  async searchLists(): Promise<Set<string>> {
    const query = this.#normalize(this.#query());
    const run = ++this.#searchSeq;
    const groups = this.#listGroups();

    const matched = new Set<string>();

    if (!query) {
      const reloads: Promise<unknown>[] = [];
      for (const group of groups) {
        const id = group.id;
        if (!this.#pageIsStale(id, query)) continue;
        if (this.#isOpen(id)) {
          reloads.push(this.loadRules(id, 0));
          continue;
        }
        delete this.pageState[id];
      }
      await Promise.all(reloads);
      return matched;
    }

    const unanswered = new Set<string>();
    const requests: Promise<unknown>[] = [];
    const ask = (id: string, answered: Promise<boolean>) => {
      requests.push(
        answered.then((ok) => {
          if (!ok) unanswered.add(id);
        }),
      );
    };

    for (const group of groups) {
      const id = group.id;
      const isOpen = this.#isOpen(id);
      const hasPage = Boolean(this.pageState[id]?.loaded);

      if (isOpen) {
        if (this.#pageIsStale(id, query)) ask(id, this.loadRules(id, 0));
        continue;
      }

      if (hasPage) {
        if (!this.#pageIsStale(id, query)) continue;
        delete this.pageState[id];
        ask(id, this.countMatches(id));
        continue;
      }

      ask(id, this.countMatches(id));
    }

    await Promise.all(requests);
    if (run !== this.#searchSeq) return matched;

    for (const group of groups) {
      if (unanswered.has(group.id)) {
        matched.add(group.id);
        continue;
      }
      const state = this.pageState[group.id];
      if (state && state.q === query && state.matched > 0) matched.add(group.id);
    }

    if (unanswered.size > 0) {
      const first = groups.find((group) => unanswered.has(group.id));
      if (first) toast.error(`${t("Search failed for")} ${first.name || first.list?.url || ""}`);
    }

    return matched;
  }

  ruleEdits(groupId: string): { id: string; type?: string; enable?: boolean }[] {
    const merged = new Map<string, ListRuleEdit>();
    const pending = this.pendingEdits.get(groupId);
    if (pending) {
      for (const [id, edit] of pending) merged.set(id, { ...edit });
    }

    const baseline = this.#ruleBaseline.get(groupId);
    const page = this.pageState[groupId]?.rules ?? [];
    if (baseline) {
      for (const rule of page) {
        const was = baseline.get(rule.id);
        if (!was) continue;
        const edit: ListRuleEdit = {};
        let changed = false;
        if (rule.type !== was.type) {
          edit.type = rule.type;
          changed = true;
        }
        if (rule.enable !== was.enable) {
          edit.enable = rule.enable;
          changed = true;
        }
        if (changed) merged.set(rule.id, edit);
        else merged.delete(rule.id);
      }
    }

    return Array.from(merged.entries()).map(([id, edit]) => ({ id, ...edit }));
  }

  acknowledgeAllSaved() {
    this.pendingEdits.clear();
    for (const id of Object.keys(this.pageState)) {
      const page = this.pageState[id].rules;
      const baseline = new Map<string, { type: string; enable: boolean }>();
      for (const rule of page) baseline.set(rule.id, { type: rule.type, enable: rule.enable });
      this.#ruleBaseline.set(id, baseline);
    }
  }

  async requestSync(groupId: string, url?: string): Promise<void> {
    const group = this.#getGroup(groupId);
    if (!group?.list) return;

    const target = url ?? group.list.url;

    if (this.ruleEdits(groupId).length > 0) {
      if (!confirm(t("Unsaved rule edits will be lost by the sync. Continue?"))) return;
    }

    try {
      const accepted = await fetcher.post<{ list?: { url?: string; sync?: SyncState } }>(
        `/groups/${groupId}/list/sync`,
        { url: target },
      );
      const live = this.#getGroup(groupId);
      if (live?.list) {
        live.list.url = accepted.list?.url ?? target;
        live.list.sync = accepted.list?.sync ?? { state: "queued", error: "", lastCheck: 0 };
        this.#acknowledgeListSaved(groupId);
      }
    } catch (error) {
      console.error(error);
      toast.error(t("Failed to sync"));
      return;
    }

    await this.followSync(groupId);
  }

  followSync(groupId: string): Promise<void> {
    if (this.#stopped) {
      if (DEV) {
        console.warn(`followSync(${groupId}) after destroy(): this controller is single-use`);
      }
      return Promise.resolve();
    }

    const pending = this.#syncFollows.get(groupId);
    if (pending) return pending;

    const abort = new AbortController();
    this.#syncAborts.set(groupId, abort);
    this.#followedUrl.set(groupId, this.#getGroup(groupId)?.list?.url ?? "");
    /* By identity: a replaced follow ends after its successor and must not drop the successor's entries. */
    const started: Promise<void> = this.#runSyncStream(groupId, abort).finally(() => {
      if (this.#syncFollows.get(groupId) === started) this.#syncFollows.delete(groupId);
      if (this.#syncAborts.get(groupId) === abort) this.#syncAborts.delete(groupId);
    });
    this.#syncFollows.set(groupId, started);
    return started;
  }

  #stopFollowingSync(groupId: string) {
    this.#syncAborts.get(groupId)?.abort();
    this.#syncAborts.delete(groupId);
    this.#syncFollows.delete(groupId);
    this.#followedUrl.delete(groupId);
    delete this.syncProgress[groupId];
  }

  adoptQueuedSync(groupId: string, record: any, repointed: boolean): boolean {
    const url = record?.list?.url;
    if (this.#syncFollows.has(groupId) && this.#followedUrl.get(groupId) === url) return false;
    const live = this.#getGroup(groupId);
    if (!live?.list || typeof url !== "string") return false;

    if (!repointed) {
      live.list.sync = record.list.sync ?? syncIdle();
      void this.followSync(groupId);
      return false;
    }

    this.#stopFollowingSync(groupId);
    live.list.url = url;
    live.list.rulesTotal = record.list.rulesTotal ?? 0;
    live.list.lastUpdate = record.list.lastUpdate ?? 0;
    live.list.sync = record.list.sync ?? syncIdle();
    delete this.pageState[groupId];
    this.pendingEdits.delete(groupId);
    this.#ruleBaseline.set(groupId, new Map());
    void this.followSync(groupId);
    return true;
  }

  async #runSyncStream(groupId: string, abort: AbortController) {
    for (let attempt = 0; !this.#stopped && !abort.signal.aborted; attempt++) {
      let ended = true;
      try {
        ended = await this.#readSyncStream(groupId, abort);
      } catch (error) {
        if (!this.#stopped && !abort.signal.aborted) console.error(error);
        ended = false;
      }
      if (ended || this.#stopped || abort.signal.aborted) return;
      if (attempt > 0) {
        delete this.syncProgress[groupId];
        toast.error(t("Sync connection lost"));
        await this.#rereadSyncState(groupId);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, this.syncReopenMs));
    }
  }

  async #readSyncStream(groupId: string, abort: AbortController): Promise<boolean> {
    if (this.#stopped || abort.signal.aborted) return true;

    const headers: Record<string, string> = {};
    if (token.current) headers.Authorization = `Bearer ${token.current}`;

    return await this.#readSyncEvents(groupId, headers, abort.signal);
  }

  async #readSyncEvents(
    groupId: string,
    headers: Record<string, string>,
    signal: AbortSignal,
  ): Promise<boolean> {
    const response = await fetch(`${API_BASE}/groups/${groupId}/list/sync/events`, {
      headers,
      signal,
    });

    if (response.status === 401) {
      token.reset();
      delete this.syncProgress[groupId];
      return true;
    }
    if (!response.ok) {
      console.error(`sync stream for ${groupId}: HTTP ${response.status}`);
      delete this.syncProgress[groupId];
      return true;
    }

    for await (const event of readEvents(response)) {
      let payload: any;
      try {
        payload = JSON.parse(event.data);
      } catch (error) {
        console.error(error);
        continue;
      }

      if (event.event === "progress") {
        this.syncProgress[groupId] = {
          stage: payload?.stage === "parse" || payload?.stage === "apply" ? payload.stage : "fetch",
          bytes: payload?.bytes ?? 0,
          total: payload?.total ?? 0,
          lines: payload?.lines ?? 0,
        };
        continue;
      }

      if (event.event === "done") {
        delete this.syncProgress[groupId];
        await this.#applySyncDone(groupId, payload);
        return true;
      }

      if (event.event === "error") {
        delete this.syncProgress[groupId];
        this.#applySyncError(groupId, String(payload?.error ?? ""));
        return true;
      }
    }

    return false;
  }

  async #applySyncDone(groupId: string, record: any) {
    await this.#applyRecord(groupId, record);
    if (this.#getGroup(groupId)) toast.success(t("Synced"));
  }

  async #fetchGroups() {
    const answer = await fetcher.get<{ groups: unknown[] }>("/groups");
    return parse(
      array(object({ id: string(), list: optional(nullable(GroupListSchema)) })),
      answer?.groups ?? [],
    );
  }

  async #rereadSyncState(groupId: string) {
    const fetched = await this.#fetchGroups().catch((error) => {
      console.error(error);
      return null;
    });
    if (!fetched) return;

    const record = fetched.find((g) => g.id === groupId);
    if (!record?.list) return;

    const state = record.list.sync?.state;
    const live = this.#getGroup(groupId);
    if (!live?.list) return;

    if (state === "queued" || state === "fetching") {
      live.list.sync = record.list.sync;
      return;
    }

    await this.#applyRecord(groupId, record);
  }

  async #applyRecord(groupId: string, record: any) {
    const live = this.#getGroup(groupId);
    if (!live?.list) return;

    live.list.url = record?.list?.url ?? live.list.url;
    live.list.rulesTotal = record?.list?.rulesTotal ?? 0;
    live.list.lastUpdate = record?.list?.lastUpdate ?? live.list.lastUpdate;
    live.list.sync = record?.list?.sync ?? syncIdle();

    delete this.pageState[groupId];
    this.pendingEdits.delete(groupId);
    this.#ruleBaseline.set(groupId, new Map());

    if (this.#isOpen(groupId)) {
      await this.loadRules(groupId, 0);
    }
  }

  #applySyncError(groupId: string, message: string) {
    const live = this.#getGroup(groupId);
    if (
      message === "list url changed" &&
      live?.list &&
      live.list.url !== this.#followedUrl.get(groupId)
    ) {
      live.list.sync = { state: "idle", error: "", lastCheck: live.list.sync?.lastCheck ?? 0 };
      return;
    }
    if (live?.list) {
      live.list.sync = {
        state: "error",
        error: message,
        lastCheck: live.list.sync?.lastCheck ?? 0,
      };
    }
    toast.error(`${t("Sync failed")}: ${message}`);
  }

  forget(groupId: string) {
    this.#stopFollowingSync(groupId);
    delete this.pageState[groupId];
    this.pendingEdits.delete(groupId);
    this.#ruleBaseline.delete(groupId);
    this.#ruleRequestSeq.delete(groupId);
    this.#requestedQ.delete(groupId);
  }
}
