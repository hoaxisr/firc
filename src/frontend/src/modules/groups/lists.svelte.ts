import { array, object, optional, parse, string } from "valibot";

import { token } from "../../data/auth.svelte";
import { locale, t } from "../../data/locale.svelte";
import { ask } from "../../utils/confirm.svelte";

import {
  GroupListSchema,
  syncIdle,
  SyncStateSchema,
  type Group,
  type GroupList,
  type ListRule,
  type SyncState,
} from "../../types";
import { toast } from "../../utils/events";
import { API_BASE, fetcher } from "../../utils/fetcher";
import { readEvents } from "../../utils/sse";

const DEV = Boolean((import.meta as ImportMeta & { env?: { DEV?: boolean } }).env?.DEV);

export type ListKey = `${string}/${string}`;

export const listKey = (groupId: string, listId: string): ListKey => `${groupId}/${listId}`;

const groupOfKey = (key: string) => key.slice(0, key.indexOf("/"));
const listOfKey = (key: string) => key.slice(key.indexOf("/") + 1);

const syncOf = (raw: unknown): SyncState => parse(SyncStateSchema, raw ?? {});

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

type Baseline = Map<string, { type: string; enable: boolean }>;

export type RuleEdit = { id: string; type?: string; enable?: boolean };

type PagePayload = { total: number; matched: number; offset: number; rules: ListRule[] };

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

  #ruleBaseline = new Map<string, Baseline>();

  #ruleRequestSeq = new Map<string, number>();

  #requestedQ = new Map<string, string>();

  #searchSeq = 0;

  #syncFollows = new Map<string, Promise<void>>();

  #syncAborts = new Map<string, AbortController>();

  #followedUrl = new Map<string, string>();

  #stopped = false;

  #acknowledgeListSaved: (groupId: string, listId: string) => void;
  #isSaved: (groupId: string, listId: string) => boolean;
  #pageLoaded: () => void;

  constructor(
    getGroup: (id: string) => Group | undefined,
    deps: {
      listGroups: () => Group[];
      isOpen: (id: string) => boolean;
      query: () => string;
      acknowledgeListSaved: (groupId: string, listId: string) => void;
      isSaved: (groupId: string, listId: string) => boolean;
      pageLoaded: () => void;
    },
  ) {
    this.#getGroup = getGroup;
    this.#listGroups = deps.listGroups;
    this.#isOpen = deps.isOpen;
    this.#query = deps.query;
    this.#acknowledgeListSaved = deps.acknowledgeListSaved;
    this.#isSaved = deps.isSaved;
    this.#pageLoaded = deps.pageLoaded;
  }

  destroy() {
    this.#stopped = true;
    for (const abort of this.#syncAborts.values()) abort.abort();
    this.#syncAborts.clear();
  }

  #list(groupId: string, listId: string): GroupList | undefined {
    return this.#getGroup(groupId)?.lists?.find((list) => list.id === listId);
  }

  #keysOf(groupId: string): string[] {
    const prefix = `${groupId}/`;
    const keys = new Set<string>();
    for (const key of [
      ...Object.keys(this.pageState),
      ...this.pendingEdits.keys(),
      ...this.#ruleBaseline.keys(),
      ...this.#ruleRequestSeq.keys(),
      ...this.#requestedQ.keys(),
      ...Object.keys(this.syncProgress),
      ...this.#followedUrl.keys(),
    ]) {
      if (key.startsWith(prefix)) keys.add(key);
    }
    return [...keys];
  }

  #dropKey(key: string) {
    delete this.pageState[key];
    delete this.syncProgress[key];
    this.pendingEdits.delete(key);
    this.#ruleBaseline.delete(key);
    this.#ruleRequestSeq.delete(key);
    this.#requestedQ.delete(key);
    this.#followedUrl.delete(key);
  }

  #clearProgress(groupId: string) {
    const prefix = `${groupId}/`;
    for (const key of Object.keys(this.syncProgress)) {
      if (key.startsWith(prefix)) delete this.syncProgress[key];
    }
  }

  #editedKeys(): Set<string> {
    return new Set([...this.pendingEdits.keys(), ...Object.keys(this.pageState)]);
  }

  get syncBlockingSave(): Group | undefined {
    for (const key of this.#editedKeys()) {
      const groupId = groupOfKey(key);
      const listId = listOfKey(key);
      const state = this.#list(groupId, listId)?.sync?.state;
      if (state !== "queued" && state !== "fetching") continue;
      if (this.ruleEdits(groupId, listId).length > 0) return this.#getGroup(groupId);
    }
    return undefined;
  }

  get hasPendingEdits(): boolean {
    for (const key of this.#editedKeys()) {
      if (this.ruleEdits(groupOfKey(key), listOfKey(key)).length > 0) return true;
    }
    return false;
  }

  groupRuleEdits(groupId: string): { listId: string; rules: RuleEdit[] }[] {
    const out: { listId: string; rules: RuleEdit[] }[] = [];
    for (const list of this.#getGroup(groupId)?.lists ?? []) {
      const rules = this.ruleEdits(groupId, list.id);
      if (rules.length > 0) out.push({ listId: list.id, rules });
    }
    return out;
  }

  baselineOf(
    groupId: string,
    listId: string,
    ruleId: string,
  ): { type: string; enable: boolean } | undefined {
    return this.#ruleBaseline.get(listKey(groupId, listId))?.get(ruleId);
  }

  #normalize(q: string) {
    return q.trim().toLowerCase();
  }

  #bumpRuleRequest(key: string, query: string): number {
    const next = (this.#ruleRequestSeq.get(key) ?? 0) + 1;
    this.#ruleRequestSeq.set(key, next);
    this.#requestedQ.set(key, query);
    return next;
  }

  #isLatestRuleRequest(key: string, requestId: number): boolean {
    return this.#ruleRequestSeq.get(key) === requestId;
  }

  #foldPageIntoPendingEdits(key: string) {
    const baseline = this.#ruleBaseline.get(key);
    const page = this.pageState[key]?.rules;
    if (!baseline || !page) return;

    let pending = this.pendingEdits.get(key);
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
          this.pendingEdits.set(key, pending);
        }
        pending.set(rule.id, diff);
      } else {
        pending?.delete(rule.id);
      }
    }

    if (pending && pending.size === 0) this.pendingEdits.delete(key);
  }

  async loadRules(groupId: string, listId: string, offset: number): Promise<boolean> {
    const list = this.#list(groupId, listId);
    if (!list || !this.#isSaved(groupId, listId)) return true;
    const key = listKey(groupId, listId);

    this.#foldPageIntoPendingEdits(key);

    const query = this.#normalize(this.#query());
    const requestId = this.#bumpRuleRequest(key, query);

    /* Seeded before the request: else the panel's open-effect sees nothing loaded and sends a second GET. */
    const previous = this.pageState[key];
    this.pageState[key] = {
      offset: previous?.offset ?? offset,
      matched: previous?.matched ?? list.rulesTotal ?? 0,
      q: previous?.q ?? query,
      loaded: true,
      failed: false,
      rules: previous?.rules ?? [],
    };

    let answer: PagePayload;
    try {
      answer = await this.rulesPage(groupId, listId, offset, query);
    } catch (error) {
      console.error(error);
      if (this.#isLatestRuleRequest(key, requestId)) {
        const seeded = this.pageState[key];
        /* failed: true stops the open-effect retrying this failure forever. */
        this.pageState[key] = { ...seeded, loaded: false, failed: true };
      }
      return false;
    }

    if (!this.#isLatestRuleRequest(key, requestId)) return true;

    const target = this.#list(groupId, listId);
    if (!target) return true;

    const page = answer.rules ?? [];

    let baseline = this.#ruleBaseline.get(key);
    if (!baseline) {
      baseline = new Map();
      this.#ruleBaseline.set(key, baseline);
    }
    for (const rule of page) {
      baseline.set(rule.id, { type: rule.type, enable: rule.enable });
    }

    target.rulesTotal = answer.total;

    const pending = this.pendingEdits.get(key);
    if (pending) {
      for (const rule of page) {
        const edit = pending.get(rule.id);
        if (!edit) continue;
        if (edit.type !== undefined) rule.type = edit.type;
        if (edit.enable !== undefined) rule.enable = edit.enable;
      }
    }

    this.pageState[key] = {
      offset: answer.offset,
      matched: answer.matched,
      q: query,
      loaded: true,
      failed: false,
      rules: page,
    };
    this.#pageLoaded();
    return true;
  }

  async rulesPage(
    groupId: string,
    listId: string,
    offset: number,
    q: string,
  ): Promise<PagePayload> {
    const qParam = q ? `&q=${encodeURIComponent(q)}` : "";
    return await fetcher.get<PagePayload>(
      `/groups/${groupId}/lists/${listId}/rules?offset=${offset}&limit=${this.pageSize}${qParam}`,
    );
  }

  async countMatches(groupId: string, listId: string): Promise<boolean> {
    if (!this.#list(groupId, listId)) return true;
    const key = listKey(groupId, listId);

    const query = this.#normalize(this.#query());
    const requestId = this.#bumpRuleRequest(key, query);

    let answer: PagePayload;
    try {
      const qParam = query ? `&q=${encodeURIComponent(query)}` : "";
      answer = await fetcher.get<PagePayload>(
        `/groups/${groupId}/lists/${listId}/rules?offset=0&limit=1${qParam}`,
      );
    } catch (error) {
      console.error(error);
      return false;
    }

    if (!this.#isLatestRuleRequest(key, requestId)) return true;

    const existing = this.pageState[key];
    this.pageState[key] = {
      offset: existing?.offset ?? 0,
      q: query,
      loaded: existing?.loaded ?? false,
      failed: false,
      matched: answer.matched,
      rules: existing?.rules ?? [],
    };
    return true;
  }

  #pageIsStale(groupId: string, key: string, query: string): boolean {
    if (!(this.#isOpen(groupId) || this.pageState[key]?.loaded)) return false;
    /* #requestedQ, not pageState.q: the latter lags behind a request still in flight. */
    return (this.#requestedQ.get(key) ?? "") !== query;
  }

  async searchLists(): Promise<Set<string>> {
    const query = this.#normalize(this.#query());
    const run = ++this.#searchSeq;
    const groups = this.#listGroups();

    const matched = new Set<string>();

    if (!query) {
      const reloads: Promise<unknown>[] = [];
      for (const group of groups) {
        for (const list of group.lists) {
          const key = listKey(group.id, list.id);
          if (!this.#pageIsStale(group.id, key, query)) continue;
          if (this.#isOpen(group.id)) {
            reloads.push(this.loadRules(group.id, list.id, 0));
            continue;
          }
          delete this.pageState[key];
        }
      }
      await Promise.all(reloads);
      return matched;
    }

    const unanswered = new Set<string>();
    const requests: Promise<unknown>[] = [];
    const ask = (groupId: string, answered: Promise<boolean>) => {
      requests.push(
        answered.then((ok) => {
          if (!ok) unanswered.add(groupId);
        }),
      );
    };

    for (const group of groups) {
      const isOpen = this.#isOpen(group.id);
      for (const list of group.lists) {
        const key = listKey(group.id, list.id);
        const hasPage = Boolean(this.pageState[key]?.loaded);

        if (isOpen) {
          if (this.#pageIsStale(group.id, key, query))
            ask(group.id, this.loadRules(group.id, list.id, 0));
          continue;
        }

        if (hasPage) {
          if (!this.#pageIsStale(group.id, key, query)) continue;
          delete this.pageState[key];
          ask(group.id, this.countMatches(group.id, list.id));
          continue;
        }

        ask(group.id, this.countMatches(group.id, list.id));
      }
    }

    await Promise.all(requests);
    if (run !== this.#searchSeq) return matched;

    for (const group of groups) {
      if (unanswered.has(group.id)) {
        matched.add(group.id);
        continue;
      }
      for (const list of group.lists) {
        const state = this.pageState[listKey(group.id, list.id)];
        if (state && state.q === query && state.matched > 0) {
          matched.add(group.id);
          break;
        }
      }
    }

    if (unanswered.size > 0) {
      const first = groups.find((group) => unanswered.has(group.id));
      if (first)
        toast.error(`${t("Search failed for")} ${first.name || first.lists[0]?.url || ""}`);
    }

    return matched;
  }

  ruleEdits(groupId: string, listId: string): RuleEdit[] {
    const key = listKey(groupId, listId);
    const merged = new Map<string, ListRuleEdit>();
    const pending = this.pendingEdits.get(key);
    if (pending) {
      for (const [id, edit] of pending) merged.set(id, { ...edit });
    }

    const baseline = this.#ruleBaseline.get(key);
    const page = this.pageState[key]?.rules ?? [];
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
    for (const key of Object.keys(this.pageState)) {
      const page = this.pageState[key].rules;
      const baseline: Baseline = new Map();
      for (const rule of page) baseline.set(rule.id, { type: rule.type, enable: rule.enable });
      this.#ruleBaseline.set(key, baseline);
    }
  }

  async #confirmDiscard(groupId: string, listId?: string): Promise<boolean> {
    const edited =
      listId !== undefined
        ? this.ruleEdits(groupId, listId).length > 0
        : this.groupRuleEdits(groupId).length > 0;
    if (!edited) return true;
    return await ask({
      tone: "warn",
      title: t("Sync the list?"),
      message: t("Unsaved rule edits in this group will be lost."),
      confirm: t("Sync"),
    });
  }

  async syncList(groupId: string, listId: string, url?: string): Promise<void> {
    const list = this.#list(groupId, listId);
    if (!list) return;

    const target = url ?? list.url;

    if (!(await this.#confirmDiscard(groupId, listId))) return;

    try {
      const accepted = await fetcher.post<{ lists?: GroupList[] }>(
        `/groups/${groupId}/lists/${listId}/sync`,
        { url: target },
      );
      const live = this.#list(groupId, listId);
      if (live) {
        const record = accepted?.lists?.find((item) => item.id === listId);
        live.url = record?.url ?? target;
        live.sync = record?.sync
          ? syncOf(record.sync)
          : { state: "queued", error: "", lastCheck: 0, cachedAt: 0 };
        this.#acknowledgeListSaved(groupId, listId);
      }
    } catch (error) {
      console.error(error);
      toast.error(t("Failed to sync"));
      return;
    }

    await this.followSync(groupId);
  }

  async syncGroup(groupId: string): Promise<void> {
    const group = this.#getGroup(groupId);
    if (!group?.lists?.length) return;

    if (!(await this.#confirmDiscard(groupId))) return;

    try {
      const accepted = await fetcher.post<{ lists?: GroupList[] }>(`/groups/${groupId}/sync`, {});
      for (const record of accepted?.lists ?? []) {
        const state = record.sync?.state;
        if (state !== "queued" && state !== "fetching") continue;
        const live = this.#list(groupId, record.id);
        if (live) live.sync = syncOf(record.sync);
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
    for (const list of this.#getGroup(groupId)?.lists ?? []) {
      this.#followedUrl.set(listKey(groupId, list.id), list.url ?? "");
    }
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
    const prefix = `${groupId}/`;
    for (const key of [...this.#followedUrl.keys()]) {
      if (key.startsWith(prefix)) this.#followedUrl.delete(key);
    }
    this.#clearProgress(groupId);
  }

  adoptQueuedSync(groupId: string, record: any, repointed: boolean): boolean {
    const listId = record?.id;
    const url = record?.url;
    if (typeof listId !== "string" || typeof url !== "string") return false;
    const key = listKey(groupId, listId);
    const known = this.#followedUrl.has(key);
    if (this.#syncFollows.has(groupId) && this.#followedUrl.get(key) === url) return false;
    const live = this.#list(groupId, listId);
    if (!live) return false;

    if (!repointed && known) {
      live.sync = record.sync ? syncOf(record.sync) : syncIdle();
      void this.followSync(groupId);
      return false;
    }

    this.#stopFollowingSync(groupId);
    live.url = url;
    live.sync = record.sync ? syncOf(record.sync) : syncIdle();
    if (repointed) {
      live.rulesTotal = record.rulesTotal ?? 0;
      live.lastUpdate = record.lastUpdate ?? 0;
      delete this.pageState[key];
      this.pendingEdits.delete(key);
      this.#ruleBaseline.set(key, new Map());
    }
    void this.followSync(groupId);
    return repointed;
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
        this.#clearProgress(groupId);
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
    if (token.current) headers["X-Firc-Token"] = token.current;

    return await this.#readSyncEvents(groupId, headers, abort.signal);
  }

  async #readSyncEvents(
    groupId: string,
    headers: Record<string, string>,
    signal: AbortSignal,
  ): Promise<boolean> {
    const response = await fetch(`${API_BASE}/groups/${groupId}/sync/events`, {
      headers,
      signal,
    });

    if (response.status === 401) {
      token.reset();
      this.#clearProgress(groupId);
      return true;
    }
    if (!response.ok) {
      console.error(`sync stream for ${groupId}: HTTP ${response.status}`);
      this.#clearProgress(groupId);
      return true;
    }

    for await (const event of readEvents(response)) {
      if (event.event !== "progress" && event.event !== "done") continue;

      let payload: any;
      try {
        payload = JSON.parse(event.data);
      } catch (error) {
        console.error(error);
        continue;
      }

      await this.#applyListEvent(groupId, String(payload?.listId ?? ""), payload?.list);

      if (event.event === "done") {
        this.#clearProgress(groupId);
        if (this.#anyRunning(groupId)) await this.#rereadSyncState(groupId);
        return true;
      }
    }

    return false;
  }

  async #applyListEvent(groupId: string, listId: string, record: any) {
    const live = this.#list(groupId, listId);
    if (!live) return;
    const key = listKey(groupId, listId);
    const state = record?.sync?.state;

    if (state === "queued" || state === "fetching") {
      live.sync = syncOf(record.sync);
      const progress = record.sync?.progress;
      if (progress) {
        this.syncProgress[key] = {
          stage:
            progress.stage === "parse" || progress.stage === "apply" ? progress.stage : "fetch",
          bytes: progress.bytes ?? 0,
          total: progress.total ?? 0,
          lines: progress.lines ?? 0,
        };
      } else {
        delete this.syncProgress[key];
      }
      return;
    }

    delete this.syncProgress[key];
    const wasRunning = live.sync?.state === "queued" || live.sync?.state === "fetching";

    if (state === "error") {
      const message = String(record.sync?.error ?? "");
      if (message === "list url changed" && live.url !== this.#followedUrl.get(key)) {
        live.sync = {
          state: "idle",
          error: "",
          lastCheck: live.sync?.lastCheck ?? 0,
          cachedAt: live.sync?.cachedAt ?? 0,
        };
        return;
      }
      live.sync = {
        state: "error",
        error: message,
        lastCheck: record.sync?.lastCheck ?? live.sync?.lastCheck ?? 0,
        cachedAt: record.sync?.cachedAt ?? live.sync?.cachedAt ?? 0,
      };
      if (wasRunning) toast.error(`${t("Sync failed")}: ${message}`);
      return;
    }

    if (!wasRunning) return;
    await this.#applyRecord(groupId, listId, record);
    if (this.#list(groupId, listId)) toast.success(t("Synced"));
  }

  #anyRunning(groupId: string): boolean {
    return (this.#getGroup(groupId)?.lists ?? []).some(
      (list) => list.sync?.state === "queued" || list.sync?.state === "fetching",
    );
  }

  async #fetchGroups() {
    const answer = await fetcher.get<{ groups: unknown[] }>("/groups");
    return parse(
      array(object({ id: string(), lists: optional(array(GroupListSchema)) })),
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
    if (!record?.lists) return;

    for (const item of record.lists) {
      const live = this.#list(groupId, item.id);
      if (!live || !(live.sync?.state === "queued" || live.sync?.state === "fetching")) continue;

      const state = item.sync?.state;
      if (state === "queued" || state === "fetching") {
        live.sync = item.sync;
        continue;
      }

      await this.#applyRecord(groupId, item.id, item);
    }
  }

  async #applyRecord(groupId: string, listId: string, record: any) {
    const live = this.#list(groupId, listId);
    if (!live) return;
    const key = listKey(groupId, listId);

    live.url = record?.url ?? live.url;
    live.rulesTotal = record?.rulesTotal ?? 0;
    live.lastUpdate = record?.lastUpdate ?? live.lastUpdate;
    live.sync = record?.sync ? syncOf(record.sync) : syncIdle();

    delete this.pageState[key];
    this.pendingEdits.delete(key);
    this.#ruleBaseline.set(key, new Map());

    if (this.#isOpen(groupId)) {
      await this.loadRules(groupId, listId, 0);
    }
  }

  forget(groupId: string) {
    this.#stopFollowingSync(groupId);
    for (const key of this.#keysOf(groupId)) this.#dropKey(key);
  }

  forgetList(groupId: string, listId: string) {
    this.#dropKey(listKey(groupId, listId));
  }
}
