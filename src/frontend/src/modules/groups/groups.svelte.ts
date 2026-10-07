import { tick } from "svelte";

import { followGroupsLoad, setKnownGroups } from "../../data/known-groups.svelte";
import { t } from "../../data/locale.svelte";
import { ChangeTracker } from "../../utils/change-tracker.svelte";
import { ListsController } from "./lists.svelte";

import {
  DEFAULT_RESOLVE,
  ruleTakesPorts,
  syncIdle,
  type DeviceSelector,
  type Group,
  type GroupResolve,
  type Rule,
} from "../../types";
import { defaultGroup, defaultRule } from "../../utils/defaults";
import { overlay, toast } from "../../utils/events";
import { fetcher, HttpError } from "../../utils/fetcher";
import { randomId } from "../../utils/random-id";
import { type SortDirection } from "../../utils/rule-sorter";
import { isValidPorts, VALIDATOP_MAP } from "../../utils/rule-validators";
import {
  cloneGroupsWithNewIds as cloneGroupsWithNewIdsData,
  cloneGroupWithNewIds as cloneGroupWithNewIdsData,
  prependGroups as prependGroupsData,
  prependRules as prependRulesData,
  restoreGroupRulesOrder as restoreGroupRulesOrderData,
  sortGroupRules as sortGroupRulesData,
  toConfigPayload as toConfigPayloadData,
} from "./groups-data";
import { type GroupLive, type NetfilterState } from "./live-state";
import { selectableIds, selectedInOrder, toggleId } from "./selection";

export const GROUPS_STORE_CONTEXT = Symbol("groups-store");

const SEARCH_DEBOUNCE_MS = 150 as const;
const IMPORT_RULES_CHUNK_SIZE = 300 as const;
const IMPORT_GROUPS_CLONE_CHUNK_SIZE = 20 as const;
const IMPORT_GROUPS_INSERT_CHUNK_SIZE = 25 as const;
const LIVE_POLL_MS = 5000 as const;
/* One poll's longest wait for an answer, under LIVE_POLL_MS. */
const LIVE_TIMEOUT_MS = 4000 as const;
/* Three polls missed: the daemon's last word is no longer vouched for. */
const LIVE_STALE_MS = 15000 as const;
export const RULE_SEARCH_MATCH_PATTERN = 1 << 1;

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

export function normalizeListUrl(value: string) {
  return (value ?? "").trim();
}

export function ruleIsInvalid(rule: Rule): boolean {
  if (rule.proto || rule.ports) {
    if (!ruleTakesPorts(rule.type) || !rule.proto) return true;
    if (rule.ports && !isValidPorts(rule.ports)) return true;
  }
  const validator = VALIDATOP_MAP[rule.type];
  return !rule.rule || !validator || !validator(rule.rule);
}

export function invalidRulesByGroup(groups: Group[]): Map<string, string[]> {
  const byGroup = new Map<string, string[]>();
  for (const group of groups) {
    const ids = (group.rules ?? []).filter(ruleIsInvalid).map((rule) => rule.id);
    if (ids.length > 0) byGroup.set(group.id, ids);
  }
  return byGroup;
}

export function isValidListUrl(value: string) {
  const normalized = normalizeListUrl(value);
  if (!normalized) return false;
  try {
    const parsed = new URL(normalized);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function deviceSelectorsEqual(a: DeviceSelector, b: DeviceSelector): boolean {
  return (
    a.allow.length === b.allow.length &&
    a.allow.every((value, i) => value === b.allow[i]) &&
    a.deny.length === b.deny.length &&
    a.deny.every((value, i) => value === b.deny[i])
  );
}

export function resolveEqual(a: GroupResolve | undefined, b: GroupResolve | undefined): boolean {
  const x = a ?? DEFAULT_RESOLVE();
  const y = b ?? DEFAULT_RESOLVE();
  return x.tunnel === y.tunnel && x.server === y.server;
}

export type GroupFieldError = { group: string; field: string; error: string };

export function groupRefusal(error: unknown): GroupFieldError | null {
  if (!(error instanceof HttpError) || error.status !== 400) return null;
  try {
    const body = JSON.parse(error.message) as { error?: string; field?: string; group?: string };
    if (!body.field || !body.group) return null;
    return { group: body.group, field: body.field, error: body.error ?? error.message };
  } catch {
    return null;
  }
}

export type GroupDialogPayload = {
  name: string;
  interface: string;
  devices: DeviceSelector;
  list?: { url: string; interval: number } | null;
  resolve: GroupResolve;
};

export type VisibleGroup = {
  group_index: number;
  ruleIndices: number[] | null;
};

export type GroupDragData = {
  group_id: string;
  group_index: number;
  name: string;
  count: number;
};

export type GroupDropSlotData = {
  group_index: number;
  insert: "before" | "after";
};

export type GroupDuplicateConflict = {
  ruleId: string;
  rulePattern: string;
  ruleType: string;
  groupId: string;
  groupName: string;
  inCurrentGroup: boolean;
  duplicateKey: string;
  totalRulesWithSameKey: number;
};

export type DuplicateRuleFocusRequest = {
  groupId: string;
  ruleId: string;
  nonce: number;
};

type DuplicateComputationResult = {
  duplicateRules: Set<string>;
  duplicateGroups: Set<string>;
  duplicateRuleKeys: Map<string, string>;
  duplicateConflictsByGroup: Map<string, GroupDuplicateConflict[]>;
};

type SearchIndexRule = {
  id: string;
  patternLower: string;
};

type SearchIndexGroup = {
  id: string;
  nameLower: string;
  rules: SearchIndexRule[];
};

type SearchHighlightSegment = {
  text: string;
  matched: boolean;
};

type GroupsStoreOptions = {
  onRenderComplete?: () => void;
};

export class GroupsStore {
  onRenderComplete?: () => void;

  tracker = $state(new ChangeTracker<Group[]>([]));
  data = $derived.by(() => this.tracker.data);
  dataRevision = $state(0);

  lists = new ListsController((id) => this.data.find((group) => group.id === id), {
    listGroups: () => this.data.filter((group) => Boolean(group.list)),
    isOpen: (id) => Boolean(this.open_state[id]),
    query: () => this.searchValue.trim().toLowerCase(),
    isSaved: (id) => this.listSaved(id),
    pageLoaded: () => this.refreshDuplicateRuleIds(),
    acknowledgeListSaved: (id) => {
      const group = this.data.find((g) => g.id === id);
      if (!group?.list) return;
      const previous = this.#listMetaBaseline.get(id);
      this.#listMetaBaseline.set(id, {
        url: group.list.url,
        interval: previous?.interval ?? group.list.interval ?? 86400,
      });
    },
  });

  #listMetaBaseline = new Map<string, { url: string; interval: number }>();

  resetListMetaBaseline(groups: Group[]) {
    this.#listMetaBaseline.clear();
    for (const group of groups) {
      if (!group.list) continue;
      this.#listMetaBaseline.set(group.id, {
        url: group.list.url,
        interval: group.list.interval ?? 86400,
      });
    }
  }

  listMetaDirty(groupId: string): boolean {
    const group = this.data.find((g) => g.id === groupId);
    if (!group?.list) return false;
    const baseline = this.#listMetaBaseline.get(groupId);
    if (!baseline) return true;
    return group.list.url !== baseline.url || (group.list.interval ?? 86400) !== baseline.interval;
  }

  listSaved(groupId: string): boolean {
    return this.#listMetaBaseline.has(groupId);
  }

  get hasListMetaEdits(): boolean {
    for (const group of this.data) {
      if (group.list && this.listMetaDirty(group.id)) return true;
    }
    return false;
  }

  invalidRules = $derived(invalidRulesByGroup(this.tracker.data));
  /* A getter, not $derived: lists state changes behind it between reads. */
  get canSave() {
    return (
      (this.tracker.isDirty || this.lists.hasPendingEdits || this.hasListMetaEdits) &&
      this.invalidRules.size === 0 &&
      this.validListUrls &&
      !this.lists.syncBlockingSave
    );
  }

  listUrlErrors = $derived.by(() => {
    const errors = new Map<string, string>();
    const idsByUrl = new Map<string, string[]>();

    for (const group of this.data) {
      if (!group.list) continue;
      const normalized = normalizeListUrl(group.list.url ?? "");

      if (!isValidListUrl(normalized)) {
        errors.set(group.id, "Invalid URL");
        continue;
      }

      const ids = idsByUrl.get(normalized) ?? [];
      ids.push(group.id);
      idsByUrl.set(normalized, ids);
    }

    for (const ids of idsByUrl.values()) {
      if (ids.length <= 1) continue;
      for (const id of ids) errors.set(id, "List already exists");
    }

    return errors;
  });
  validListUrls = $derived(this.listUrlErrors.size === 0);

  hasListUrlError(groupId: string): boolean {
    return this.listUrlErrors.has(groupId);
  }

  listUrlErrorMessage(groupId: string): string {
    const reason = this.listUrlErrors.get(groupId);
    if (reason === "List already exists") return t("List already exists");
    if (reason === "Invalid URL") return t("Invalid URL");
    return "";
  }

  open_state = $state<Record<string, boolean>>({});

  selectedIds = $state<string[]>([]);

  get selection(): string[] {
    return selectedInOrder(this.selectedIds, this.data);
  }

  isSelected(id: string): boolean {
    return this.selectedIds.includes(id);
  }

  toggleSelected(id: string) {
    this.selectedIds = toggleId(this.selection, id);
  }

  clearSelection() {
    if (this.selectedIds.length) this.selectedIds = [];
  }

  async selectAll() {
    if (this.searchActive) await this.#searchSettled();
    this.selectedIds = selectableIds(this.data, this.searchActive, this.visibilityMap);
  }

  async #searchSettled(maxMs = 5000) {
    const until = Date.now() + maxMs;
    while (
      (this.#debounceTimer !== null || this.searchPending || this.#searchRuns > 0) &&
      Date.now() < until
    ) {
      await new Promise((resolve) => setTimeout(resolve, 16));
    }
  }

  #editSelected(edit: (group: Group) => void) {
    const wanted = new Set(this.selection);
    if (!wanted.size) return;
    for (const group of this.data) {
      if (wanted.has(group.id)) edit(group);
    }
    this.markDataRevision();
  }

  setSelectedInterface(iface: string) {
    this.#editSelected((group) => {
      if (group.interface !== iface) group.interface = iface;
    });
  }

  setSelectedEnable(enable: boolean) {
    this.#editSelected((group) => {
      if (group.enable !== enable) group.enable = enable;
    });
  }

  /* One confirm naming the count, then no per-group one. */
  deleteSelected = () => {
    const doomed = new Set(this.selection);
    if (!doomed.size) return;
    if (!confirm(t("Delete the selected groups ({n})?").replace("{n}", String(doomed.size)))) {
      return;
    }
    for (let i = this.data.length - 1; i >= 0; i--) {
      if (doomed.has(this.data[i].id)) this.#removeGroupAt(i);
    }
    this.markDataRevision();
  };

  searchValue = $state("");
  visibleGroups = $state<VisibleGroup[]>([]);
  searchPending = $state(false);
  searchMatchedGroupIds = $state<Set<string>>(new Set());
  searchRuleMatchMaskById = $state<Map<string, number>>(new Map());

  normalizedSearch = $derived(this.searchValue.trim().toLowerCase());
  searchActive = $derived(Boolean(this.normalizedSearch));

  searchIndex = $state<SearchIndexGroup[]>([]);
  searchIndexRevision = $state(-1);

  visibilityMap = $derived(new Map(this.visibleGroups.map((v) => [v.group_index, v.ruleIndices])));

  firstVisibleGroupIndex = $derived(
    this.searchActive ? (this.visibleGroups.length ? this.visibleGroups[0].group_index : -1) : 0,
  );

  noVisibleGroups = $derived(
    this.searchActive && !this.searchPending && this.visibleGroups.length === 0,
  );

  finishedGroupsCount = $state(0);
  fetchError = $state(false);
  dataLoaded = $state(false);
  groupFieldError = $state<GroupFieldError | null>(null);

  clearGroupFieldError() {
    this.groupFieldError = null;
  }

  #live = $state<Record<string, GroupLive>>({});
  netfilter = $state<NetfilterState | null>(null);
  checkedAt = $state(0);
  noAnswer = $state(false);
  #liveTimer: ReturnType<typeof setInterval> | null = null;
  #livePolling = false;
  #pollFailing = false;
  /* An answer is taken only if its ticket beats the last taken: a PUT's can land after a later poll's. */
  #liveSeq = 0;
  #liveTaken = 0;
  #netfilterTaken = 0;

  liveOf(groupId: string): GroupLive | undefined {
    return this.#live[groupId];
  }

  #liveTicket() {
    return { seq: ++this.#liveSeq, sentAt: Date.now() };
  }

  #takeNetfilter(netfilter: NetfilterState, ticket: { seq: number }) {
    if (ticket.seq <= this.#netfilterTaken) return;
    this.#netfilterTaken = ticket.seq;
    this.netfilter = netfilter;
  }

  #takeLive(records: any[], ticket: { seq: number; sentAt: number }) {
    if (ticket.seq <= this.#liveTaken) return;
    this.#liveTaken = ticket.seq;
    const next: Record<string, GroupLive> = {};
    for (const record of records) {
      if (!record?.id || typeof record.live !== "boolean") continue;
      next[record.id] = {
        live: record.live,
        liveReason: record.live ? undefined : record.liveReason,
      };
    }
    this.#live = next;
    this.checkedAt = ticket.sentAt;
    this.noAnswer = false;
  }

  groupDirty(group: Group): boolean {
    return (
      this.tracker.isDirtyWithin(group) ||
      this.listMetaDirty(group.id) ||
      this.lists.ruleEdits(group.id).length > 0
    );
  }

  pollLive = async () => {
    if (this.#livePolling) return;
    this.#livePolling = true;
    const ticket = this.#liveTicket();
    const opts = { quiet: true, signal: AbortSignal.timeout(LIVE_TIMEOUT_MS) };
    try {
      const [netfilter, answer] = await Promise.all([
        fetcher.get<NetfilterState>("/system/netfilter", opts),
        fetcher.get<{ groups?: any[] }>("/groups", opts),
      ]);
      this.#takeNetfilter(netfilter, ticket);
      this.#takeLive(answer?.groups ?? [], ticket);
      if (this.#pollFailing) console.info("Live state polls answer again");
      this.#pollFailing = false;
    } catch (error) {
      /* Once per run of failures, not twice every five seconds. */
      if (!this.#pollFailing) console.error("Failed to poll live state:", error);
      this.#pollFailing = true;
      if (this.checkedAt > 0 && Date.now() - this.checkedAt > LIVE_STALE_MS) {
        this.noAnswer = true;
      }
    } finally {
      this.#livePolling = false;
    }
  };

  #onVisibility = () => {
    if (document.visibilityState === "visible") {
      void this.pollLive();
      this.#armLiveTimer();
    } else {
      this.#disarmLiveTimer();
    }
  };

  #armLiveTimer() {
    this.#disarmLiveTimer();
    this.#liveTimer = setInterval(() => void this.pollLive(), LIVE_POLL_MS);
  }

  #disarmLiveTimer() {
    if (this.#liveTimer !== null) clearInterval(this.#liveTimer);
    this.#liveTimer = null;
  }

  startLivePolling() {
    if (typeof document === "undefined") return;
    document.addEventListener("visibilitychange", this.#onVisibility);
    if (document.visibilityState === "visible") this.#armLiveTimer();
  }

  #stopLivePolling() {
    this.#disarmLiveTimer();
    if (typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", this.#onVisibility);
    }
  }

  isAllRendered = $derived(
    this.dataLoaded &&
      (this.data.length === 0 || this.finishedGroupsCount >= this.data.length || this.searchActive),
  );

  isEmptyData = $derived(
    this.dataLoaded &&
      !this.fetchError &&
      !this.searchActive &&
      !this.searchPending &&
      this.data.length === 0,
  );
  duplicateRuleIds = $state<Set<string>>(new Set());
  duplicateGroupIds = $state<Set<string>>(new Set());
  duplicateRuleKeys = $state<Map<string, string>>(new Map());
  duplicateConflictsByGroup = $state<Map<string, GroupDuplicateConflict[]>>(new Map());
  activeDuplicateKey = $state<string | null>(null);
  duplicateHighlightPinned = $state(false);
  highlightedRuleId = $state<string | null>(null);
  duplicateFocusRequest = $state<DuplicateRuleFocusRequest | null>(null);

  renderGroupsLimit = $state(1);
  renderGroupsTimeout: number | null = null;

  #forcedGroupIds = new Set<string>();
  #forcedRuleIdsByGroup = new Map<string, Set<string>>();
  #forcedSearchKey = "";
  #debounceTimer: number | null = null;
  #duplicateRuleIdsTimer: number | null = null;
  #highlightedRuleTimer: number | null = null;
  #searchIndexBuildToken = 0;
  #searchIndexBuilding = false;
  #dispose: (() => void) | null = null;

  constructor(options: GroupsStoreOptions = {}) {
    this.onRenderComplete = options.onRenderComplete;
    this.#setupEffects();
  }

  #setupEffects() {
    this.#dispose = $effect.root(() => {
      $effect(() => {
        if (typeof window === "undefined" || !this.canSave) return;

        const handleBeforeUnload = (event: BeforeUnloadEvent) => {
          event.preventDefault();
        };

        window.addEventListener("beforeunload", handleBeforeUnload);
        return () => window.removeEventListener("beforeunload", handleBeforeUnload);
      });

      $effect(() => {
        const query = this.normalizedSearch;
        this.dataRevision;
        this.data.length;

        if (this.#debounceTimer) {
          clearTimeout(this.#debounceTimer);
          this.#debounceTimer = null;
        }

        if (!query) {
          this.#cancelSearchIndexBuild();
          this.visibleGroups = this.data.map((_, index) => ({
            group_index: index,
            ruleIndices: null,
          }));
          this.#clearSearchMatches();
          this.searchPending = false;
          void this.lists.searchLists();
          return;
        }

        this.searchPending = true;

        if (this.searchIndexRevision !== this.dataRevision) {
          this.#startSearchIndexBuild();
        }

        if (typeof window === "undefined") {
          void this.#runSearch();
          return;
        }

        this.#debounceTimer = window.setTimeout(() => {
          this.#debounceTimer = null;
          void this.#runSearch();
        }, SEARCH_DEBOUNCE_MS);
      });

      $effect(() => {
        if (this.searchActive) {
          this.renderGroupsLimit = this.data.length;
          if (this.renderGroupsTimeout) {
            clearTimeout(this.renderGroupsTimeout);
            this.renderGroupsTimeout = null;
          }
        } else {
          this.scheduleGroupsNext();
        }
      });

      $effect(() => {
        this.data.length;
        this.scheduleGroupsNext();
      });

      $effect(() => {
        if (this.isAllRendered) {
          this.onRenderComplete?.();
        }
      });

      return () => {
        if (this.#debounceTimer) {
          clearTimeout(this.#debounceTimer);
          this.#debounceTimer = null;
        }

        if (this.#duplicateRuleIdsTimer) {
          clearTimeout(this.#duplicateRuleIdsTimer);
          this.#duplicateRuleIdsTimer = null;
        }

        if (this.#highlightedRuleTimer) {
          clearTimeout(this.#highlightedRuleTimer);
          this.#highlightedRuleTimer = null;
        }

        if (this.renderGroupsTimeout) {
          clearTimeout(this.renderGroupsTimeout);
          this.renderGroupsTimeout = null;
        }
      };
    });
  }

  destroy() {
    if (typeof window !== "undefined") {
      window.removeEventListener("keydown", this.handleSaveShortcut);
    }

    this.lists.destroy();
    this.#stopLivePolling();

    if (this.#dispose) {
      this.#dispose();
      this.#dispose = null;
    }
  }

  mount = async () => {
    this.finishedGroupsCount = 0;
    this.fetchError = false;
    try {
      const ticket = this.#liveTicket();
      const request = fetcher
        .get<{ groups: Group[] }>("/groups?with_rules=true")
        .then((answer) => answer?.groups ?? []);
      followGroupsLoad(request);
      const records = await request;
      this.#takeLive(records, ticket);
      void fetcher
        .get<NetfilterState>("/system/netfilter", { quiet: true })
        .then((netfilter) => this.#takeNetfilter(netfilter, ticket))
        .catch((error) => console.error("Failed to read netfilter state:", error));
      const fetched = records.map(({ live: _live, liveReason: _reason, ...group }: any) => group);
      this.tracker = new ChangeTracker(fetched);
      this.dataRevision = 0;
      this.resetListMetaBaseline(fetched);

      for (const group of fetched) {
        const state = group.list?.sync?.state;
        if (state === "queued" || state === "fetching") {
          void this.lists.followSync(group.id);
        }
      }
    } catch (error) {
      this.fetchError = true;
      console.error("Failed to load groups:", error);
    } finally {
      this.refreshDuplicateRuleIds();
      this.dataLoaded = true;
    }

    if (typeof window !== "undefined") {
      window.addEventListener("keydown", this.handleSaveShortcut);
    }
  };

  handleSaveShortcut = (event: KeyboardEvent) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
      if (this.canSave || this.invalidRules.size > 0) {
        event.preventDefault();
        this.saveChanges();
      }
    }
  };

  forceVisibleGroup(groupId: string) {
    if (!this.normalizedSearch) return;
    this.#forcedGroupIds.add(groupId);
    this.#forcedSearchKey = this.normalizedSearch;
  }

  forceVisibleRule(groupId: string, ruleId: string) {
    if (!this.normalizedSearch) return;
    let forced = this.#forcedRuleIdsByGroup.get(groupId);
    if (!forced) {
      forced = new Set<string>();
      this.#forcedRuleIdsByGroup.set(groupId, forced);
    }
    forced.add(ruleId);
    this.#forcedSearchKey = this.normalizedSearch;
  }

  removeForcedGroup(groupId: string) {
    this.#forcedGroupIds.delete(groupId);
    this.#forcedRuleIdsByGroup.delete(groupId);
  }

  removeForcedRule(groupId: string, ruleId: string) {
    const forced = this.#forcedRuleIdsByGroup.get(groupId);
    if (!forced) return;
    forced.delete(ruleId);
    if (!forced.size) this.#forcedRuleIdsByGroup.delete(groupId);
  }

  moveForcedRule(sourceGroupId: string, targetGroupId: string, ruleId: string) {
    if (sourceGroupId === targetGroupId) return;
    const forced = this.#forcedRuleIdsByGroup.get(sourceGroupId);
    if (!forced?.has(ruleId)) return;
    forced.delete(ruleId);
    if (!forced.size) this.#forcedRuleIdsByGroup.delete(sourceGroupId);
    let targetForced = this.#forcedRuleIdsByGroup.get(targetGroupId);
    if (!targetForced) {
      targetForced = new Set<string>();
      this.#forcedRuleIdsByGroup.set(targetGroupId, targetForced);
    }
    targetForced.add(ruleId);
  }

  syncRuleDeletion(groupIndex: number, ruleIndex: number) {
    if (!this.searchActive) return;
    const targetIndex = this.visibleGroups.findIndex((entry) => entry.group_index === groupIndex);
    if (targetIndex === -1) return;
    const target = this.visibleGroups[targetIndex];
    if (!target?.ruleIndices) return;

    const ruleIndices = target.ruleIndices;
    let write = 0;
    for (let i = 0; i < ruleIndices.length; i++) {
      const index = ruleIndices[i];
      if (index === ruleIndex) continue;
      ruleIndices[write] = index > ruleIndex ? index - 1 : index;
      write += 1;
    }

    if (write === 0) {
      this.visibleGroups.splice(targetIndex, 1);
      return;
    }

    ruleIndices.length = write;
    target.ruleIndices = ruleIndices;
    this.visibleGroups[targetIndex] = target;
  }

  #resetForcedVisibility(searchKey: string) {
    if (!this.#forcedSearchKey) return;
    if (this.#forcedSearchKey !== searchKey) {
      this.#forcedGroupIds.clear();
      this.#forcedRuleIdsByGroup.clear();
      this.#forcedSearchKey = "";
    }
  }

  #clearSearchMatches() {
    this.searchMatchedGroupIds = new Set();
    this.searchRuleMatchMaskById = new Map();
  }

  #splitSearchHighlightSegments(
    value: string,
    query: string,
  ): SearchHighlightSegment[] | undefined {
    if (!value || !query) return undefined;

    const source = `${value}`;
    const needle = query.trim().toLowerCase();
    if (!needle) return undefined;

    const haystack = source.toLowerCase();
    const needleLength = needle.length;

    let cursor = 0;
    let matchIndex = haystack.indexOf(needle, cursor);
    if (matchIndex === -1) return undefined;

    const segments: SearchHighlightSegment[] = [];

    while (matchIndex !== -1) {
      if (matchIndex > cursor) {
        segments.push({ text: source.slice(cursor, matchIndex), matched: false });
      }

      const matchEnd = matchIndex + needleLength;
      segments.push({ text: source.slice(matchIndex, matchEnd), matched: true });

      cursor = matchEnd;
      matchIndex = haystack.indexOf(needle, cursor);
    }

    if (cursor < source.length) {
      segments.push({ text: source.slice(cursor), matched: false });
    }

    return segments;
  }

  #cancelSearchIndexBuild() {
    this.#searchIndexBuildToken += 1;
  }

  #startSearchIndexBuild(incrementToken = true) {
    if (incrementToken) {
      this.#searchIndexBuildToken += 1;
    }

    if (this.#searchIndexBuilding) return;
    void this.#buildSearchIndex(this.#searchIndexBuildToken);
  }

  async #buildSearchIndex(token: number) {
    if (!this.searchActive) return;

    this.#searchIndexBuilding = true;
    const revision = this.dataRevision;
    const groups = this.data;
    const total = groups.length;
    const nextIndex = new Array<SearchIndexGroup>(total);

    const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());
    let lastYield = now();

    const maybeYield = async () => {
      if (now() - lastYield < 8) return;
      await this.#yieldToMain();
      lastYield = now();
    };

    const abortIfStale = () => token !== this.#searchIndexBuildToken || !this.searchActive;

    for (let i = 0; i < total; i++) {
      if (abortIfStale()) {
        this.#searchIndexBuilding = false;
        if (this.searchActive && token !== this.#searchIndexBuildToken) {
          this.#startSearchIndexBuild(false);
        }
        return;
      }

      const group = groups[i];
      const rules = group.rules;
      const rulesCount = rules.length;
      const indexedRules = new Array<SearchIndexRule>(rulesCount);

      for (let r = 0; r < rulesCount; r++) {
        const rule = rules[r];
        indexedRules[r] = {
          id: rule.id,
          patternLower: (rule.rule || "").toLowerCase(),
        };
        if ((r & 31) === 0) {
          await maybeYield();
          if (abortIfStale()) {
            this.#searchIndexBuilding = false;
            if (this.searchActive && token !== this.#searchIndexBuildToken) {
              this.#startSearchIndexBuild(false);
            }
            return;
          }
        }
      }

      nextIndex[i] = {
        id: group.id,
        nameLower: (group.name || "").toLowerCase(),
        rules: indexedRules,
      };

      if ((i & 7) === 0) {
        await maybeYield();
      }
    }

    if (abortIfStale()) {
      this.#searchIndexBuilding = false;
      if (this.searchActive && token !== this.#searchIndexBuildToken) {
        this.#startSearchIndexBuild(false);
      }
      return;
    }

    if (this.dataRevision !== revision) {
      this.#searchIndexBuilding = false;
      if (this.searchActive) {
        this.#startSearchIndexBuild(false);
      }
      return;
    }

    this.searchIndex = nextIndex;
    this.searchIndexRevision = revision;
    this.#searchIndexBuilding = false;

    if (this.normalizedSearch) {
      this.performSearch();
    } else {
      this.searchPending = false;
    }
  }

  performSearch() {
    const query = this.normalizedSearch;
    this.#resetForcedVisibility(query);

    if (!query) {
      this.visibleGroups = this.data.map((_, index) => ({
        group_index: index,
        ruleIndices: null,
      }));
      this.#clearSearchMatches();
      this.searchPending = false;
      return;
    }

    if (this.searchIndexRevision !== this.dataRevision) {
      this.#clearSearchMatches();
      this.searchPending = true;
      return;
    }

    const nextVisible: VisibleGroup[] = [];
    const matchedGroupIds = new Set<string>();
    const ruleMatchMaskById = new Map<string, number>();
    const searchIndex = this.searchIndex;
    const len = searchIndex.length;

    for (let i = 0; i < len; i++) {
      const indexedGroup = searchIndex[i];
      const isForcedGroup = this.#forcedGroupIds.has(indexedGroup.id);
      const isGroupMatchedByName = indexedGroup.nameLower.includes(query);

      if (isForcedGroup || isGroupMatchedByName) {
        if (isGroupMatchedByName) {
          matchedGroupIds.add(indexedGroup.id);
        }
        nextVisible.push({ group_index: i, ruleIndices: null });
        continue;
      }

      const matchedRuleIndices: number[] = [];
      const forcedRules = this.#forcedRuleIdsByGroup.get(indexedGroup.id);
      const rules = indexedGroup.rules;
      const rulesLen = rules.length;

      for (let r = 0; r < rulesLen; r++) {
        const indexedRule = rules[r];
        let matchMask = 0;
        if (indexedRule.patternLower.includes(query)) {
          matchMask |= RULE_SEARCH_MATCH_PATTERN;
        }

        if (forcedRules?.has(indexedRule.id) || matchMask !== 0) {
          matchedRuleIndices.push(r);
          if (matchMask !== 0) {
            ruleMatchMaskById.set(indexedRule.id, matchMask);
          }
        }
      }

      if (matchedRuleIndices.length > 0) {
        nextVisible.push({ group_index: i, ruleIndices: matchedRuleIndices });
      }
    }

    this.visibleGroups = nextVisible;
    this.searchMatchedGroupIds = matchedGroupIds;
    this.searchRuleMatchMaskById = ruleMatchMaskById;
    this.searchPending = false;
  }

  #searchRuns = 0;

  async #runSearch() {
    this.#searchRuns += 1;
    try {
      await this.#runSearchOnce();
    } finally {
      this.#searchRuns -= 1;
    }
  }

  async #runSearchOnce() {
    const query = this.normalizedSearch;
    this.performSearch();

    const listMatched = await this.lists.searchLists();
    if (!listMatched.size) return;
    if (this.normalizedSearch !== query) return;
    if (!this.searchActive) return;

    const present = new Set(
      this.visibleGroups.map((entry) => this.data[entry.group_index]?.id).filter(Boolean),
    );
    let changed = false;
    const next = [...this.visibleGroups];
    for (const id of listMatched) {
      if (present.has(id)) continue;
      const index = this.data.findIndex((group) => group.id === id);
      if (index === -1) continue;
      next.push({ group_index: index, ruleIndices: [] });
      changed = true;
    }
    if (!changed) return;
    next.sort((a, b) => a.group_index - b.group_index);
    this.visibleGroups = next;
  }

  #saving = false;

  async saveChanges() {
    if (this.invalidRules.size > 0) {
      this.revealInvalidRule();
      return;
    }
    if (!this.canSave) return;
    if (this.#saving) return;
    this.#saving = true;
    this.groupFieldError = null;
    overlay.show(t("saving changes..."));

    const current = $state.snapshot(this.data) as Group[];
    const bodyGroups = current.map(({ list, resolver, ...rest }) => ({
      ...rest,
      list: list ? { url: list.url, interval: list.interval } : null,
    }));
    const edits = current
      .map((group) => ({ id: group.id, rules: this.lists.ruleEdits(group.id) }))
      .filter((e) => e.rules.length > 0);

    const savedUrls = new Map(
      Array.from(this.#listMetaBaseline, ([id, baseline]) => [id, baseline.url]),
    );

    const save = (last: boolean) => (last ? "?save=true" : "");
    let landed = 0;
    try {
      const putTicket = this.#liveTicket();
      const answer = await fetcher.put<{ groups?: any[] }>(`/groups${save(edits.length === 0)}`, {
        groups: bodyGroups,
      });
      landed++;
      if (answer?.groups) this.#takeLive(answer.groups, putTicket);

      const replaced = new Set<string>();
      for (const record of answer?.groups ?? []) {
        const state = record?.list?.sync?.state;
        if (state !== "queued" && state !== "fetching") continue;
        const repointed = savedUrls.get(record.id) !== record.list.url;
        if (this.lists.adoptQueuedSync(record.id, record, repointed)) replaced.add(record.id);
      }

      const patches = edits.filter((edit) => !replaced.has(edit.id));
      if (edits.length > 0 && patches.length === 0) {
        await fetcher.post("/system/config/save", {});
      }
      for (let i = 0; i < patches.length; i++) {
        const edit = patches[i];
        await fetcher.patch(`/groups/${edit.id}/list/rules${save(i === patches.length - 1)}`, {
          rules: edit.rules,
        });
        landed++;
      }

      const answerById = new Map((answer.groups ?? []).map((g: any) => [g.id, g]));
      const saved = current.map((group) => {
        const withResolver = answerById.get(group.id)?.resolver
          ? { ...group, resolver: answerById.get(group.id).resolver }
          : group;
        if (!withResolver.list) return withResolver;
        /* List sync fields from live data, not `current`: a sync can land mid-Save. */
        const live = this.data.find((g) => g.id === group.id);
        const fresh = live ? ($state.snapshot(live) as Group) : undefined;
        return {
          ...withResolver,
          list: {
            url: withResolver.list.url,
            interval: withResolver.list.interval,
            rulesTotal: fresh?.list?.rulesTotal ?? withResolver.list.rulesTotal,
            lastUpdate: fresh?.list?.lastUpdate ?? withResolver.list.lastUpdate,
            sync: fresh?.list?.sync ?? withResolver.list.sync,
          },
        };
      });
      this.tracker.reset(saved);
      this.lists.acknowledgeAllSaved();
      this.resetListMetaBaseline(current);
      setKnownGroups(current);
      overlay.hide();
      toast.success(t("Saved"));
    } catch (error) {
      this.groupFieldError = groupRefusal(error);
      const answered = error instanceof HttpError;
      /* An unanswered request may still have applied: the daemon applies a PUT before answering. */
      if (landed > 0 || !answered) {
        try {
          await fetcher.post("/system/config/save", {});
        } catch (saveError) {
          console.error(saveError);
        }
      }
      overlay.hide();
    } finally {
      this.#saving = false;
    }
  }

  revealInvalidRule = () => {
    const first = this.data.find((group) => this.invalidRules.has(group.id));
    const ruleId = first && this.invalidRules.get(first.id)?.[0];
    if (!first || !ruleId) return;
    toast.error(t("Fill in or fix the highlighted rules before saving"));
    this.requestDuplicateRuleFocus(first.id, ruleId);
  };

  #sortDuplicateConflicts(conflicts: GroupDuplicateConflict[]) {
    conflicts.sort((a, b) => {
      const byKey = a.duplicateKey.localeCompare(b.duplicateKey);
      if (byKey !== 0) return byKey;

      if (a.inCurrentGroup !== b.inCurrentGroup) {
        return a.inCurrentGroup ? 1 : -1;
      }
      const byGroup = (a.groupName || "").localeCompare(b.groupName || "");
      if (byGroup !== 0) return byGroup;
      const byPattern = (a.rulePattern || "").localeCompare(b.rulePattern || "");
      if (byPattern !== 0) return byPattern;
      return a.ruleId.localeCompare(b.ruleId);
    });
  }

  #computeDuplicates(): DuplicateComputationResult {
    const duplicateRules = new Set<string>();
    const duplicateGroups = new Set<string>();
    const duplicateRuleKeys = new Map<string, string>();
    const rulesByKey = new Map<string, { rule: Rule; groupId: string; groupName: string }[]>();

    for (const group of this.data) {
      const listed = (group.list ? (this.lists.pageState[group.id]?.rules ?? []) : []) as Rule[];
      for (const rule of [...group.rules, ...listed]) {
        const normalizedPattern = rule.rule.trim();
        if (!normalizedPattern) continue;

        const key = `${rule.type}:${rule.rule}:${rule.proto ?? ""}:${rule.ports ?? ""}`;
        duplicateRuleKeys.set(rule.id, key);
        let rules = rulesByKey.get(key);
        if (!rules) {
          rules = [];
          rulesByKey.set(key, rules);
        }
        rules.push({
          rule,
          groupId: group.id,
          groupName: group.name,
        });
      }
    }

    const conflictsByKey = new Map<string, GroupDuplicateConflict[]>();
    const duplicateKeysByGroup = new Map<string, Set<string>>();

    for (const [key, rules] of rulesByKey) {
      if (rules.length < 2) continue;

      for (const entry of rules) {
        duplicateRules.add(entry.rule.id);
        duplicateGroups.add(entry.groupId);
        let keys = duplicateKeysByGroup.get(entry.groupId);
        if (!keys) {
          keys = new Set<string>();
          duplicateKeysByGroup.set(entry.groupId, keys);
        }
        keys.add(key);
      }

      conflictsByKey.set(
        key,
        rules.map((entry) => ({
          ruleId: entry.rule.id,
          rulePattern: entry.rule.rule,
          ruleType: entry.rule.type,
          groupId: entry.groupId,
          groupName: entry.groupName,
          inCurrentGroup: false,
          duplicateKey: key,
          totalRulesWithSameKey: rules.length,
        })),
      );
    }

    const duplicateConflictsByGroup = new Map<string, GroupDuplicateConflict[]>();

    for (const [groupId, keys] of duplicateKeysByGroup) {
      const conflicts: GroupDuplicateConflict[] = [];
      for (const key of keys) {
        const sameKeyConflicts = conflictsByKey.get(key);
        if (!sameKeyConflicts) continue;
        for (const conflict of sameKeyConflicts) {
          conflicts.push({
            ...conflict,
            inCurrentGroup: conflict.groupId === groupId,
          });
        }
      }
      this.#sortDuplicateConflicts(conflicts);
      duplicateConflictsByGroup.set(groupId, conflicts);
    }

    return { duplicateRules, duplicateGroups, duplicateRuleKeys, duplicateConflictsByGroup };
  }

  #applyDuplicateComputation(result: DuplicateComputationResult) {
    this.duplicateRuleIds = result.duplicateRules;
    this.duplicateGroupIds = result.duplicateGroups;
    this.duplicateRuleKeys = result.duplicateRuleKeys;
    this.duplicateConflictsByGroup = result.duplicateConflictsByGroup;
    this.#syncActiveDuplicateKey();
  }

  #syncActiveDuplicateKey() {
    if (this.highlightedRuleId && !this.duplicateRuleIds.has(this.highlightedRuleId)) {
      this.highlightedRuleId = null;
    }

    if (!this.activeDuplicateKey) return;

    for (const ruleId of this.duplicateRuleIds) {
      if (this.duplicateRuleKeys.get(ruleId) === this.activeDuplicateKey) {
        return;
      }
    }

    this.activeDuplicateKey = null;
    this.duplicateHighlightPinned = false;
  }

  #resolveDuplicateKey(ruleId: string) {
    const key = this.duplicateRuleKeys.get(ruleId);
    if (!key || !this.duplicateRuleIds.has(ruleId)) {
      return null;
    }
    return key;
  }

  refreshDuplicateRuleIds = () => {
    if (this.#duplicateRuleIdsTimer) {
      clearTimeout(this.#duplicateRuleIdsTimer);
      this.#duplicateRuleIdsTimer = null;
    }
    this.#applyDuplicateComputation(this.#computeDuplicates());
  };

  scheduleDuplicateRuleIdsRefresh = (delayMs = 120) => {
    if (typeof window === "undefined") {
      this.refreshDuplicateRuleIds();
      return;
    }

    if (this.#duplicateRuleIdsTimer) {
      clearTimeout(this.#duplicateRuleIdsTimer);
    }

    this.#duplicateRuleIdsTimer = window.setTimeout(() => {
      this.#duplicateRuleIdsTimer = null;
      this.#applyDuplicateComputation(this.#computeDuplicates());
    }, delayMs);
  };

  isRuleDuplicate = (ruleId: string) => this.duplicateRuleIds.has(ruleId);
  getRuleSearchMatchMask = (ruleId: string) => this.searchRuleMatchMaskById.get(ruleId) ?? 0;
  getSearchHighlightParts = (value: string, query: string): SearchHighlightSegment[] | undefined =>
    this.#splitSearchHighlightSegments(value, query);

  pinDuplicateByRuleId = (ruleId: string) => {
    const key = this.#resolveDuplicateKey(ruleId);
    if (!key) {
      this.activeDuplicateKey = null;
      this.duplicateHighlightPinned = false;
      return false;
    }
    this.activeDuplicateKey = key;
    this.duplicateHighlightPinned = true;
    return true;
  };

  setActiveDuplicateByRuleId = (ruleId: string) => {
    if (this.duplicateHighlightPinned) return;
    const key = this.#resolveDuplicateKey(ruleId);
    if (!key) {
      this.activeDuplicateKey = null;
      return;
    }
    this.activeDuplicateKey = key;
  };

  clearActiveDuplicateByRuleId = (ruleId: string) => {
    if (this.duplicateHighlightPinned || !this.activeDuplicateKey) return;
    const key = this.#resolveDuplicateKey(ruleId);
    if (!key || key === this.activeDuplicateKey) {
      this.activeDuplicateKey = null;
    }
  };

  togglePinnedDuplicateByRuleId = (ruleId: string) => {
    const key = this.#resolveDuplicateKey(ruleId);
    if (!key) {
      this.activeDuplicateKey = null;
      this.duplicateHighlightPinned = false;
      return;
    }
    if (this.duplicateHighlightPinned && this.activeDuplicateKey === key) {
      this.activeDuplicateKey = null;
      this.duplicateHighlightPinned = false;
      return;
    }
    this.pinDuplicateByRuleId(ruleId);
  };

  clearPinnedDuplicateHighlight = () => {
    if (!this.duplicateHighlightPinned) return;
    this.activeDuplicateKey = null;
    this.duplicateHighlightPinned = false;
  };

  highlightRuleTemporarily = (ruleId: string, durationMs = 2200) => {
    if (!this.duplicateRuleIds.has(ruleId)) return false;

    if (this.#highlightedRuleTimer) {
      clearTimeout(this.#highlightedRuleTimer);
      this.#highlightedRuleTimer = null;
    }

    const applyHighlight = () => {
      this.highlightedRuleId = ruleId;

      if (typeof window === "undefined") return;

      this.#highlightedRuleTimer = window.setTimeout(() => {
        this.#highlightedRuleTimer = null;
        if (this.highlightedRuleId === ruleId) {
          this.highlightedRuleId = null;
        }
      }, durationMs);
    };

    if (this.highlightedRuleId === ruleId) {
      this.highlightedRuleId = null;
      if (typeof window !== "undefined") {
        requestAnimationFrame(() => applyHighlight());
      } else {
        applyHighlight();
      }
      return true;
    }

    applyHighlight();

    return true;
  };

  isRuleHighlighted = (ruleId: string) => this.highlightedRuleId === ruleId;

  isRuleHighlightPinned = (ruleId: string) => this.isRuleHighlighted(ruleId);

  requestDuplicateRuleFocus = (groupId: string, ruleId: string) => {
    const groupIndex = this.data.findIndex((group) => group.id === groupId);
    if (groupIndex < 0) return false;

    if (this.searchActive) {
      this.forceVisibleRule(groupId, ruleId);
      this.performSearch();
    }

    this.renderGroupsLimit = Math.max(this.renderGroupsLimit, groupIndex + 1);
    this.open_state[groupId] = true;

    const nonce = (this.duplicateFocusRequest?.nonce ?? 0) + 1;
    this.duplicateFocusRequest = { groupId, ruleId, nonce };
    return true;
  };

  consumeDuplicateRuleFocus = (groupId: string, ruleId: string, nonce: number) => {
    const request = this.duplicateFocusRequest;
    if (!request) return;
    if (request.groupId !== groupId || request.ruleId !== ruleId || request.nonce !== nonce) return;
    this.duplicateFocusRequest = null;
  };

  getDuplicateConflictsForGroup = (groupId: string): GroupDuplicateConflict[] =>
    this.duplicateConflictsByGroup.get(groupId) ?? [];

  markDataRevision = () => {
    this.dataRevision += 1;
    this.scheduleDuplicateRuleIdsRefresh();
  };

  async addRuleToGroup(group_index: number, rule: Rule, focus = false) {
    const group = this.data[group_index];
    if (!group) return;
    group.rules.unshift(rule);
    this.markDataRevision();
    if (this.searchActive) {
      this.forceVisibleRule(group.id, rule.id);
    }
    if (!focus) return;
    await tick();
    const el = document.querySelector(
      `.rule[data-group-uuid="${group.id}"][data-uuid="${rule.id}"]`,
    );
    if (el) {
      el.querySelector<HTMLInputElement>("div.name input")?.focus();
      el.querySelector<HTMLInputElement>("div.pattern input.pattern-input")?.classList.add(
        "invalid",
      );
    }
  }

  deleteRuleFromGroup = (group_index: number, rule_index: number) => {
    const group = this.data[group_index];
    if (!group) return;
    const removed = group.rules[rule_index];
    group.rules.splice(rule_index, 1);
    if (removed) {
      this.removeForcedRule(group.id, removed.id);
    }
    this.syncRuleDeletion(group_index, rule_index);
    this.markDataRevision();
  };

  changeRuleIndex(
    from_group_index: number,
    from_rule_index: number,
    to_group_index: number,
    to_rule_index: number,
    to_rule_id?: string,
    insert: "before" | "after" = "before",
  ) {
    const sourceGroup = this.data[from_group_index];
    const targetGroup = this.data[to_group_index];

    if (!sourceGroup || !targetGroup) return;

    const isSameGroup = from_group_index === to_group_index;

    const sourceRules = sourceGroup.rules;
    const targetRules = targetGroup.rules;

    if (!sourceRules.length) return;

    const fromIndex = clamp(from_rule_index, 0, sourceRules.length - 1);
    const [movedRule] = sourceRules.splice(fromIndex, 1);
    if (!movedRule) return;

    if (!isSameGroup) {
      this.moveForcedRule(sourceGroup.id, targetGroup.id, movedRule.id);
    }

    let anchorIndex =
      to_rule_id && to_rule_id.length > 0 ? targetRules.findIndex((r) => r.id === to_rule_id) : -1;

    if (anchorIndex === -1 && targetRules.length > 0) {
      anchorIndex = clamp(to_rule_index, 0, targetRules.length - 1);
      if (isSameGroup && fromIndex < anchorIndex) {
        anchorIndex -= 1;
      }
    }

    let insertIndex: number;
    if (anchorIndex === -1) {
      insertIndex = insert === "after" ? targetRules.length : 0;
    } else {
      insertIndex = insert === "after" ? anchorIndex + 1 : anchorIndex;
    }

    insertIndex = clamp(insertIndex, 0, targetRules.length);
    targetRules.splice(insertIndex, 0, movedRule);

    this.markDataRevision();
  }

  changeGroupIndex(from_index: number, to_index: number, insert: "before" | "after" = "before") {
    if (from_index === to_index && insert !== "after") return;

    if (from_index < 0 || from_index >= this.data.length) return;

    const group = this.data[from_index];
    if (!group) return;

    this.data.splice(from_index, 1);

    let target = insert === "after" ? to_index + 1 : to_index;

    if (from_index < target) target -= 1;

    if (target < 0) target = 0;
    if (target > this.data.length) target = this.data.length;

    this.data.splice(target, 0, group);
    this.markDataRevision();
  }

  handleGroupSlotDrop = (source: GroupDragData, target: GroupDropSlotData) => {
    const { group_index: from_index } = source;
    const { group_index: to_index, insert } = target;
    if (from_index === to_index && insert !== "after") return;
    this.changeGroupIndex(from_index, to_index, insert);
  };

  get canAdd() {
    return this.dataLoaded && !this.fetchError;
  }

  async addGroup() {
    if (!this.canAdd) return;
    const group = defaultGroup();
    this.data.unshift(group);
    this.open_state[group.id] = true;
    this.markDataRevision();
    if (this.searchActive) {
      this.forceVisibleGroup(group.id);
    }
    await this.addRuleToGroup(0, defaultRule(), false);
    await tick();
    const el = document.querySelector(`.group-header[data-group-index="0"]`);
    el?.querySelector<HTMLInputElement>("input.group-name")?.focus();
  }

  setListUrl(groupId: string, url: string) {
    const group = this.data.find((g) => g.id === groupId);
    /* Mutated in place: replacing `list` dirties ChangeTracker by identity. */
    if (!group?.list || group.list.url === url) return;
    group.list.url = url;
    this.markDataRevision();
  }

  setListInterval(groupId: string, interval: number) {
    const group = this.data.find((g) => g.id === groupId);
    if (!group?.list || group.list.interval === interval) return;
    group.list.interval = interval;
    this.markDataRevision();
  }

  async createGroupFromDialog(payload: GroupDialogPayload) {
    if (!this.canAdd) return;
    const group: Group = {
      id: randomId(),
      name: payload.name,
      interface: payload.interface,
      enable: true,
      devices: payload.devices,
      resolve: { ...payload.resolve },
      rules: [],
      list: payload.list
        ? {
            url: payload.list.url,
            interval: payload.list.interval,
            lastUpdate: 0,
            rulesTotal: 0,
            sync: syncIdle(),
          }
        : undefined,
    };
    this.data.push(group);
    this.open_state[group.id] = true;
    this.markDataRevision();
    if (this.searchActive) {
      this.forceVisibleGroup(group.id);
    }
    await tick();
    document
      .querySelector<HTMLInputElement>(`.group[data-uuid="${group.id}"] input.group-name`)
      ?.focus();
  }

  updateGroupFromDialog(groupIndex: number, payload: GroupDialogPayload) {
    const group = this.data[groupIndex];
    if (!group) return;
    let changed = false;

    if (group.name !== payload.name) {
      group.name = payload.name;
      changed = true;
    }
    if (group.interface !== payload.interface) {
      group.interface = payload.interface;
      changed = true;
    }
    if (!deviceSelectorsEqual(group.devices, payload.devices)) {
      group.devices = payload.devices;
      changed = true;
    }
    if (!resolveEqual(group.resolve, payload.resolve)) {
      group.resolve = { ...payload.resolve };
      changed = true;
    }

    if (payload.list === null) {
      if (group.list) {
        this.lists.forget(group.id);
        this.#listMetaBaseline.delete(group.id);
        group.list = undefined;
        changed = true;
      }
    } else if (payload.list) {
      if (group.list) {
        if (group.list.url !== payload.list.url) {
          group.list.url = payload.list.url;
          changed = true;
        }
        if (group.list.interval !== payload.list.interval) {
          group.list.interval = payload.list.interval;
          changed = true;
        }
      } else {
        group.list = {
          url: payload.list.url,
          interval: payload.list.interval,
          lastUpdate: 0,
          rulesTotal: 0,
          sync: syncIdle(),
        };
        changed = true;
      }
    }

    if (changed) this.markDataRevision();
  }

  deleteGroup = (index: number) => {
    if (!confirm(t("Delete this group?"))) return;
    this.#removeGroupAt(index);
    this.markDataRevision();
  };

  #removeGroupAt(index: number) {
    const removed = this.data[index];
    this.data.splice(index, 1);
    if (removed) {
      this.removeForcedGroup(removed.id);
      delete this.open_state[removed.id];
      this.lists.forget(removed.id);
      this.#listMetaBaseline.delete(removed.id);
      if (this.selectedIds.includes(removed.id)) {
        this.selectedIds = this.selectedIds.filter((id) => id !== removed.id);
      }
    }
  }

  cloneGroupWithNewIds(group: Group): Group {
    return cloneGroupWithNewIdsData(group);
  }

  sortGroupRules(groupIndex: number, direction: SortDirection) {
    const group = this.data[groupIndex];
    if (!group) return false;
    sortGroupRulesData(group, direction);
    this.markDataRevision();
    return true;
  }

  restoreGroupRulesOrder(groupIndex: number, ruleIds: string[]) {
    const group = this.data[groupIndex];
    if (!group) return false;

    const restored = restoreGroupRulesOrderData(group, ruleIds);
    if (!restored) return false;
    this.markDataRevision();
    return true;
  }

  toConfigPayload() {
    return toConfigPayloadData($state.snapshot(this.data));
  }

  async cloneGroupsWithNewIds(groups: Group[]) {
    return cloneGroupsWithNewIdsData(
      groups,
      () => this.#yieldToMain(),
      IMPORT_GROUPS_CLONE_CHUNK_SIZE,
    );
  }

  async addGroups(groups: Group[]) {
    if (!groups.length || !this.canAdd) return;
    await prependGroupsData(
      this.data,
      this.open_state,
      groups,
      () => this.#yieldToMain(),
      IMPORT_GROUPS_INSERT_CHUNK_SIZE,
    );
    this.markDataRevision();
  }

  async overwriteGroups(groups: Group[]) {
    this.finishedGroupsCount = 0;
    this.renderGroupsLimit = 1;
    for (const removed of this.data) {
      this.lists.forget(removed.id);
      this.#listMetaBaseline.delete(removed.id);
    }
    this.data.splice(0, this.data.length);
    this.open_state = {};
    await this.addGroups(groups);
    if (!groups.length) {
      this.markDataRevision();
    }
  }

  async addRulesToGroup(groupIndex: number, rules: Rule[]) {
    const group = this.data[groupIndex];
    if (!group || !rules.length) return;

    await prependRulesData(group, rules, () => this.#yieldToMain(), IMPORT_RULES_CHUNK_SIZE);
    this.markDataRevision();
  }

  async #yieldToMain() {
    if (typeof window === "undefined") return;
    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, 0);
    });
  }

  handleGroupFinished = () => {
    this.finishedGroupsCount += 1;
  };

  scheduleGroupsNext() {
    if (typeof window === "undefined") return;
    if (this.renderGroupsTimeout) return;
    if (this.renderGroupsLimit >= this.data.length) return;

    this.renderGroupsTimeout = window.setTimeout(() => {
      this.renderGroupsTimeout = null;
      if (this.searchActive) {
        this.renderGroupsLimit = this.data.length;
        return;
      }
      this.renderGroupsLimit = Math.min(this.renderGroupsLimit + 2, this.data.length);
      this.scheduleGroupsNext();
    }, 15);
  }
}
