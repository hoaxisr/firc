import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const createMemoryStorage = () => {
  const store = new Map<string, string>();
  return {
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null;
    },
    setItem(key: string, value: string) {
      store.set(key, String(value));
    },
    removeItem(key: string) {
      store.delete(key);
    },
    clear() {
      store.clear();
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null;
    },
    get length() {
      return store.size;
    },
  };
};

const patchGlobal = (key: string, value: unknown) => {
  const original = Object.getOwnPropertyDescriptor(globalThis, key);
  Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  return () => {
    if (original) {
      Object.defineProperty(globalThis, key, original);
      return;
    }
    delete (globalThis as any)[key];
  };
};

const restoreLocalStorage = patchGlobal("localStorage", createMemoryStorage());
type ProcessLike = { env?: unknown };
const processObj = (globalThis as unknown as { process?: ProcessLike }).process;
const originalProcessEnvDescriptor = processObj
  ? Object.getOwnPropertyDescriptor(processObj, "env")
  : undefined;
if (processObj) {
  Object.defineProperty(processObj, "env", {
    value: { NODE_ENV: "test" },
    configurable: true,
    writable: true,
  });
}
const { GroupsStore } = await import("../../src/modules/groups/groups.svelte");
if (processObj) {
  if (originalProcessEnvDescriptor) {
    Object.defineProperty(processObj, "env", originalProcessEnvDescriptor);
  } else {
    delete processObj.env;
  }
}
restoreLocalStorage();

type ListRule = {
  id: string;
  enable: boolean;
  rule: string;
  type: string;
};

const makeRules = (count: number, offset = 0): ListRule[] =>
  Array.from({ length: count }).map((_, i) => ({
    id: `rule${String(offset + i).padStart(4, "0")}`,
    enable: true,
    rule: `${offset + i}.example.com`,
    type: "domain",
  }));

const ALL_RULES = makeRules(120);

const rulesPage = (offset: number, limit: number, q?: string) => {
  const pool = q
    ? ALL_RULES.filter((r) => r.rule.toLowerCase().includes(q.toLowerCase()))
    : ALL_RULES;
  return {
    total: ALL_RULES.length,
    matched: pool.length,
    offset,
    rules: pool.slice(offset, offset + limit),
  };
};

type FetchHandler = unknown | (() => unknown);

const SSE_BODY = Symbol("sse-body");
const eventStream = (...events: string[]) => ({ [SSE_BODY]: events.join("") });
const syncDone = (record: Record<string, unknown>) =>
  eventStream(`event: done\ndata: ${JSON.stringify(record)}\n\n`);

function installFetchStub(handlers: Record<string, FetchHandler>) {
  const calls: string[] = [];
  const requests: { path: string; method?: string; body?: unknown }[] = [];
  const original = globalThis.fetch;

  (globalThis as any).fetch = async (input: unknown, init?: { method?: string; body?: string }) => {
    const url = String(input);
    const path = url.replace(/^https?:\/\/[^/]+/, "").replace(/^\/api\/v1/, "");
    calls.push(path);

    let body: unknown;
    if (init?.body !== undefined) {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    requests.push({ path, method: init?.method, body });

    if (!(path in handlers)) {
      throw new Error(`unstubbed fetch: ${path}`);
    }

    const registered = handlers[path];
    const resolved = await (typeof registered === "function"
      ? (registered as () => unknown)()
      : registered);

    const events = (resolved as any)?.[SSE_BODY];
    if (typeof events === "string") {
      return {
        ok: true,
        status: 200,
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(events));
            controller.close();
          },
        }),
      };
    }

    return {
      ok: true,
      status: 200,
      json: async () => structuredClone(resolved),
    };
  };

  return {
    calls,
    requests,
    restore: () => {
      (globalThis as any).fetch = original;
    },
  };
}

const makeGroup = (id: string, rulesTotal: number) => ({
  id,
  name: `group-${id}`,
  interface: "",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  list: {
    url: `https://example.com/${id}.txt`,
    interval: 86400,
    lastUpdate: 0,
    rulesTotal,
    sync: { state: "idle", error: "", lastCheck: 0 },
  },
});

async function withWindowStub<T>(
  action: (toasts: { type: string; content: string }[]) => Promise<T>,
): Promise<T> {
  const hadWindow = "window" in globalThis;
  const original = (globalThis as any).window;
  const toasts: { type: string; content: string }[] = [];
  (globalThis as any).window = {
    dispatchEvent: (event: any) => {
      if (event?.type === "toast") toasts.push(event.detail);
      return true;
    },
    addEventListener: () => {},
    removeEventListener: () => {},
  };
  try {
    return await action(toasts);
  } finally {
    if (hadWindow) {
      (globalThis as any).window = original;
    } else {
      delete (globalThis as any).window;
    }
  }
}

function seed(store: InstanceType<typeof GroupsStore>, groups: ReturnType<typeof makeGroup>[]) {
  const cloned = structuredClone(groups);
  store.tracker.reset(cloned);
  store.resetListMetaBaseline(cloned);
}

describe("a group's list, paged and searched", () => {
  it("loads a page and remembers the count", async () => {
    const stub = installFetchStub({
      "/groups/a1b2c3d4/list/rules?offset=0&limit=50": rulesPage(0, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup("a1b2c3d4", 120)]);

      const group = store.data.find((g: any) => g.id === "a1b2c3d4");
      assert.ok(group);

      await store.lists.loadRules("a1b2c3d4", 0);

      assert.strictEqual(store.lists.pageState["a1b2c3d4"].rules.length, 50);
      assert.strictEqual(group.list.rulesTotal, 120);
      assert.strictEqual(store.lists.pageState["a1b2c3d4"].offset, 0);
      assert.strictEqual(store.tracker.isDirty, false);
    } finally {
      stub.restore();
    }
  });

  it("an edit on page one survives a visit to page two", async () => {
    const stub = installFetchStub({
      "/groups/b2b2b2b2/list/rules?offset=0&limit=50": rulesPage(0, 50),
      "/groups/b2b2b2b2/list/rules?offset=50&limit=50": rulesPage(50, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup("b2b2b2b2", 120)]);

      await store.lists.loadRules("b2b2b2b2", 0);
      const firstRuleId = store.lists.pageState["b2b2b2b2"].rules[0].id;
      assert.strictEqual(firstRuleId, "rule0000");

      store.lists.pageState["b2b2b2b2"].rules[0].enable = false;

      await store.lists.loadRules("b2b2b2b2", 50);
      assert.strictEqual(store.lists.pageState["b2b2b2b2"].rules[0].id, "rule0050");

      const editsWhileAway = store.lists.ruleEdits("b2b2b2b2");
      assert.deepStrictEqual(
        editsWhileAway.find((e: any) => e.id === firstRuleId),
        { id: firstRuleId, enable: false },
      );

      await store.lists.loadRules("b2b2b2b2", 0);
      assert.strictEqual(store.lists.pageState["b2b2b2b2"].rules[0].id, firstRuleId);
      assert.strictEqual(store.lists.pageState["b2b2b2b2"].rules[0].enable, false);
    } finally {
      stub.restore();
    }
  });

  // "42" matches exactly one rule's pattern, so both groups answering matched: 1 is a real match.
  it("search asks the daemon", async () => {
    const stub = installFetchStub({
      "/groups/c3c3c3c3/list/rules?offset=0&limit=50&q=42": rulesPage(0, 50, "42"),
      "/groups/d4d4d4d4/list/rules?offset=0&limit=1&q=42": rulesPage(0, 1, "42"),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup("c3c3c3c3", 120), makeGroup("d4d4d4d4", 120)]);
      store.open_state["c3c3c3c3"] = true;
      store.open_state["d4d4d4d4"] = false;

      store.searchValue = "42";
      const matched = await store.lists.searchLists();

      assert.ok(
        stub.calls.includes("/groups/c3c3c3c3/list/rules?offset=0&limit=50&q=42"),
        `expected a page request for the open group, got: ${stub.calls.join(", ")}`,
      );
      assert.ok(
        stub.calls.includes("/groups/d4d4d4d4/list/rules?offset=0&limit=1&q=42"),
        `expected a count-only request for the closed group, got: ${stub.calls.join(", ")}`,
      );

      assert.ok(matched.has("c3c3c3c3"), "open group's list with a match should be reported");
      assert.ok(matched.has("d4d4d4d4"), "closed group's list with a match should be reported");
    } finally {
      stub.restore();
    }
  });

  // Each half of what a `done` does to the replaced page is pinned by its own assertion.
  it("a sync empties the page it replaces and forgets the ids under it", async () => {
    const id = "f1f1f1f1";
    const preSyncPage = {
      total: 5,
      matched: 5,
      offset: 0,
      rules: [0, 1, 2, 3, 4].map((i) => ({
        id: `pre000${i}`,
        enable: true,
        rule: `${i}.old.example.com`,
        type: "domain",
      })),
    };
    const postSyncPage = {
      total: 5,
      matched: 5,
      offset: 0,
      rules: [0, 1, 2, 3, 4].map((i) => ({
        id: `post000${i}`,
        enable: true,
        rule: `${i}.new.example.com`,
        type: "domain",
      })),
    };

    let synced = false;
    let releasePostSyncPage!: () => void;
    const postSyncPageGate = new Promise<void>((resolve) => {
      releasePostSyncPage = resolve;
    });

    const pageUrl = `/groups/${id}/list/rules?offset=0&limit=50`;
    const stub = installFetchStub({
      [pageUrl]: async () => {
        if (!synced) return preSyncPage;
        await postSyncPageGate;
        return postSyncPage;
      },
      [`/groups/${id}/list/sync`]: () => {
        synced = true;
        return { sync: { state: "queued", error: "", lastCheck: 0 } };
      },
      [`/groups/${id}/list/sync/events`]: () =>
        syncDone({
          id,
          list: {
            rulesTotal: 5,
            lastUpdate: 999,
            url: `https://example.com/${id}.txt`,
            sync: { state: "idle", error: "", lastCheck: 999 },
          },
        }),
    });

    const hadConfirm = "confirm" in globalThis;
    const originalConfirm = (globalThis as any).confirm;
    (globalThis as any).confirm = () => true;

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      assert.strictEqual(store.lists.pageState[id].rules[0].id, "pre0000");

      store.lists.pageState[id].rules[0].enable = false;

      const syncing = withWindowStub(() => store.lists.requestSync(id));
      for (let i = 0; i < 6; i++) await new Promise((resolve) => setTimeout(resolve, 0));

      assert.strictEqual(
        stub.calls.filter((c) => c === pageUrl).length,
        2,
        `fixture: the done's own page request is the one in flight, got: ${stub.calls.join(", ")}`,
      );
      assert.strictEqual(
        store.lists.pageState[id]?.rules.length ?? 0,
        0,
        "the pre-sync page must be gone before the reload folds it into pendingEdits",
      );

      releasePostSyncPage();
      await syncing;

      assert.strictEqual(
        store.lists.pageState[id].rules[0].id,
        "post0000",
        "the page should be the post-sync one",
      );
      assert.deepStrictEqual(
        store.lists.ruleEdits(id),
        [],
        "no edit should survive a sync into ids the daemon has already replaced",
      );

      assert.strictEqual(
        store.lists.baselineOf(id, "pre0000"),
        undefined,
        "an id the sync discarded must not be kept in the baseline",
      );
      assert.ok(
        store.lists.baselineOf(id, "post0000"),
        "fixture: the page that did arrive is baselined",
      );
    } finally {
      stub.restore();
      if (hadConfirm) {
        (globalThis as any).confirm = originalConfirm;
      } else {
        delete (globalThis as any).confirm;
      }
    }
  });

  it("an edit folded into pendingEdits still allows Save", async () => {
    const id = "5ca0e000";
    const pageOne = {
      total: 100,
      matched: 100,
      offset: 0,
      rules: Array.from({ length: 50 }).map((_, i) => ({
        id: `c${String(i).padStart(4, "0")}`,
        enable: true,
        rule: `${i}.example.com`,
        type: "domain",
      })),
    };
    const pageTwo = {
      total: 100,
      matched: 100,
      offset: 50,
      rules: Array.from({ length: 50 }).map((_, i) => ({
        id: `c${String(50 + i).padStart(4, "0")}`,
        enable: true,
        rule: `${50 + i}.example.com`,
        type: "domain",
      })),
    };

    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: pageOne,
      [`/groups/${id}/list/rules?offset=50&limit=50`]: pageTwo,
      "/groups": { status: "ok" },
      [`/groups/${id}/list/rules?save=true`]: { status: "ok" },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 100)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      const editedRuleId = store.lists.pageState[id].rules[0].id;
      store.lists.pageState[id].rules[0].enable = false;

      await store.lists.loadRules(id, 50);
      assert.strictEqual(
        store.tracker.isDirty,
        false,
        "the tracker alone no longer knows about it (a list carries no id)",
      );
      assert.strictEqual(
        store.canSave,
        true,
        "canSave must still see the edit held in pendingEdits",
      );

      await withWindowStub(() => store.saveChanges());

      const patchRequest = stub.requests.find(
        (r) => r.path === `/groups/${id}/list/rules?save=true`,
      );
      assert.ok(patchRequest, "expected a PATCH to the list rules endpoint");
      assert.deepStrictEqual(patchRequest.body, { rules: [{ id: editedRuleId, enable: false }] });
      assert.deepStrictEqual(
        store.lists.ruleEdits(id),
        [],
        "the edit is gone once it has been saved",
      );
    } finally {
      stub.restore();
    }
  });

  it("clearing the search reloads a group's stale filtered list page", async () => {
    const id = "c1ea0000";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50&q=42`]: rulesPage(0, 50, "42"),
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      store.searchValue = "42";
      await store.lists.searchLists();
      assert.strictEqual(store.lists.pageState[id].q, "42");

      store.searchValue = "";
      await store.lists.searchLists();

      assert.ok(
        stub.calls.includes(`/groups/${id}/list/rules?offset=0&limit=50`),
        `expected the unfiltered page to be re-fetched, got: ${stub.calls.join(", ")}`,
      );
      assert.strictEqual(
        store.lists.pageState[id].q,
        "",
        "pageState.q must track the cleared query",
      );
    } finally {
      stub.restore();
    }
  });

  // No component to race against, so the guard an open-effect would run is run by hand between the calls.
  it("a page 0 load already in flight is visible to a guard checking pageState before firing again", async () => {
    const id = "a0a0a0a0";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);

      const firstLoad = store.lists.loadRules(id, 0);

      if (!store.lists.pageState[id]?.loaded) {
        store.lists.loadRules(id, 0);
      }

      await firstLoad;

      const pageRequests = stub.calls.filter(
        (c) => c === `/groups/${id}/list/rules?offset=0&limit=50`,
      );
      assert.strictEqual(
        pageRequests.length,
        1,
        `expected exactly one page-0 request, got: ${stub.calls.join(", ")}`,
      );
    } finally {
      stub.restore();
    }
  });

  // Catches a sync on a collapsed group leaving its page marked loaded, so reopening shows pre-sync rows.
  it("a sync on a collapsed group marks its list page unloaded, so the next open reloads it", async () => {
    const id = "c2c2c2c2";
    const preSyncPage = {
      total: 5,
      matched: 5,
      offset: 0,
      rules: [0, 1, 2, 3, 4].map((i) => ({
        id: `pre000${i}`,
        enable: true,
        rule: `${i}.old.example.com`,
        type: "domain",
      })),
    };

    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: preSyncPage,
      [`/groups/${id}/list/sync`]: { sync: { state: "queued", error: "", lastCheck: 0 } },
      [`/groups/${id}/list/sync/events`]: () =>
        syncDone({
          id,
          list: {
            rulesTotal: 40,
            lastUpdate: 999,
            url: `https://example.com/${id}.txt`,
            sync: { state: "idle", error: "", lastCheck: 999 },
          },
        }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);

      store.open_state[id] = true;
      await store.lists.loadRules(id, 0);
      assert.strictEqual(store.lists.pageState[id].loaded, true);
      store.open_state[id] = false;

      await withWindowStub(() => store.lists.requestSync(id));

      assert.notStrictEqual(
        store.lists.pageState[id]?.loaded,
        true,
        "a sync on a collapsed group must not leave its pre-sync page marked loaded",
      );
      assert.deepStrictEqual(
        store.lists.ruleEdits(id),
        [],
        "no edit should survive a sync while collapsed either",
      );
    } finally {
      stub.restore();
    }
  });

  it("a failed loadRules leaves pageState with loaded: false, failed: true, and does not throw", async () => {
    const id = "fa11ed00";
    const original = globalThis.fetch;
    (globalThis as any).fetch = async () => ({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      body: "",
      text: async () => "",
    });

    const originalError = console.error;
    console.error = () => {};
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);

      await withWindowStub(() => store.lists.loadRules(id, 0));

      assert.strictEqual(store.lists.pageState[id]?.loaded, false);
      assert.strictEqual(store.lists.pageState[id]?.failed, true);
    } finally {
      (globalThis as any).fetch = original;
      console.error = originalError;
    }
  });

  it("a revert to the previous query during an in-flight fetch discards the stale answer", async () => {
    const id = "5ta1e000";
    const unfilteredPage = {
      total: 3,
      matched: 3,
      offset: 0,
      rules: [0, 1, 2].map((i) => ({
        id: `plain000${i}`,
        enable: true,
        rule: `${i}.example.com`,
        type: "domain",
      })),
    };
    const staleFilteredPage = {
      total: 3,
      matched: 1,
      offset: 0,
      rules: [{ id: "stale0000", enable: true, rule: "stale.example.com", type: "domain" }],
    };

    let releaseStale!: () => void;
    const staleGate = new Promise<void>((resolve) => {
      releaseStale = resolve;
    });

    const calls: string[] = [];
    const original = globalThis.fetch;
    (globalThis as any).fetch = async (input: unknown) => {
      const url = String(input);
      const path = url.replace(/^https?:\/\/[^/]+/, "").replace(/^\/api\/v1/, "");
      calls.push(path);

      if (path === `/groups/${id}/list/rules?offset=0&limit=50&q=stale`) {
        await staleGate;
        return { ok: true, status: 200, json: async () => structuredClone(staleFilteredPage) };
      }
      if (path === `/groups/${id}/list/rules?offset=0&limit=50`) {
        return { ok: true, status: 200, json: async () => structuredClone(unfilteredPage) };
      }
      throw new Error(`unstubbed fetch: ${path}`);
    };

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 3)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      assert.strictEqual(store.lists.pageState[id].rules[0].id, "plain0000");
      assert.strictEqual(store.lists.pageState[id].q, "");

      store.searchValue = "stale";
      const inFlight = store.lists.loadRules(id, 0);

      store.searchValue = "";
      await store.lists.searchLists();

      releaseStale();
      await inFlight;

      assert.ok(
        calls.filter((c) => c === `/groups/${id}/list/rules?offset=0&limit=50`).length >= 2,
        `expected the unfiltered page to be re-requested after the revert, got: ${calls.join(", ")}`,
      );
      assert.strictEqual(
        store.lists.pageState[id].rules[0].id,
        "plain0000",
        "the abandoned filtered answer must not overwrite the reverted-to page",
      );
      assert.strictEqual(
        store.lists.pageState[id].q,
        "",
        "pageState.q must track the query actually in force, not the discarded one",
      );
    } finally {
      (globalThis as any).fetch = original;
    }
  });

  // Catches an older search run's late answer replacing a newer run's.
  it("an older search run's answer does not replace a newer one's", async () => {
    const alpha = "aaaaaaa1";
    const beta = "bbbbbbb2";
    const nothingMatched = { total: 3, matched: 0, offset: 0, rules: [] };

    let releaseFirstRun!: () => void;
    const firstRunGate = new Promise<void>((resolve) => {
      releaseFirstRun = resolve;
    });

    const calls: string[] = [];
    const original = globalThis.fetch;
    (globalThis as any).fetch = async (input: unknown) => {
      const path = String(input)
        .replace(/^https?:\/\/[^/]+/, "")
        .replace(/^\/api\/v1/, "");
      calls.push(path);
      if (path === `/groups/${beta}/list/rules?offset=0&limit=1&q=alpha`) {
        await firstRunGate;
        return { ok: true, status: 200, json: async () => structuredClone(nothingMatched) };
      }
      if (path.endsWith("q=alpha") || path.endsWith("q=zzz")) {
        return { ok: true, status: 200, json: async () => structuredClone(nothingMatched) };
      }
      throw new Error(`unstubbed fetch: ${path}`);
    };

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(alpha, 3), makeGroup(beta, 3)]);

      store.searchValue = "alpha";
      const older = store.lists.searchLists();

      store.searchValue = "zzz";
      const newer = await store.lists.searchLists();
      assert.deepStrictEqual(Array.from(newer), [], "fixture: the newer run matched nothing");

      releaseFirstRun();
      const olderResult = await older;

      assert.deepStrictEqual(
        Array.from(olderResult),
        [],
        "the older run answers for itself and must not be read after a newer one has landed",
      );
    } finally {
      (globalThis as any).fetch = original;
    }
  });

  // Catches a failed search request silently dropping the group instead of presuming it matched.
  it("a search request that fails leaves the group presumed matched and says so", async () => {
    const id = "fa11ed01";
    const original = globalThis.fetch;
    (globalThis as any).fetch = async (input: unknown) => {
      const path = String(input);
      if (path.includes("q=42")) {
        return {
          ok: false,
          status: 500,
          statusText: "Internal Server Error",
          body: "",
          text: async () => "",
        };
      }
      throw new Error(`unstubbed fetch: ${path}`);
    };
    const originalError = console.error;
    console.error = () => {};

    try {
      const store = new GroupsStore();
      const group = makeGroup(id, 120);
      seed(store, [group]);

      await withWindowStub(async (toasts) => {
        store.searchValue = "42";
        const matched = await store.lists.searchLists();

        assert.ok(
          matched.has(id),
          "a group whose list the search could not ask about must not be hidden as a non-match",
        );
        assert.deepStrictEqual(
          toasts.filter((entry) => entry.content.startsWith("Search failed for")),
          [{ type: "error", content: `Search failed for ${group.name}` }],
          "and the run says so once, naming the group",
        );
      });
    } finally {
      (globalThis as any).fetch = original;
      console.error = originalError;
    }
  });

  it("a collapsed group is counted, never paged", async () => {
    const named = "c0115ed0";
    const other = "c0115ed1";
    const stub = installFetchStub({
      [`/groups/${named}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
      [`/groups/${other}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
      [`/groups/${named}/list/rules?offset=0&limit=1&q=foo`]: rulesPage(0, 1, "foo"),
      [`/groups/${other}/list/rules?offset=0&limit=1&q=foo`]: rulesPage(0, 1, "foo"),
      [`/groups/${named}/list/rules?offset=0&limit=50&q=foo`]: rulesPage(0, 50, "foo"),
      [`/groups/${other}/list/rules?offset=0&limit=50&q=foo`]: rulesPage(0, 50, "foo"),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(named, 120), makeGroup(other, 120)]);

      for (const id of [named, other]) {
        store.open_state[id] = true;
        await store.lists.loadRules(id, 0);
        store.open_state[id] = false;
      }

      store.searchValue = "foo";
      await store.lists.searchLists();

      assert.deepStrictEqual(stub.calls, [
        `/groups/${named}/list/rules?offset=0&limit=50`,
        `/groups/${other}/list/rules?offset=0&limit=50`,
        `/groups/${named}/list/rules?offset=0&limit=1&q=foo`,
        `/groups/${other}/list/rules?offset=0&limit=1&q=foo`,
      ]);

      for (const id of [named, other]) {
        assert.notStrictEqual(
          store.lists.pageState[id]?.loaded,
          true,
          `the page ${id} was holding answers the old query, so the next open must ask again`,
        );
      }
    } finally {
      stub.restore();
    }
  });

  it("clearing the search drops a collapsed group's filtered list page rather than refetching it", async () => {
    const id = "c1ea0001";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50&q=foo`]: rulesPage(0, 50, "foo"),
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      store.searchValue = "foo";
      await store.lists.searchLists();
      assert.strictEqual(store.lists.pageState[id].q, "foo", "fixture: it holds a filtered page");

      store.open_state[id] = false;
      store.searchValue = "";
      await store.lists.searchLists();

      assert.deepStrictEqual(
        stub.calls,
        [`/groups/${id}/list/rules?offset=0&limit=50&q=foo`],
        "clearing the box must not fetch a page for a panel nobody has open",
      );
      assert.strictEqual(
        store.lists.pageState[id],
        undefined,
        "and what it was holding is gone, so the next open asks for an unfiltered page",
      );
    } finally {
      stub.restore();
    }
  });

  it("a first page loaded under a search shows the list's own count until the answer lands", async () => {
    const id = "5eed0000";
    let releasePage!: () => void;
    const pageGate = new Promise<void>((resolve) => {
      releasePage = resolve;
    });

    const original = globalThis.fetch;
    (globalThis as any).fetch = async (input: unknown) => {
      const path = String(input);
      if (path.includes("q=42")) {
        await pageGate;
        return { ok: true, status: 200, json: async () => structuredClone(rulesPage(0, 50, "42")) };
      }
      throw new Error(`unstubbed fetch: ${path}`);
    };

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;
      store.searchValue = "42";

      const inFlight = store.lists.loadRules(id, 0);
      assert.strictEqual(
        store.lists.pageState[id].q,
        "42",
        "fixture: the seed answers for the query in force",
      );
      assert.strictEqual(
        store.lists.pageState[id].matched,
        120,
        "until the daemon answers, the count is the whole list, not zero",
      );

      releasePage();
      await inFlight;

      assert.strictEqual(
        store.lists.pageState[id].matched,
        1,
        "and then it is what the daemon matched",
      );
    } finally {
      (globalThis as any).fetch = original;
    }
  });

  // Catches forget() leaving offset, count, pending edits, baseline, counter or query behind.
  it("forget() leaves nothing of the group's list behind", async () => {
    const id = "de1e7ed0";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
      [`/groups/${id}/list/rules?offset=50&limit=50`]: rulesPage(50, 50),
      [`/groups/${id}/list/rules?offset=0&limit=50&q=42`]: rulesPage(0, 50, "42"),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      await store.lists.loadRules(id, 50);
      store.searchValue = "42";
      await store.lists.searchLists();

      assert.notStrictEqual(
        store.lists.baselineOf(id, "rule0050"),
        undefined,
        "fixture: a baseline was taken",
      );
      assert.ok(store.lists.pageState[id], "fixture: a page was loaded");

      store.lists.forget(id);

      assert.strictEqual(store.lists.pageState[id], undefined, "no page state");
      assert.strictEqual(store.lists.baselineOf(id, "rule0050"), undefined, "no rule baseline");
      assert.deepStrictEqual(store.lists.ruleEdits(id), [], "no pending edits");

      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;
      const before = stub.calls.filter(
        (c) => c === `/groups/${id}/list/rules?offset=0&limit=50&q=42`,
      ).length;
      store.searchValue = "42";
      await store.lists.searchLists();
      assert.strictEqual(
        stub.calls.filter((c) => c === `/groups/${id}/list/rules?offset=0&limit=50&q=42`).length,
        before + 1,
        "a group arriving under a forgotten id must be asked about the query in force",
      );
    } finally {
      stub.restore();
    }
  });

  it("an edit undone leaves nothing to save", async () => {
    const id = "und0ed00";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
      [`/groups/${id}/list/rules?offset=50&limit=50`]: rulesPage(50, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;

      await store.lists.loadRules(id, 50);
      assert.strictEqual(store.canSave, true, "fixture: the edit is real while it stands");
      await store.lists.loadRules(id, 0);
      assert.strictEqual(
        store.lists.pageState[id].rules[0].enable,
        false,
        "fixture: it came back with the page",
      );

      store.lists.pageState[id].rules[0].enable = true;

      assert.deepStrictEqual(
        store.lists.ruleEdits(id),
        [],
        "fixture: nothing differs from the daemon's page any more",
      );
      assert.strictEqual(
        store.canSave,
        false,
        "an undone edit must not leave Save enabled for a full config.yaml write that PATCHes nothing",
      );
    } finally {
      stub.restore();
    }
  });

  // Catches mount() choking on a list sent without rules, or loading a page for it unasked.
  it("a group whose list the daemon sends without rules starts with no page loaded", async () => {
    const id = "a11e0000";
    const stub = installFetchStub({
      "/groups?with_rules=true": {
        groups: [
          {
            id,
            name: "no-rules-here",
            interface: "",
            enable: true,
            devices: { allow: [], deny: [] },
            rules: [],
            list: {
              url: "https://example.com/no-rules.txt",
              rulesTotal: 12,
              lastUpdate: 5,
              interval: 86400,
              sync: { state: "idle", error: "", lastCheck: 0 },
            },
          },
        ],
      },
    });

    try {
      const store = new GroupsStore();
      await withWindowStub(() => store.mount());

      const group = store.tracker.data.find((g: any) => g.id === id);
      assert.ok(group, "fixture: the record is on the page");
      assert.strictEqual(group.list.rulesTotal, 12, "the count the daemon sent is kept");
      assert.strictEqual(
        store.lists.pageState[id],
        undefined,
        "no page is loaded until loadRules is called",
      );
    } finally {
      stub.restore();
    }
  });

  // Catches a Save PATCHing rule ids that a running sync is about to discard.
  it("a Save is held back while a sync is replacing the rules it would PATCH", async () => {
    const id = "5ync0000";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      assert.strictEqual(store.canSave, true, "fixture: the edit is saveable while nothing syncs");

      const group = store.data.find((g: any) => g.id === id);
      group.list.sync = { state: "fetching", error: "", lastCheck: 0 };
      assert.ok(store.lists.syncBlockingSave, "the sync in flight is named");
      assert.strictEqual(store.canSave, false, "and Save is held back while it runs");

      group.list.sync = { state: "idle", error: "", lastCheck: 1 };
      assert.strictEqual(store.canSave, true, "and reachable again once it has ended");
    } finally {
      stub.restore();
    }
  });

  // Catches a sync silently throwing away an unsaved rule edit.
  it("a sync asks before it throws an unsaved rule edit away", async () => {
    const id = "c0nf1rm0";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(0, 50),
      [`/groups/${id}/list/sync`]: { sync: { state: "queued", error: "", lastCheck: 0 } },
      [`/groups/${id}/list/sync/events`]: () =>
        syncDone({
          id,
          list: {
            rulesTotal: 120,
            lastUpdate: 999,
            url: `https://example.com/${id}.txt`,
            sync: { state: "idle", error: "", lastCheck: 999 },
          },
        }),
    });

    const asked: string[] = [];
    let answer = false;
    const hadConfirm = "confirm" in globalThis;
    const originalConfirm = (globalThis as any).confirm;
    (globalThis as any).confirm = (message: string) => {
      asked.push(message);
      return answer;
    };

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      assert.strictEqual(store.lists.ruleEdits(id).length, 1, "fixture: there is an edit to lose");

      await withWindowStub(() => store.lists.requestSync(id));

      assert.deepStrictEqual(asked, ["Unsaved rule edits will be lost by the sync. Continue?"]);
      assert.ok(
        !stub.calls.includes(`/groups/${id}/list/sync`),
        `a declined sync must not be asked for, got: ${stub.calls.join(", ")}`,
      );
      assert.strictEqual(store.lists.ruleEdits(id).length, 1, "and the edit is still there");

      answer = true;
      await withWindowStub(() => store.lists.requestSync(id));

      assert.strictEqual(asked.length, 2, "fixture: asked again");
      assert.ok(
        stub.calls.includes(`/groups/${id}/list/sync`),
        "an accepted sync goes out as it always did",
      );
    } finally {
      stub.restore();
      if (hadConfirm) {
        (globalThis as any).confirm = originalConfirm;
      } else {
        delete (globalThis as any).confirm;
      }
    }
  });

  // Catches an open group's page.q not tracking each new query, even when its name already matches.
  it("an open group's list page tracks each new query in turn", async () => {
    const id = "name0001";
    const pageForFoo = {
      total: 3,
      matched: 0,
      offset: 0,
      rules: [{ id: "foo0000", enable: true, rule: "unrelated.example.com", type: "domain" }],
    };
    const pageForOob = {
      total: 3,
      matched: 0,
      offset: 0,
      rules: [{ id: "oob0000", enable: true, rule: "unrelated.example.com", type: "domain" }],
    };

    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50&q=foo`]: pageForFoo,
      [`/groups/${id}/list/rules?offset=0&limit=50&q=oob`]: pageForOob,
    });

    try {
      const store = new GroupsStore();
      const group = makeGroup(id, 3) as any;
      group.name = "foobar-list";
      seed(store, [group]);
      store.open_state[id] = true;

      store.searchValue = "foo";
      await store.lists.searchLists();
      assert.strictEqual(store.lists.pageState[id].q, "foo");
      assert.ok(stub.calls.includes(`/groups/${id}/list/rules?offset=0&limit=50&q=foo`));

      store.searchValue = "oob";
      await store.lists.searchLists();
      assert.strictEqual(
        store.lists.pageState[id].q,
        "oob",
        "an open group's page must stay in sync with the current query",
      );
      assert.ok(stub.calls.includes(`/groups/${id}/list/rules?offset=0&limit=50&q=oob`));
    } finally {
      stub.restore();
    }
  });

  // Catches overwriteGroups leaving replaced groups' list state and sync streams behind.
  it("overwriteGroups forgets every replaced group's list", async () => {
    const id = "01d0001d";
    let syncEventsSignal: AbortSignal | undefined;
    const original = globalThis.fetch;
    (globalThis as any).fetch = async (input: unknown, init?: { signal?: AbortSignal }) => {
      const path = String(input)
        .replace(/^https?:\/\/[^/]+/, "")
        .replace(/^\/api\/v1/, "");
      if (path === `/groups/${id}/list/rules?offset=0&limit=50`) {
        return { ok: true, status: 200, json: async () => structuredClone(rulesPage(0, 50)) };
      }
      if (path === `/groups/${id}/list/sync/events`) {
        syncEventsSignal = init?.signal;
        return new Promise(() => {});
      }
      throw new Error(`unstubbed fetch: ${path}`);
    };

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 120)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      void store.lists.followSync(id);
      await Promise.resolve();
      assert.ok(syncEventsSignal, "fixture: the follow opened a stream");
      assert.strictEqual(syncEventsSignal!.aborted, false, "fixture: not aborted yet");

      assert.strictEqual(store.lists.hasPendingEdits, true, "fixture: an edit is pending");

      await store.overwriteGroups([]);

      assert.strictEqual(
        syncEventsSignal!.aborted,
        true,
        "the follow for a group the import replaced must be aborted",
      );
      assert.strictEqual(store.lists.pageState[id], undefined, "no page state survives the import");
      assert.deepStrictEqual(store.lists.ruleEdits(id), [], "no pending edits survive it either");
      assert.strictEqual(
        store.lists.hasPendingEdits,
        false,
        "no list edit for a card that is gone must go on asking for a PATCH",
      );
    } finally {
      (globalThis as any).fetch = original;
    }
  });
});
