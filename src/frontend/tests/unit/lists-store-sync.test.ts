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
const { syncProgressLabel } = await import("../../src/modules/groups/lists.svelte");
if (processObj) {
  if (originalProcessEnvDescriptor) {
    Object.defineProperty(processObj, "env", originalProcessEnvDescriptor);
  } else {
    delete processObj.env;
  }
}
restoreLocalStorage();

const { token } = await import("../../src/data/auth.svelte");

type Answer = { status?: number; json?: unknown; body?: ReadableStream<Uint8Array> };
type Init = {
  method?: string;
  body?: string;
  headers?: Record<string, unknown>;
  signal?: AbortSignal;
};
type Handler = Answer | ((init: Init) => Answer | Promise<Answer>);

function installFetchStub(handlers: Record<string, Handler>) {
  const calls: string[] = [];
  const requests: { path: string; body?: unknown }[] = [];
  const headers: Record<string, unknown>[] = [];
  const original = globalThis.fetch;

  (globalThis as any).fetch = async (input: unknown, init?: Init) => {
    const url = String(input);
    const path = url.replace(/^https?:\/\/[^/]+/, "").replace(/^\/api\/v1/, "");
    calls.push(path);
    requests.push({ path, body: init?.body !== undefined ? JSON.parse(init.body) : undefined });
    headers.push(init?.headers ?? {});

    if (!(path in handlers)) {
      throw new Error(`unstubbed fetch: ${path}`);
    }

    const registered = handlers[path];
    const answer = await (typeof registered === "function" ? registered(init ?? {}) : registered);
    const status = answer.status ?? 200;

    return {
      ok: status >= 200 && status <= 299,
      status,
      statusText: "",
      body: answer.body,
      text: async () => "",
      json: async () => structuredClone(answer.json),
    };
  };

  return {
    calls,
    requests,
    headers,
    restore: () => {
      (globalThis as any).fetch = original;
    },
  };
}

function syncStreams() {
  const encoder = new TextEncoder();
  const sources: {
    body: ReadableStream<Uint8Array>;
    emit: (event: string, data: unknown) => void;
    close: () => void;
    fail: () => void;
  }[] = [];
  let waiters: (() => void)[] = [];

  const create = (signal?: AbortSignal) => {
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const body = new ReadableStream<Uint8Array>({
      start: (c) => {
        controller = c;
      },
    });
    signal?.addEventListener("abort", () => {
      try {
        controller.error(new Error("aborted"));
      } catch {
        /* already closed */
      }
    });
    const source = {
      body,
      emit: (event: string, data: unknown) =>
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)),
      close: () => controller.close(),
      fail: () => controller.error(new Error("stream dropped")),
    };
    sources.push(source);
    const woken = waiters;
    waiters = [];
    for (const wake of woken) wake();
    return source;
  };

  const open = async (n: number) => {
    while (sources.length < n) {
      await new Promise<void>((resolve) => waiters.push(resolve));
    }
    return sources[n - 1];
  };

  return {
    body: (signal?: AbortSignal) => create(signal).body,
    open,
    get count() {
      return sources.length;
    },
  };
}

async function settle(rounds = 3, ms = 0) {
  for (let i = 0; i < rounds; i++) {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}

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

const listRecord = (id: string, state = "idle", rulesTotal = 0) => ({
  id,
  list: {
    url: `https://example.com/${id}.txt`,
    interval: 86400,
    lastUpdate: 1700000000,
    rulesTotal,
    sync: { state, error: "", lastCheck: 1700000000 },
  },
});

const makeGroup = (id: string, rulesTotal = 0) => ({
  id,
  name: `group-${id}`,
  interface: "",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  list: {
    url: `https://example.com/${id}.txt`,
    interval: 86400,
    lastUpdate: 1700000000,
    rulesTotal,
    sync: { state: "idle", error: "", lastCheck: 1700000000 },
  },
});

const rulesPage = (count: number) => ({
  total: count,
  matched: count,
  offset: 0,
  rules: Array.from({ length: count }).map((_, i) => ({
    id: `rule000${i}`,
    enable: true,
    rule: `${i}.example.com`,
    type: "domain",
  })),
});

function seed(store: any, groups: ReturnType<typeof makeGroup>[]) {
  const cloned = structuredClone(groups);
  store.tracker.reset(cloned);
  store.resetListMetaBaseline(cloned);
}

describe("a group's list, synced over its event stream", () => {
  it("a 202 opens the stream and a done event applies the record and reloads page 0", async () => {
    const id = "a1b2c3d4";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: { status: 202, json: listRecord(id, "queued") },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      [`/groups/${id}/list/rules?offset=0&limit=50`]: { json: rulesPage(3) },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.open_state[id] = true;

      await withWindowStub(async (toasts) => {
        const pending = store.lists.requestSync(id);
        const source = await streams.open(1);
        source.emit("done", {
          ...listRecord(id, "idle", 3),
          list: { ...listRecord(id, "idle", 3).list, lastUpdate: 1800000000 },
        });
        source.close();
        await pending;

        const group = store.data[0];
        assert.strictEqual(group.list.rulesTotal, 3);
        assert.strictEqual(group.list.lastUpdate, 1800000000);
        assert.strictEqual(group.list.sync.state, "idle");
        assert.strictEqual(
          store.lists.pageState[id].rules.length,
          3,
          "the page the done event asked for",
        );
        assert.strictEqual(store.lists.pageState[id].offset, 0);
        assert.ok(
          stub.calls.includes(`/groups/${id}/list/rules?offset=0&limit=50`),
          "the done event reloads page 0",
        );
        assert.strictEqual(streams.count, 1, "one stream, closed on done, never reopened");
        assert.strictEqual(store.lists.syncProgress[id], undefined, "the progress is over");
        assert.deepStrictEqual(
          toasts.map((t) => `${t.type}:${t.content}`),
          ["success:Synced"],
        );
        assert.strictEqual(store.canSave, false, "a synced record is not an unsaved edit");
      });
    } finally {
      stub.restore();
    }
  });

  it("progress events are visible while the stream is open", async () => {
    const id = "b2c3d4e5";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: { status: 202, json: listRecord(id, "queued") },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);

      await withWindowStub(async () => {
        const pending = store.lists.requestSync(id);
        const source = await streams.open(1);

        source.emit("progress", { stage: "fetch", bytes: 100, total: 200 });
        await settle();
        assert.deepStrictEqual(store.lists.syncProgress[id], {
          stage: "fetch",
          bytes: 100,
          total: 200,
          lines: 0,
        });

        source.emit("progress", { stage: "parse", lines: 20000 });
        await settle();
        assert.strictEqual(store.lists.syncProgress[id].stage, "parse");
        assert.strictEqual(store.lists.syncProgress[id].lines, 20000);

        source.emit("done", listRecord(id, "idle"));
        source.close();
        await pending;

        assert.strictEqual(
          store.lists.syncProgress[id],
          undefined,
          "a finished sync leaves no progress behind",
        );
      });
    } finally {
      stub.restore();
    }
  });

  it("an error event toasts and leaves the state error", async () => {
    const id = "c3d4e5f6";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: { status: 202, json: listRecord(id, "queued") },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.open_state[id] = true;

      await withWindowStub(async (toasts) => {
        const pending = store.lists.requestSync(id);
        const source = await streams.open(1);
        source.emit("error", { error: "fetch failed: HTTP 404" });
        source.close();
        await pending;

        const group = store.data[0];
        assert.strictEqual(group.list.sync.state, "error");
        assert.strictEqual(group.list.sync.error, "fetch failed: HTTP 404");
        assert.deepStrictEqual(
          toasts.map((t) => `${t.type}:${t.content}`),
          ["error:Sync failed: fetch failed: HTTP 404"],
        );
        assert.ok(
          !stub.calls.some((c) => c.includes("/list/rules")),
          "a sync that failed replaced no rules, so nothing is reloaded",
        );
        assert.strictEqual(store.canSave, false, "the failure is not an unsaved edit");
      });
    } finally {
      stub.restore();
    }
  });

  it("a dropped stream is reopened once and the restated state is applied", async () => {
    const id = "d4e5f6a7";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: { status: 202, json: listRecord(id, "queued") },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 150;

      const originalError = console.error;
      console.error = () => {};
      await withWindowStub(async () => {
        const pending = store.lists.requestSync(id);
        const first = await streams.open(1);
        first.emit("progress", { stage: "fetch", bytes: 10, total: 100 });
        await settle();
        first.fail();
        await settle();

        assert.strictEqual(streams.count, 1, "the reopen waits rather than spinning");

        const second = await streams.open(2);
        second.emit("done", listRecord(id, "idle", 7));
        second.close();
        await pending;

        assert.strictEqual(store.data[0].list.rulesTotal, 7);
        assert.strictEqual(streams.count, 2, "reopened once");
      });
      console.error = originalError;
    } finally {
      stub.restore();
    }
  });

  it("a second followSync for the same id shares the stream", async () => {
    const id = "e5f6a7b8";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);

      await withWindowStub(async (toasts) => {
        const first = store.lists.followSync(id);
        const second = store.lists.followSync(id);
        const source = await streams.open(1);
        source.emit("done", listRecord(id, "idle"));
        source.close();
        await Promise.all([first, second]);

        assert.strictEqual(streams.count, 1, "one stream for two followers");
        assert.strictEqual(toasts.length, 1, "and one toast");
      });
    } finally {
      stub.restore();
    }
  });

  it("a destroyed store lets its stream go and does not reopen it", async () => {
    const id = "f6a7b8c9";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 20;

      await withWindowStub(async (toasts) => {
        const pending = store.lists.followSync(id);
        const source = await streams.open(1);
        source.emit("progress", { stage: "fetch", bytes: 10, total: 100 });
        await settle();

        store.destroy();
        await pending;
        await settle(3, 40);

        assert.strictEqual(streams.count, 1, "the abort is not a drop to reopen after");
        assert.strictEqual(toasts.length, 0, "and nothing is reported about it");
      });
    } finally {
      stub.restore();
    }
  });

  // Catches forget() reporting the 404 of a stream the daemon ended for a removed group, or reopening it.
  it("forget() stops following a group's sync and reports nothing about it", async () => {
    const id = "b8c9d0e1";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 20;

      await withWindowStub(async (toasts) => {
        const pending = store.lists.followSync(id);
        const source = await streams.open(1);
        source.emit("progress", { stage: "fetch", bytes: 10, total: 100 });
        await settle();
        assert.ok(store.lists.syncProgress[id], "fixture: the bar is being drawn for this id");

        store.lists.forget(id);

        const ended = await Promise.race([
          pending.then(() => true),
          settle(4, 40).then(() => false),
        ]);

        assert.ok(ended, "the follow ended instead of going on watching a forgotten id");
        assert.strictEqual(streams.count, 1, "and it was not reopened for that id either");
        assert.strictEqual(
          store.lists.syncProgress[id],
          undefined,
          "and no bar is left behind for it",
        );
        assert.deepStrictEqual(toasts, [], "a sync ended by forget() is not reported as a failure");
      });
    } finally {
      stub.restore();
    }
  });

  it("a sync the page lost for good is said, and the record is re-read", async () => {
    const id = "a7b8c9d0";
    const streams = syncStreams();
    let listReads = 0;
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: { status: 202, json: listRecord(id, "queued") },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups": () => {
        listReads++;
        return { json: { groups: [makeGroup(id, 9)] } };
      },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 20;

      const originalError = console.error;
      console.error = () => {};
      await withWindowStub(async (toasts) => {
        const pending = store.lists.requestSync(id);
        (await streams.open(1)).fail();
        (await streams.open(2)).fail();
        await pending;
        await settle(3, 40);

        assert.strictEqual(streams.count, 2, "two attempts, not a reconnect loop");
        assert.strictEqual(listReads, 1, "the record is re-read exactly once");
        assert.strictEqual(store.data[0].list.rulesTotal, 9);
        assert.strictEqual(store.data[0].list.sync.state, "idle", "no longer stuck at queued");
        assert.deepStrictEqual(
          toasts.map((t) => `${t.type}:${t.content}`),
          ["error:Sync connection lost"],
        );
        assert.strictEqual(store.lists.syncProgress[id], undefined);
        assert.strictEqual(store.canSave, false, "a re-read record is not an unsaved edit");
      });
      console.error = originalError;
    } finally {
      stub.restore();
    }
  });

  // Catches saveChanges rolling a done applied mid-Save back to the pre-sync count and page.
  it("a done applied during a Save is not undone by it", async () => {
    const id = "b8c9d0e1";
    const streams = syncStreams();
    const page = (offset: number, prefix: string, total: number, count: number) => ({
      total,
      matched: total,
      offset,
      rules: Array.from({ length: count }).map((_, i) => ({
        id: `${prefix}${String(offset + i).padStart(4, "0")}`,
        enable: true,
        rule: `${offset + i}.example.com`,
        type: "domain",
      })),
    });

    let synced = false;
    let releasePut!: () => void;
    const putHeld = new Promise<void>((resolve) => (releasePut = resolve));

    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: () => ({
        json: synced ? page(0, "post", 5, 5) : page(0, "pre", 100, 50),
      }),
      [`/groups/${id}/list/rules?offset=50&limit=50`]: () => ({
        json: page(50, "pre", 100, 50),
      }),
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups": async () => {
        await putHeld;
        return { json: { status: "ok" } };
      },
      [`/groups/${id}/list/rules?save=true`]: { json: { status: "ok" } },
    });

    try {
      const store = new GroupsStore();
      const group = makeGroup(id, 100);
      seed(store, [group]);
      store.open_state[id] = true;

      await withWindowStub(async () => {
        await store.lists.loadRules(id, 0);
        store.lists.pageState[id].rules[0].enable = false;
        await store.lists.loadRules(id, 50);
        assert.strictEqual(store.canSave, true);

        const follow = store.lists.followSync(id);
        const source = await streams.open(1);

        const saving = store.saveChanges();
        await settle();

        synced = true;
        source.emit("done", {
          ...listRecord(id, "idle", 5),
          list: { ...listRecord(id, "idle", 5).list, lastUpdate: 1800000000 },
        });
        source.close();
        await follow;

        assert.strictEqual(store.data[0].list.rulesTotal, 5, "the done landed");

        releasePut();
        await saving;

        assert.strictEqual(store.data[0].list.rulesTotal, 5, "and the Save did not roll it back");
        assert.strictEqual(store.data[0].list.lastUpdate, 1800000000);
        assert.strictEqual(store.data[0].list.sync.state, "idle");
        assert.strictEqual(
          store.lists.pageState[id].rules[0].id,
          "post0000",
          "nor the page it loaded",
        );
        assert.strictEqual(store.lists.pageState[id].offset, 0);
      });
    } finally {
      stub.restore();
    }
  });

  it("the stream fetch carries the session's bearer token", async () => {
    const id = "c9d0e1f2";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      token.current = "session-token";

      await withWindowStub(async () => {
        const follow = store.lists.followSync(id);
        const source = await streams.open(1);
        source.emit("done", listRecord(id, "idle"));
        source.close();
        await follow;

        const at = stub.calls.indexOf(`/groups/${id}/list/sync/events`);
        assert.deepStrictEqual(stub.headers[at], { Authorization: "Bearer session-token" });
      });
    } finally {
      token.reset();
      stub.restore();
    }
  });

  it("a 401 on the stream resets the session and does not reopen", async () => {
    const id = "d0e1f2a3";
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: { status: 401 },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 20;
      token.current = "stale-token";

      await withWindowStub(async () => {
        await store.lists.followSync(id);
        await settle(3, 40);

        assert.strictEqual(token.current, undefined, "the session is thrown away");
        assert.strictEqual(
          stub.calls.filter((c) => c.endsWith("/sync/events")).length,
          1,
          "and not asked again with it",
        );
      });
    } finally {
      token.reset();
      stub.restore();
    }
  });

  it("a 401 on the reopened stream leaves no bar behind", async () => {
    const id = "d0e1f2a4";
    const streams = syncStreams();
    let opens = 0;
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => {
        opens++;
        return opens === 1 ? { body: streams.body(init.signal) } : { status: 401 };
      },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.lists.syncReopenMs = 20;
      token.current = "stale-token";

      const originalError = console.error;
      console.error = () => {};
      await withWindowStub(async () => {
        const pending = store.lists.followSync(id);
        const source = await streams.open(1);
        source.emit("progress", { stage: "fetch", bytes: 10, total: 100 });
        await settle();
        assert.ok(store.lists.syncProgress[id], "fixture: the bar is being drawn for this id");

        source.fail();
        await pending;
        await settle();

        assert.strictEqual(opens, 2, "fixture: the drop was reopened, and that reopen got the 401");
        assert.strictEqual(token.current, undefined, "fixture: the session was thrown away");
        assert.strictEqual(
          store.lists.syncProgress[id],
          undefined,
          "a refused reopen must leave no bar behind either",
        );
      });
      console.error = originalError;
    } finally {
      token.reset();
      stub.restore();
    }
  });

  it("a destroyed store follows nothing more", async () => {
    const id = "e1f2a3b4";
    const stub = installFetchStub({});

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.destroy();

      await withWindowStub(async () => {
        await store.lists.followSync(id);
        await settle();
      });

      assert.deepStrictEqual(
        stub.calls,
        [],
        "a store that has been torn down must not open a stream",
      );
    } finally {
      stub.restore();
    }
  });

  // Catches a re-read of a still queued or fetching sync being applied as done.
  it("a re-read that finds the sync still running does not apply it as done", async () => {
    const id = "5411c0de";
    const pageUrl = `/groups/${id}/list/rules?offset=0&limit=50`;
    const streams = syncStreams();
    let listReads = 0;
    const stub = installFetchStub({
      [pageUrl]: { json: rulesPage(3) },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups": () => {
        listReads++;
        return {
          json: {
            groups: [makeGroup(id, 4)].map((g) => ({
              ...g,
              list: { ...g.list, sync: { state: "fetching", error: "", lastCheck: 1700000000 } },
            })),
          },
        };
      },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 3)]);
      store.open_state[id] = true;
      store.lists.syncReopenMs = 20;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      assert.strictEqual(store.lists.ruleEdits(id).length, 1, "fixture: an edit is waiting");

      const originalError = console.error;
      console.error = () => {};
      await withWindowStub(async (toasts) => {
        const follow = store.lists.followSync(id);
        (await streams.open(1)).fail();
        (await streams.open(2)).fail();
        await follow;
        await settle(3, 40);

        assert.strictEqual(listReads, 1, "fixture: the record was re-read exactly once");
        assert.deepStrictEqual(
          toasts.map((entry) => entry.content),
          ["Sync connection lost"],
          "fixture: this is the lost-stream path",
        );

        assert.strictEqual(
          store.data[0].list.sync.state,
          "fetching",
          "the record says what the daemon says",
        );
        assert.strictEqual(
          stub.calls.filter((c) => c === pageUrl).length,
          1,
          "but no page is re-read for a list that has not arrived",
        );
        assert.strictEqual(store.data[0].list.rulesTotal, 3, "and the count is left where it was");
        assert.strictEqual(
          store.lists.ruleEdits(id).length,
          1,
          "and the edit waiting on that page is still there",
        );
      });
      console.error = originalError;
    } finally {
      stub.restore();
    }
  });

  // Catches a page loaded mid-sync (second tab, reload) sitting on rulesTotal 0 until reloaded.
  it("groups loaded with a list queued or fetching are followed on mount", async () => {
    const streams = syncStreams();
    const stub = installFetchStub({
      "/groups?with_rules=true": {
        json: {
          groups: [
            makeGroup("aaaaaaa1", 0),
            {
              ...makeGroup("aaaaaaa2", 0),
              list: {
                ...makeGroup("aaaaaaa2").list,
                sync: { state: "queued", error: "", lastCheck: 0 },
              },
            },
            {
              ...makeGroup("aaaaaaa3", 0),
              list: {
                ...makeGroup("aaaaaaa3").list,
                sync: { state: "fetching", error: "", lastCheck: 0 },
              },
            },
          ],
        },
      },
      "/groups/aaaaaaa2/list/sync/events": (init) => ({ body: streams.body(init.signal) }),
      "/groups/aaaaaaa3/list/sync/events": (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();

      await withWindowStub(async () => {
        await store.mount();
        await settle(3, 20);

        assert.deepStrictEqual(
          stub.calls.filter((c) => c.endsWith("/sync/events")).sort(),
          ["/groups/aaaaaaa2/list/sync/events", "/groups/aaaaaaa3/list/sync/events"],
          "the two running syncs are followed and the idle one is not",
        );

        for (let n = 1; n <= streams.count; n++) {
          const source = await streams.open(n);
          source.emit("error", { error: "stopped" });
          source.close();
        }
        await settle();
      });
    } finally {
      stub.restore();
    }
  });
});

describe("a Save that starts a sync", () => {
  const queuedRecord = (id: string, url: string) => ({
    ...makeGroup(id),
    list: {
      url,
      interval: 86400,
      lastUpdate: 0,
      rulesTotal: 0,
      sync: { state: "queued", error: "", lastCheck: 0 },
    },
  });

  // Catches saveChanges not reading the PUT's answer, so no stream opens for the added list.
  it("a list added by the Save is followed without a Sync click", async () => {
    const id = "5a0e0001";
    const url = "https://example.com/new.txt";
    const streams = syncStreams();
    const stub = installFetchStub({
      "/groups?save=true": { json: { groups: [queuedRecord(id, url)] } },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      [`/groups/${id}/list/rules?offset=0&limit=50`]: { json: rulesPage(3) },
    });

    try {
      const store = new GroupsStore();
      const { list: _list, ...bare } = makeGroup(id);
      seed(store, [bare as any]);
      store.open_state[id] = true;
      store.data[0].list = {
        url,
        interval: 86400,
        lastUpdate: 0,
        rulesTotal: 0,
        sync: { state: "idle", error: "", lastCheck: 0 },
      };
      assert.strictEqual(store.canSave, true, "fixture: attaching a list makes Save reachable");

      await withWindowStub(async (toasts) => {
        await store.saveChanges();
        assert.strictEqual(store.data[0].list.sync.state, "queued", "the answer's state, applied");

        const source = await streams.open(1);
        source.emit("done", {
          ...queuedRecord(id, url),
          list: { ...listRecord(id, "idle", 3).list, url },
        });
        source.close();
        await settle(3, 10);

        assert.strictEqual(store.data[0].list.rulesTotal, 3);
        assert.strictEqual(store.lists.pageState[id].rules.length, 3, "the list's rules appear");
        assert.deepStrictEqual(
          toasts.map((t) => `${t.type}:${t.content}`),
          ["success:Saved", "success:Synced"],
        );
        assert.strictEqual(store.canSave, false);
      });
    } finally {
      stub.restore();
    }
  });

  // Catches the Save's own superseded sync being toasted as "Sync failed: list url changed".
  it("the old url's sync ended by the Save is not reported as failed", async () => {
    const id = "5a0e0002";
    const next = "https://example.com/next.txt";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups?save=true": async () => {
        const old = await streams.open(1);
        old.emit("error", { error: "list url changed" });
        old.close();
        await settle();
        return { json: { groups: [queuedRecord(id, next)] } };
      },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);
      store.data[0].list.sync = { state: "fetching", error: "", lastCheck: 0 };
      void store.lists.followSync(id);
      await streams.open(1);
      store.setListUrl(id, next);

      await withWindowStub(async (toasts) => {
        await store.saveChanges();
        const fresh = await streams.open(2);

        assert.deepStrictEqual(
          toasts.map((t) => `${t.type}:${t.content}`),
          ["success:Saved"],
          "no Sync failed for the sync the Save replaced",
        );
        assert.strictEqual(store.data[0].list.sync.state, "queued");
        assert.strictEqual(store.data[0].list.url, next);
        assert.strictEqual(store.data[0].list.rulesTotal, 0, "the old list's count is gone");

        fresh.emit("error", { error: "stopped" });
        fresh.close();
        await settle();
      });
    } finally {
      stub.restore();
    }
  });

  // Catches a follow for the old url being handed back, so the new url's sync is never read.
  it("a follow still open for the old url is replaced by one for the new", async () => {
    const id = "5a0e0003";
    const next = "https://example.com/next.txt";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups?save=true": { json: { groups: [queuedRecord(id, next)] } },
      [`/groups/${id}/list/rules?offset=0&limit=50`]: { json: rulesPage(2) },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);
      store.open_state[id] = true;
      store.data[0].list.sync = { state: "fetching", error: "", lastCheck: 0 };
      void store.lists.followSync(id);
      await streams.open(1);
      store.setListUrl(id, next);

      await withWindowStub(async () => {
        await store.saveChanges();
        const fresh = await streams.open(2);
        fresh.emit("done", {
          ...queuedRecord(id, next),
          list: { ...listRecord(id, "idle", 2).list, url: next },
        });
        fresh.close();
        await settle(3, 10);

        assert.strictEqual(streams.count, 2);
        assert.strictEqual(store.data[0].list.rulesTotal, 2);
        assert.strictEqual(store.data[0].list.sync.state, "idle");
      });
    } finally {
      stub.restore();
    }
  });

  // Catches the Save PATCHing edits on a page whose rules the PUT just dropped (404, no "Saved").
  it("edits on a list whose url the Save changed are not PATCHed", async () => {
    const id = "5a0e0004";
    const next = "https://example.com/next.txt";
    const streams = syncStreams();
    let configSaves = 0;
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: { json: rulesPage(3) },
      "/groups": { json: { groups: [queuedRecord(id, next)] } },
      [`/groups/${id}/list/rules?save=true`]: { status: 404, json: { error: "rule not found" } },
      "/system/config/save": () => {
        configSaves++;
        return { json: { status: "ok" } };
      },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 3)]);
      store.open_state[id] = true;
      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      store.setListUrl(id, next);

      await withWindowStub(async (toasts) => {
        await store.saveChanges();
        assert.ok(
          !stub.calls.includes(`/groups/${id}/list/rules?save=true`),
          `no PATCH for dropped rules, got: ${stub.calls.join(", ")}`,
        );
        assert.strictEqual(configSaves, 1, "the one write the Save owes");
        assert.deepStrictEqual(store.lists.ruleEdits(id), []);
        assert.ok(toasts.some((t) => t.content === "Saved"));

        const source = await streams.open(1);
        source.emit("error", { error: "stopped" });
        source.close();
        await settle();
      });
    } finally {
      stub.restore();
    }
  });

  // Catches a same-url list with a sync already running being treated as re-pointed and its edits dropped.
  it("edits on a same-url list whose sync is already running are still PATCHed", async () => {
    const id = "5a0e0006";
    const url = `https://example.com/${id}.txt`;
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: { json: rulesPage(3) },
      "/groups": {
        json: {
          groups: [
            {
              ...makeGroup(id, 3),
              list: {
                ...makeGroup(id, 3).list,
                sync: { state: "fetching", error: "", lastCheck: 0 },
              },
            },
          ],
        },
      },
      [`/groups/${id}/list/rules?save=true`]: { json: { status: "ok" } },
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 3)]);
      store.open_state[id] = true;
      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;
      assert.strictEqual(store.data[0].list.url, url, "fixture: the url is the saved one");

      await withWindowStub(async () => {
        await store.saveChanges();
        const patch = stub.requests.find((r) => r.path === `/groups/${id}/list/rules?save=true`);
        assert.ok(patch, `the PATCH is sent, got: ${stub.calls.join(", ")}`);
        assert.deepStrictEqual(patch!.body, { rules: [{ id: "rule0000", enable: false }] });
        assert.strictEqual(store.data[0].list.sync.state, "fetching", "the running sync, adopted");

        const source = await streams.open(1);
        source.emit("error", { error: "stopped" });
        source.close();
        await settle();
      });
    } finally {
      stub.restore();
    }
  });

  // Catches a superseded sync leaving the list `fetching` with nothing to move it on.
  it("a superseded sync's list is left idle, not fetching", async () => {
    const id = "5a0e0007";
    const streams = syncStreams();
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, 5)]);
      store.data[0].list.sync = { state: "fetching", error: "", lastCheck: 1700000000 };
      const follow = store.lists.followSync(id);
      const source = await streams.open(1);
      store.setListUrl(id, "https://example.com/elsewhere.txt");
      await withWindowStub(async (toasts) => {
        source.emit("error", { error: "list url changed" });
        source.close();
        await follow;

        assert.deepStrictEqual(toasts, [], "superseded, not failed");
        assert.deepStrictEqual(store.data[0].list.sync, {
          state: "idle",
          error: "",
          lastCheck: 1700000000,
        });
      });
    } finally {
      stub.restore();
    }
  });
});

describe("the lost-stream re-read", () => {
  // Catches the re-read parsing the rules-less answer as a full Group, which throws.
  it("reads the daemon's rules-less answer", async () => {
    const id = "5a0e0005";
    const streams = syncStreams();
    const { rules: _rules, ...rulesless } = makeGroup(id, 9);
    const stub = installFetchStub({
      [`/groups/${id}/list/sync/events`]: (init) => ({ body: streams.body(init.signal) }),
      "/groups": { json: { groups: [rulesless] } },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.data[0].list.sync = { state: "queued", error: "", lastCheck: 0 };
      store.lists.syncReopenMs = 20;

      const originalError = console.error;
      console.error = () => {};
      await withWindowStub(async () => {
        const follow = store.lists.followSync(id);
        (await streams.open(1)).fail();
        (await streams.open(2)).fail();
        await follow;
        await settle(3, 20);
      });
      console.error = originalError;

      assert.strictEqual(store.data[0].list.rulesTotal, 9);
      assert.strictEqual(store.data[0].list.sync.state, "idle");
    } finally {
      stub.restore();
    }
  });
});

describe("what the progress bar says", () => {
  it("names the stage and the numbers that stage has", () => {
    assert.strictEqual(
      syncProgressLabel({ stage: "fetch", bytes: 3145728, total: 7786120, lines: 0 }),
      "fetching 3.1 / 7.8 MB",
    );
    assert.strictEqual(
      syncProgressLabel({ stage: "fetch", bytes: 3145728, total: 0, lines: 0 }),
      "fetching 3.1 MB",
    );
    assert.strictEqual(
      syncProgressLabel({ stage: "parse", bytes: 0, total: 0, lines: 120000 }),
      "parsing 120,000 lines",
    );
    assert.strictEqual(
      syncProgressLabel({ stage: "apply", bytes: 0, total: 0, lines: 0 }),
      "applying",
    );
  });
});
