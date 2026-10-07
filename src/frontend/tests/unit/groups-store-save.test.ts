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

type FetchHandler = unknown | (() => unknown);

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

    if (resolved && typeof resolved === "object" && "__status" in (resolved as any)) {
      const r = resolved as { __status: number; __body: unknown };
      return {
        ok: false,
        status: r.__status,
        body: true,
        statusText: "error",
        text: async () => JSON.stringify(r.__body),
        json: async () => structuredClone(r.__body),
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

async function withWindowStub<T>(action: () => Promise<T>): Promise<T> {
  const hadWindow = "window" in globalThis;
  const original = (globalThis as any).window;
  (globalThis as any).window = {
    dispatchEvent: () => true,
    addEventListener: () => {},
    removeEventListener: () => {},
  };
  try {
    return await action();
  } finally {
    if (hadWindow) {
      (globalThis as any).window = original;
    } else {
      delete (globalThis as any).window;
    }
  }
}

const makeGroup = (id: string, withList = false) => ({
  id,
  name: `group-${id}`,
  interface: "",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [{ id: `r${id}`, enable: true, rule: `${id}.example.com`, type: "domain" }],
  ...(withList
    ? {
        list: {
          url: `https://example.com/${id}.txt`,
          interval: 86400,
          lastUpdate: 1700000000,
          rulesTotal: 3,
          sync: { state: "idle" as const, error: "", lastCheck: 1700000000 },
        },
      }
    : {}),
});

function seed(store: any, groups: ReturnType<typeof makeGroup>[]) {
  const cloned = structuredClone(groups);
  store.tracker.reset(cloned);
  store.resetListMetaBaseline(cloned);
}

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

describe("GroupsStore.saveChanges, with a list in the array", () => {
  it("a save sends the list config but not its rules", async () => {
    const id = "5a5e0001";
    const stub = installFetchStub({ "/groups?save=true": { status: "ok" } });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, true)]);
      store.data[0].name = "renamed";

      await withWindowStub(() => store.saveChanges());

      const putRequest = stub.requests.find((r) => r.path === "/groups?save=true");
      assert.ok(putRequest, "expected a PUT to /groups?save=true");
      const sentGroup = (putRequest!.body as any).groups[0];
      assert.deepStrictEqual(sentGroup.list, {
        url: `https://example.com/${id}.txt`,
        interval: 86400,
      });
      assert.strictEqual(
        (sentGroup.list as any).rulesTotal,
        undefined,
        "rulesTotal is the daemon's own and must not ride along",
      );
      assert.strictEqual((sentGroup.list as any).lastUpdate, undefined);
      assert.strictEqual((sentGroup.list as any).sync, undefined);
      assert.strictEqual(
        (sentGroup.list as any).rules,
        undefined,
        "never the list's rules -- this is the whole point of the split",
      );
    } finally {
      stub.restore();
    }
  });

  it("a save with list edits patches only that group", async () => {
    const withEdit = "5a5e0002";
    const withoutEdit = "5a5e0003";
    const stub = installFetchStub({
      [`/groups/${withEdit}/list/rules?offset=0&limit=50`]: rulesPage(3),
      "/groups": { status: "ok" },
      [`/groups/${withEdit}/list/rules?save=true`]: { status: "ok" },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(withEdit, true), makeGroup(withoutEdit, true)]);
      store.open_state[withEdit] = true;

      await store.lists.loadRules(withEdit, 0);
      store.lists.pageState[withEdit].rules[0].enable = false;
      assert.strictEqual(store.canSave, true, "fixture: the edit makes Save reachable");

      await withWindowStub(() => store.saveChanges());

      const patchRequest = stub.requests.find(
        (r) => r.path === `/groups/${withEdit}/list/rules?save=true`,
      );
      assert.ok(patchRequest, "expected a PATCH for the group with the edit");
      assert.deepStrictEqual(patchRequest!.body, {
        rules: [{ id: "rule0000", enable: false }],
      });
      assert.ok(
        !stub.calls.includes(`/groups/${withoutEdit}/list/rules?save=true`),
        "the group with no edit gets no PATCH",
      );
      assert.deepStrictEqual(store.lists.ruleEdits(withEdit), [], "the edit is saved");
    } finally {
      stub.restore();
    }
  });

  it("a save without list edits sends no patch", async () => {
    const id = "5a5e0004";
    const stub = installFetchStub({ "/groups?save=true": { status: "ok" } });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, true)]);
      store.data[0].name = "renamed";

      await withWindowStub(() => store.saveChanges());

      assert.ok(
        !stub.calls.some((c) => c.includes("/list/rules")),
        `expected no PATCH request, got: ${stub.calls.join(", ")}`,
      );
      assert.deepStrictEqual(stub.calls, ["/groups?save=true"]);
    } finally {
      stub.restore();
    }
  });

  it("only the last request asks for a write", async () => {
    const id = "5a5e0005";
    const stub = installFetchStub({
      [`/groups/${id}/list/rules?offset=0&limit=50`]: rulesPage(3),
      "/groups": { status: "ok" },
      [`/groups/${id}/list/rules?save=true`]: { status: "ok" },
    });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, true)]);
      store.open_state[id] = true;

      await store.lists.loadRules(id, 0);
      store.lists.pageState[id].rules[0].enable = false;

      const before = stub.calls.length;
      await withWindowStub(() => store.saveChanges());

      assert.deepStrictEqual(
        stub.calls.slice(before),
        ["/groups", `/groups/${id}/list/rules?save=true`],
        "the metadata PUT carries no query, the trailing PATCH is the only `?save=true`",
      );
    } finally {
      stub.restore();
    }
  });

  it("duplicating a list group keeps its url and interval and nothing fetched", () => {
    const store = new GroupsStore();
    const source = makeGroup("5a5e0006", true) as any;
    source.list.rulesTotal = 12345;
    source.list.lastUpdate = 1700000000;
    source.list.sync = { state: "idle", error: "", lastCheck: 1700000000 };

    const cloned = store.cloneGroupWithNewIds(source);

    assert.notStrictEqual(cloned.id, source.id);
    assert.ok(cloned.list, "fixture: the clone keeps a list at all");
    assert.strictEqual(cloned.list!.url, source.list.url);
    assert.strictEqual(cloned.list!.interval, source.list.interval);
    assert.strictEqual(cloned.list!.rulesTotal, 0, "nothing has been fetched for the copy yet");
    assert.strictEqual(cloned.list!.lastUpdate, 0);
    assert.deepStrictEqual(cloned.list!.sync, { state: "idle", error: "", lastCheck: 0 });
  });
});

describe("a group's device selector", () => {
  it("a_devices_edit_marks_the_group_dirty_and_is_sent", async () => {
    const id = "d1d2d3d4";
    const stub = installFetchStub({ "/groups?save=true": { status: "ok" } });

    try {
      const store = new GroupsStore();
      const group = makeGroup(id) as any;
      group.devices = { allow: ["10.0.0.5"], deny: [] };
      seed(store, [group]);

      assert.strictEqual(store.tracker.isDirty, false, "fixture: nothing has been edited yet");
      assert.strictEqual(store.canSave, false);

      store.data[0].devices = { allow: ["192.168.1.0/24"], deny: ["192.168.1.5"] };

      assert.strictEqual(store.tracker.isDirty, true, "a devices edit must mark the group dirty");
      assert.strictEqual(store.canSave, true);

      await withWindowStub(() => store.saveChanges());

      const putRequest = stub.requests.find((r) => r.path === "/groups?save=true");
      assert.ok(putRequest, "expected a PUT to /groups?save=true");
      const sent = (putRequest!.body as any).groups[0];
      assert.deepStrictEqual(
        sent.devices,
        { allow: ["192.168.1.0/24"], deny: ["192.168.1.5"] },
        "the edited selector must be in the save body",
      );
    } finally {
      stub.restore();
    }
  });

  // Regression guard: addGroup() must keep giving a fresh group the empty selector.
  it("a_freshly_added_group_has_an_empty_selector", async () => {
    const store = new GroupsStore();
    store.dataLoaded = true;

    const hadDocument = "document" in globalThis;
    const originalDocument = (globalThis as any).document;
    (globalThis as any).document = { querySelector: () => null };
    try {
      await store.addGroup();
    } finally {
      if (hadDocument) {
        (globalThis as any).document = originalDocument;
      } else {
        delete (globalThis as any).document;
      }
    }

    const group = store.data[0];
    assert.ok(group, "fixture: the group was added");
    assert.deepStrictEqual(group.devices, { allow: [], deny: [] });
  });
});

describe("a list's url/interval, edited from the header or the dialog", () => {
  it("setListUrl marks Save reachable and Save clears it", async () => {
    const id = "5a5e0007";
    const stub = installFetchStub({ "/groups?save=true": { status: "ok" } });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, true)]);
      assert.strictEqual(store.canSave, false, "fixture: nothing edited yet");

      store.setListUrl(id, "https://example.com/new.txt");
      assert.strictEqual(store.canSave, true, "the url edit must make Save reachable");
      assert.strictEqual(store.data[0].list.url, "https://example.com/new.txt");

      await withWindowStub(() => store.saveChanges());

      const putRequest = stub.requests.find((r) => r.path === "/groups?save=true");
      assert.ok(putRequest, "expected a PUT to /groups?save=true");
      assert.strictEqual(
        (putRequest!.body as any).groups[0].list.url,
        "https://example.com/new.txt",
      );
      assert.strictEqual(store.canSave, false, "clean again once the edit is saved");
    } finally {
      stub.restore();
    }
  });

  it("setListInterval marks Save reachable and Save clears it", async () => {
    const id = "5a5e0008";
    const stub = installFetchStub({ "/groups?save=true": { status: "ok" } });

    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id, true)]);
      assert.strictEqual(store.canSave, false, "fixture: nothing edited yet");

      store.setListInterval(id, 3600);
      assert.strictEqual(store.canSave, true, "the interval edit must make Save reachable");
      assert.strictEqual(store.data[0].list.interval, 3600);

      await withWindowStub(() => store.saveChanges());

      const putRequest = stub.requests.find((r) => r.path === "/groups?save=true");
      assert.strictEqual((putRequest!.body as any).groups[0].list.interval, 3600);
      assert.strictEqual(store.canSave, false, "clean again once the edit is saved");
    } finally {
      stub.restore();
    }
  });

  // onblur always calls setListUrl; tabbing through URL fields must not dirty any group.
  it("setListUrl with the value already current is a no-op", () => {
    const id = "5a5e0009";
    const store = new GroupsStore();
    const group = makeGroup(id, true) as any;
    seed(store, [group]);
    assert.strictEqual(store.canSave, false, "fixture: nothing edited yet");

    store.setListUrl(id, group.list.url);

    assert.strictEqual(store.canSave, false, "the same value must not make Save reachable");
  });

  // Catches dirtiness tracking "ever reassigned" instead of comparing with what was last saved.
  it("an edit undone by hand reads clean again", () => {
    const id = "5a5e000a";
    const store = new GroupsStore();
    const group = makeGroup(id, true) as any;
    const originalUrl = group.list.url;
    seed(store, [group]);

    store.setListUrl(id, "https://example.com/typed-then-reverted.txt");
    assert.strictEqual(store.canSave, true, "fixture: the edit itself must dirty it");

    store.setListUrl(id, originalUrl);
    assert.strictEqual(store.canSave, false, "reverted by hand, so nothing is left to save");
  });

  // A sync persists only the url; an interval edit made before it must not read as saved.
  it("a sync persists only url, so an unsaved interval edit survives it", async () => {
    const id = "5a5e000b";
    const stub = installFetchStub({
      [`/groups/${id}/list/sync`]: {
        list: {
          url: "https://example.com/synced.txt",
          sync: { state: "queued", error: "", lastCheck: 0 },
        },
      },
      "/groups?save=true": { status: "ok" },
    });

    try {
      const store = new GroupsStore();
      const group = makeGroup(id, true) as any;
      seed(store, [group]);
      store.lists.syncReopenMs = 0;

      store.setListInterval(id, 604800);
      assert.strictEqual(store.canSave, true, "fixture: the interval edit must dirty it");

      await withWindowStub(() => store.lists.requestSync(id, "https://example.com/synced.txt"));

      assert.strictEqual(
        store.canSave,
        true,
        "the sync persisted url, not the still-unsaved interval",
      );
      assert.strictEqual(store.data[0].list.interval, 604800, "the edit itself must survive");

      await withWindowStub(() => store.saveChanges());

      const putRequest = stub.requests.find((r) => r.path === "/groups?save=true");
      assert.ok(putRequest, "expected a PUT to /groups?save=true");
      assert.strictEqual((putRequest!.body as any).groups[0].list.interval, 604800);
      assert.strictEqual(
        (putRequest!.body as any).groups[0].list.url,
        "https://example.com/synced.txt",
      );
    } finally {
      stub.restore();
    }
  });
});

describe("updateGroupFromDialog, the settings button on an existing group", () => {
  it("a Save with nothing changed in the dialog leaves the group clean", () => {
    const id = "5a5e000c";
    const store = new GroupsStore();
    const group = makeGroup(id, true) as any;
    seed(store, [group]);
    assert.strictEqual(store.canSave, false, "fixture: nothing edited yet");

    store.updateGroupFromDialog(0, {
      name: group.name,
      interface: group.interface,
      devices: { allow: [...group.devices.allow], deny: [...group.devices.deny] },
      list: { url: group.list.url, interval: group.list.interval },
      resolve: { tunnel: true, server: "" },
    });

    assert.strictEqual(store.canSave, false, "an unchanged dialog submit must not dirty it");
  });

  it("a Save that actually changes the list still dirties it", () => {
    const id = "5a5e000d";
    const store = new GroupsStore();
    const group = makeGroup(id, true) as any;
    seed(store, [group]);

    store.updateGroupFromDialog(0, {
      name: group.name,
      interface: group.interface,
      devices: group.devices,
      list: { url: "https://example.com/changed.txt", interval: group.list.interval },
      resolve: { tunnel: true, server: "" },
    });

    assert.strictEqual(store.canSave, true, "a real change must still be reachable to save");
    assert.strictEqual(store.data[0].list.url, "https://example.com/changed.txt");
  });
});

describe("a group's resolve", () => {
  it("a dialog Save with resolve unchanged leaves the group clean", () => {
    const id = "5e5e0001";
    const store = new GroupsStore();
    const group = makeGroup(id) as any;
    seed(store, [group]);
    store.updateGroupFromDialog(0, {
      name: group.name,
      interface: group.interface,
      devices: { allow: [], deny: [] },
      resolve: { tunnel: true, server: "" },
    });
    assert.strictEqual(
      store.canSave,
      false,
      "same content must not dirty it (ChangeTracker compares objects by identity)",
    );
  });

  it("a changed resolve dirties the group and is what the PUT sends, without the read-only resolver", async () => {
    const id = "5e5e0002";
    const stub = installFetchStub({
      "/groups?save=true": {
        groups: [
          {
            ...makeGroup(id),
            resolve: { tunnel: true, server: "9.9.9.9" },
            resolver: { source: "group", servers: ["9.9.9.9"], fallbacks: 0 },
          },
        ],
      },
    });
    try {
      const store = new GroupsStore();
      const group = {
        ...makeGroup(id),
        resolver: { source: "none", servers: [], fallbacks: 3 },
      } as any;
      seed(store, [group]);
      store.updateGroupFromDialog(0, {
        name: group.name,
        interface: group.interface,
        devices: { allow: [], deny: [] },
        resolve: { tunnel: true, server: "9.9.9.9" },
      });
      assert.strictEqual(store.canSave, true);
      await withWindowStub(() => store.saveChanges());
      const put = stub.requests.find((r) => r.path === "/groups?save=true");
      const sent = (put!.body as any).groups[0];
      assert.deepStrictEqual(sent.resolve, { tunnel: true, server: "9.9.9.9" });
      assert.strictEqual("resolver" in sent, false, "resolver is the daemon's, never sent");
      assert.strictEqual((store.data[0] as any).resolver.source, "group");
      assert.strictEqual(store.canSave, false);
    } finally {
      stub.restore();
    }
  });

  it("a 400 naming a group's field is kept for that group's dialog, and a later successful Save clears it on its own", async () => {
    const id = "5e5e0003";
    let saveAttempt = 0;
    const stub = installFetchStub({
      "/groups?save=true": () => {
        saveAttempt++;
        if (saveAttempt === 1) {
          return {
            __status: 400,
            __body: {
              error: 'resolve.server "198.18.0.1" is inside firc\'s address pool',
              field: "resolve.server",
              group: id,
            },
          };
        }
        return {
          groups: [{ ...makeGroup(id), resolve: { tunnel: true, server: "198.18.0.1" } }],
        };
      },
      "/system/config/save": {},
    });
    try {
      const store = new GroupsStore();
      const group = makeGroup(id) as any;
      seed(store, [group]);
      store.updateGroupFromDialog(0, {
        name: group.name,
        interface: group.interface,
        devices: { allow: [], deny: [] },
        resolve: { tunnel: true, server: "198.18.0.1" },
      });
      await withWindowStub(() => store.saveChanges());
      assert.deepStrictEqual(store.groupFieldError, {
        group: id,
        field: "resolve.server",
        error: 'resolve.server "198.18.0.1" is inside firc\'s address pool',
      });
      assert.strictEqual(store.canSave, true, "the edit is kept for the operator to fix");

      await withWindowStub(() => store.saveChanges());
      assert.strictEqual(
        store.groupFieldError,
        null,
        "a later Save that succeeds must clear the earlier refusal itself",
      );
    } finally {
      stub.restore();
    }
  });

  it("clearGroupFieldError resets it by hand", () => {
    const store = new GroupsStore();
    store.groupFieldError = { group: "5e5e00ff", field: "resolve.server", error: "bad" };
    store.clearGroupFieldError();
    assert.strictEqual(store.groupFieldError, null);
  });

  it("a duplicated group gets its own resolve and no resolver", async () => {
    const { cloneGroupWithNewIds } = await import("../../src/modules/groups/groups-data.ts");
    const source = {
      ...makeGroup("5e5e0004"),
      resolve: { tunnel: false, server: "1.1.1.1" },
      resolver: { source: "off", servers: [], fallbacks: 9 },
    } as any;
    const copy = cloneGroupWithNewIds(source) as any;
    assert.deepStrictEqual(copy.resolve, { tunnel: false, server: "1.1.1.1" });
    assert.notStrictEqual(copy.resolve, source.resolve, "its own object");
    assert.strictEqual(copy.resolver, undefined, "a copy has fallen back nowhere yet");
  });

  // The bulk clone has its own copy of the single clone's lines; catches the two drifting apart.
  it("the bulk clone gives each duplicate its own resolve and no resolver", async () => {
    const { cloneGroupsWithNewIds } = await import("../../src/modules/groups/groups-data.ts");
    const source = {
      ...makeGroup("5e5e0005"),
      resolve: { tunnel: false, server: "1.1.1.1" },
      resolver: { source: "off", servers: [], fallbacks: 9 },
    } as any;
    const [copy] = (await cloneGroupsWithNewIds([source])) as any[];
    assert.deepStrictEqual(copy.resolve, { tunnel: false, server: "1.1.1.1" });
    assert.notStrictEqual(copy.resolve, source.resolve, "its own object");
    assert.strictEqual(copy.resolver, undefined, "a copy has fallen back nowhere yet");
  });
});

const byId = (store: any, id: string) => store.data.find((g: any) => g.id === id);

describe("GroupsStore live state", () => {
  const liveAnswer = (records: Record<string, unknown>[]) => ({ groups: records });

  // Catches a poll writing through the tracker, rolling back an edit, or dropping the netfilter answer.
  it("a poll merges live state without touching edits or dirtiness", async () => {
    const a = "11ve0001";
    const b = "11ve0002";
    const stub = installFetchStub({
      "/groups": liveAnswer([
        { ...makeGroup(a), name: "daemon-name", live: true },
        { ...makeGroup(b), live: false, liveReason: "no-interface" },
      ]),
      "/system/netfilter": { ok: false, error: "i/o error", since: 1790000000 },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(a), makeGroup(b)]);
      assert.strictEqual(store.tracker.isDirty, false, "fixture: clean");

      await store.pollLive();
      assert.strictEqual(store.tracker.isDirty, false, "a poll is not an edit");
      assert.deepStrictEqual(store.liveOf(a), { live: true, liveReason: undefined });
      assert.deepStrictEqual(store.liveOf(b), { live: false, liveReason: "no-interface" });
      assert.deepStrictEqual(store.netfilter, { ok: false, error: "i/o error", since: 1790000000 });
      assert.ok(store.checkedAt > 0, "the check is timed");
      assert.strictEqual(store.data[0].name, `group-${a}`, "only live state is taken");

      store.data[1].name = "edited";
      await store.pollLive();
      assert.strictEqual(store.data[1].name, "edited", "the edit survives the poll");
      assert.strictEqual(store.tracker.isDirty, true, "and stays unsaved");
      assert.strictEqual(store.groupDirty(byId(store, b)), true);
      assert.strictEqual(store.groupDirty(byId(store, a)), false);
    } finally {
      stub.restore();
    }
  });

  // Catches a failed poll blanking the icons or resetting the last good answer's age.
  it("a failed poll keeps the last known state and its time", async () => {
    const id = "11ve0003";
    let failing = false;
    const stub = installFetchStub({
      "/groups": () =>
        failing ? { __status: 503, __body: { error: "down" } } : liveAnswer([{ id, live: true }]),
      "/system/netfilter": { ok: true },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      await store.pollLive();
      const checkedAt = store.checkedAt;
      assert.ok(checkedAt > 0);

      failing = true;
      await store.pollLive();
      assert.deepStrictEqual(store.liveOf(id), { live: true, liveReason: undefined });
      assert.deepStrictEqual(store.netfilter, { ok: true });
      assert.strictEqual(store.checkedAt, checkedAt);
    } finally {
      stub.restore();
    }
  });

  // Catches the page showing pre-Save daemon state, or sending the daemon's own fields back.
  it("a Save takes live state from its answer and never sends it", async () => {
    const id = "11ve0004";
    const stub = installFetchStub({
      "/groups": liveAnswer([{ id, live: true }]),
      "/system/netfilter": { ok: true },
      "/groups?save=true": liveAnswer([
        { ...makeGroup(id), live: false, liveReason: "not-enabled" },
      ]),
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      await store.pollLive();
      store.data[0].interface = "nwg9";
      await withWindowStub(() => store.saveChanges());

      assert.deepStrictEqual(store.liveOf(id), { live: false, liveReason: "not-enabled" });
      const put = stub.requests.find((r) => r.path === "/groups?save=true")!;
      const sent = (put.body as any).groups[0];
      assert.ok(!("live" in sent) && !("liveReason" in sent), JSON.stringify(sent));
      assert.strictEqual(store.groupDirty(byId(store, id)), false, "saved is clean again");
    } finally {
      stub.restore();
    }
  });

  // Catches the first load leaving `live` inside tracked data, where it would ride every PUT.
  it("the first load reads live state out of the tracked groups", async () => {
    const id = "11ve0005";
    const stub = installFetchStub({
      "/groups?with_rules=true": liveAnswer([
        { ...makeGroup(id), live: false, liveReason: "not-written" },
      ]),
      "/system/netfilter": { ok: false, firstWritePending: true },
    });
    try {
      const store = new GroupsStore();
      await withWindowStub(() => store.mount());
      assert.strictEqual(store.fetchError, false);
      assert.deepStrictEqual(store.liveOf(id), { live: false, liveReason: "not-written" });
      const [loaded] = store.tracker.data as any[];
      assert.strictEqual(loaded.id, id);
      assert.ok(!("live" in loaded) && !("liveReason" in loaded), JSON.stringify(loaded));
      assert.ok(store.checkedAt > 0);
      store.destroy();
    } finally {
      stub.restore();
    }
  });

  // Catches a group reading unsaved for another's edit, or saved despite its own (rule, list url, new group).
  it("tells which group carries an unsaved edit", () => {
    const a = "11ve0006";
    const b = "11ve0007";
    const store = new GroupsStore();
    seed(store, [makeGroup(a, true), makeGroup(b)]);
    assert.strictEqual(store.groupDirty(byId(store, a)), false);
    assert.strictEqual(store.groupDirty(byId(store, b)), false);

    store.data[1].rules[0].rule = "changed.example.com";
    assert.strictEqual(store.groupDirty(byId(store, b)), true, "a rule edit");
    assert.strictEqual(store.groupDirty(byId(store, a)), false, "not the other group");
    store.data[1].rules[0].rule = `${b}.example.com`;
    assert.strictEqual(store.groupDirty(byId(store, b)), false, "reverted");

    store.data[1].rules.push({ id: "abcd0001", enable: true, rule: "x.com", type: "domain" });
    assert.strictEqual(store.groupDirty(byId(store, b)), true, "a rule added");
    store.data[1].rules.pop();
    assert.strictEqual(store.groupDirty(byId(store, b)), false);

    store.setListUrl(a, "https://example.com/other.txt");
    assert.strictEqual(store.groupDirty(byId(store, a)), true, "a list's url");

    store.data.push({ ...makeGroup("11ve0008") } as any);
    assert.strictEqual(store.groupDirty(byId(store, "11ve0008")), true, "never saved");
    assert.strictEqual(store.groupDirty(byId(store, b)), false, "a group added elsewhere");
  });
});

describe("GroupsStore live state, fix round 1", () => {
  const liveAnswer = (records: Record<string, unknown>[]) => ({ groups: records });

  // Catches an older Save answer overwriting a poll sent after the PUT and answered first.
  it("a poll sent after the PUT wins over the PUT's answer", async () => {
    const id = "11ve0101";
    let releasePut!: () => void;
    const putHeld = new Promise<void>((resolve) => (releasePut = resolve));
    let putSent!: () => void;
    const putStarted = new Promise<void>((resolve) => (putSent = resolve));
    const stub = installFetchStub({
      "/groups?save=true": async () => {
        putSent();
        await putHeld;
        return liveAnswer([{ ...makeGroup(id), live: false, liveReason: "not-enabled" }]);
      },
      "/groups": liveAnswer([{ id, live: true }]),
      "/system/netfilter": { ok: true },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.data[0].name = "renamed";
      const saving = withWindowStub(() => store.saveChanges());
      await putStarted;
      await new Promise((resolve) => setTimeout(resolve, 5));
      await store.pollLive();
      const polledAt = store.checkedAt;
      assert.deepStrictEqual(store.liveOf(id), { live: true, liveReason: undefined });

      releasePut();
      await saving;
      assert.deepStrictEqual(
        store.liveOf(id),
        { live: true, liveReason: undefined },
        "the older PUT answer is not taken",
      );
      assert.strictEqual(store.checkedAt, polledAt, "nor stamped as the latest check");
    } finally {
      stub.restore();
    }
  });

  // Catches checkedAt being the answer's arrival time instead of the request's send time.
  it("stamps a check with the time its request was sent", async () => {
    const id = "11ve0102";
    const realNow = Date.now;
    let clock = 1_000_000;
    (Date as any).now = () => clock;
    const stub = installFetchStub({
      "/groups": async () => {
        clock += 3000;
        return liveAnswer([{ id, live: true }]);
      },
      "/system/netfilter": { ok: true },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      await store.pollLive();
      assert.strictEqual(store.checkedAt, 1_000_000);
    } finally {
      (Date as any).now = realNow;
      stub.restore();
    }
  });

  // Catches stale icons staying up past 15 s, one missed poll reading as silence, or no recovery.
  it("reads no answer once the last good check is over 15 s old", async () => {
    const id = "11ve0103";
    const realNow = Date.now;
    let clock = 2_000_000;
    (Date as any).now = () => clock;
    let failing = false;
    const stub = installFetchStub({
      "/groups": () =>
        failing ? { __status: 502, __body: { error: "gone" } } : liveAnswer([{ id, live: true }]),
      "/system/netfilter": { ok: true },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      await store.pollLive();
      assert.strictEqual(store.noAnswer, false);

      failing = true;
      clock += 10_000;
      await store.pollLive();
      assert.strictEqual(store.noAnswer, false, "10 s is two missed polls, not silence");
      clock += 6_000;
      await store.pollLive();
      assert.strictEqual(store.noAnswer, true, "16 s without an answer");
      assert.deepStrictEqual(store.liveOf(id), { live: true, liveReason: undefined }, "kept");

      failing = false;
      clock += 5_000;
      await store.pollLive();
      assert.strictEqual(store.noAnswer, false, "the next answer clears it");
    } finally {
      (Date as any).now = realNow;
      stub.restore();
    }
  });

  // Catches reordering cards marking the moved group unsaved.
  it("moving a group does not make it unsaved", () => {
    const a = "11ve0104";
    const b = "11ve0105";
    const store = new GroupsStore();
    seed(store, [makeGroup(a), makeGroup(b)]);
    store.changeGroupIndex(1, 0, "before");
    assert.deepStrictEqual(
      store.data.map((g: any) => g.id),
      [b, a],
      "fixture: moved",
    );
    assert.strictEqual(store.tracker.isDirty, true, "fixture: the order is an edit");
    assert.strictEqual(store.groupDirty(byId(store, a)), false);
    assert.strictEqual(store.groupDirty(byId(store, b)), false);
  });

  // Catches a refused Save taking the edit as saved.
  it("a failed Save leaves the group unsaved", async () => {
    const id = "11ve0106";
    const stub = installFetchStub({
      "/groups?save=true": { __status: 500, __body: { error: "random error" } },
    });
    try {
      const store = new GroupsStore();
      seed(store, [makeGroup(id)]);
      store.data[0].name = "renamed";
      await withWindowStub(() => store.saveChanges());
      assert.strictEqual(store.groupDirty(byId(store, id)), true);
    } finally {
      stub.restore();
    }
  });
});
