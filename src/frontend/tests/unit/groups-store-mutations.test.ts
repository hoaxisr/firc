import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

type Rule = {
  id: string;
  enable: boolean;
  name: string;
  rule: string;
  type: string;
};

type Group = {
  id: string;
  name: string;
  interface: string;
  enable: boolean;
  rules: Rule[];
};

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
  Object.defineProperty(globalThis, key, {
    value,
    configurable: true,
    writable: true,
  });

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
const { GroupsStore, invalidRulesByGroup, mergeOutside } =
  await import("../../src/modules/groups/groups.svelte");
const { answer, confirmation } = await import("../../src/utils/confirm.svelte");
if (processObj) {
  if (originalProcessEnvDescriptor) {
    Object.defineProperty(processObj, "env", originalProcessEnvDescriptor);
  } else {
    delete processObj.env;
  }
}
restoreLocalStorage();

const makeRule = (id: string, pattern = `${id}.example.com`): Rule => ({
  id,
  enable: true,
  rule: pattern,
  type: "domain",
});

const makeGroup = (id: string, rules: Rule[] = []): Group => ({
  id,
  name: `group-${id}`,
  interface: "all",
  enable: true,
  rules,
});

const createStore = (groups: Group[] = []) => {
  const store = new GroupsStore();
  store.data.splice(0, store.data.length, ...structuredClone(groups));
  store.dataRevision = 0;
  store.dataLoaded = true;
  store.open_state = {};
  for (const group of store.data) {
    store.open_state[group.id] = false;
  }
  return store;
};

const groupIds = (store: InstanceType<typeof GroupsStore>) => store.data.map((group) => group.id);
const ruleIds = (store: InstanceType<typeof GroupsStore>, groupIndex: number) =>
  store.data[groupIndex]?.rules.map((rule) => rule.id) ?? [];

const withPatchedGlobal = async <T>(key: string, value: unknown, action: () => T | Promise<T>) => {
  const restore = patchGlobal(key, value);
  try {
    return await action();
  } finally {
    restore();
  }
};

describe("GroupsStore mutations and validation", () => {
  it("invalidRules names each group's empty or malformed rules, and nothing else", () => {
    const groups = [
      makeGroup("g1", [makeRule("ok"), makeRule("empty", ""), makeRule("bad", "a..b")]),
      makeGroup("g2", [makeRule("fine")]),
    ];
    assert.deepStrictEqual([...invalidRulesByGroup(groups).entries()], [["g1", ["empty", "bad"]]]);
  });

  it("markDataRevision increments revision counter", () => {
    const store = createStore();
    store.markDataRevision();
    store.markDataRevision();
    assert.strictEqual(store.dataRevision, 2);
  });

  // Catches a group added before the list arrives or after it failed, which the load or a save would then clobber.
  it("nothing is added while the list is not loaded or failed to load", async () => {
    const store = createStore();
    store.dataLoaded = false;
    await store.addGroup();
    await store.addGroups([makeGroup("g1")]);
    assert.strictEqual(store.data.length, 0);
    store.dataLoaded = true;
    store.fetchError = true;
    await store.addGroup();
    assert.strictEqual(store.data.length, 0);
  });

  // Catches the toolbar reading every group as open, or the open-all loop stopping short.
  it("anyShownOpen is true while one group is open and setShownOpen moves every group", async () => {
    const store = createStore([makeGroup("g1"), makeGroup("g2"), makeGroup("g3")]);
    assert.strictEqual(store.anyShownOpen, false);

    store.open_state.g2 = true;
    assert.strictEqual(store.anyShownOpen, true);

    await store.setShownOpen(false);
    assert.deepStrictEqual(store.open_state, { g1: false, g2: false, g3: false });
    assert.strictEqual(store.anyShownOpen, false);

    await store.setShownOpen(true);
    assert.deepStrictEqual(store.open_state, { g1: true, g2: true, g3: true });
  });

  // Catches opening all skipping the retry a single open gives a list whose page failed.
  it("setShownOpen(true) lets a failed list page load again", async () => {
    const store = createStore([
      { ...makeGroup("g1"), list: { url: "https://l.example/x" } } as Group,
    ]);
    store.lists.pageState.g1 = { failed: true } as any;

    await store.setShownOpen(true);

    assert.strictEqual(store.lists.pageState.g1.failed, false);
  });

  it("addGroup prepends group, adds default rule and opens it", async () => {
    const store = createStore([makeGroup("g1", [makeRule("r1")])]);

    await withPatchedGlobal("document", { querySelector: () => null }, async () => {
      await store.addGroup();
    });

    assert.strictEqual(store.data.length, 2);
    assert.strictEqual(store.data[0].rules.length, 1);
    assert.strictEqual(store.open_state[store.data[0].id], true);
    assert.deepStrictEqual(groupIds(store).slice(1), ["g1"]);
    assert.strictEqual(store.dataRevision, 2);
  });

  // Catches a declined dialog deleting, a dialog not naming the group and its rule count, or a delete of whatever moved into the index while it was open.
  it("deleteGroup asks, names the group, and removes the one it asked about", async () => {
    const store = createStore([makeGroup("g1", [makeRule("r1"), makeRule("r2")]), makeGroup("g2")]);
    store.open_state.g1 = true;
    store.open_state.g2 = true;

    const declined = store.deleteGroup(0);
    assert.strictEqual(confirmation.current?.title, "Delete group «group-g1»?");
    assert.match(confirmation.current?.message ?? "", /\b2 rules\b/);
    answer(false);
    await declined;
    assert.deepStrictEqual(groupIds(store), ["g1", "g2"]);
    assert.strictEqual(store.dataRevision, 0);

    const accepted = store.deleteGroup(0);
    store.changeGroupIndex(0, 1, "after");
    answer(true);
    await accepted;
    assert.deepStrictEqual(groupIds(store), ["g2"]);
    assert.strictEqual("g1" in store.open_state, false);
  });

  it("changeGroupIndex supports before/after and clamps target indexes", () => {
    const store = createStore([makeGroup("a"), makeGroup("b"), makeGroup("c")]);

    store.changeGroupIndex(0, 2, "before");
    assert.deepStrictEqual(groupIds(store), ["b", "a", "c"]);

    store.changeGroupIndex(0, 99, "after");
    assert.deepStrictEqual(groupIds(store), ["a", "c", "b"]);

    store.changeGroupIndex(0, 0, "before");
    assert.deepStrictEqual(groupIds(store), ["a", "c", "b"]);
    assert.strictEqual(store.dataRevision, 2);
  });

  it("handleGroupSlotDrop applies group reorder semantics", () => {
    const store = createStore([makeGroup("a"), makeGroup("b"), makeGroup("c")]);

    store.handleGroupSlotDrop(
      { group_id: "a", group_index: 0, name: "group-a", count: 0 },
      { group_index: 2, insert: "before" },
    );

    assert.deepStrictEqual(groupIds(store), ["b", "a", "c"]);
    assert.strictEqual(store.dataRevision, 1);
  });

  it("addRuleToGroup prepends and marks rules invalid for empty fields", async () => {
    const store = createStore([makeGroup("g1", [makeRule("r1")])]);

    await store.addRuleToGroup(0, makeRule("r2", ""), false);
    assert.deepStrictEqual(ruleIds(store, 0), ["r2", "r1"]);
    assert.strictEqual(store.dataRevision, 1);

    await store.addRuleToGroup(99, makeRule("r3"), false);
    assert.deepStrictEqual(ruleIds(store, 0), ["r2", "r1"]);
    assert.strictEqual(store.dataRevision, 1);
  });

  // Catches the block group pushed last (below the owner it must beat), saved, closed, or a routing one.
  it("createBlockGroup puts an unsaved block group first", async () => {
    const store = createStore();
    store.tracker.reset(structuredClone([makeGroup("g1", [makeRule("r1")])]) as any);
    assert.strictEqual(store.tracker.isDirty, false, "fixture: clean");

    const id = await store.createBlockGroup("Блокировка · Phone", {
      allow: ["mac:aa:00:00:00:00:03"],
      deny: [],
    });

    assert.deepStrictEqual(groupIds(store), [id, "g1"]);
    const created = store.data[0] as any;
    assert.strictEqual(created.name, "Блокировка · Phone");
    assert.strictEqual(created.interface, "block");
    assert.strictEqual(created.block, "null");
    assert.strictEqual(created.enable, true);
    assert.deepStrictEqual(created.devices, { allow: ["mac:aa:00:00:00:00:03"], deny: [] });
    assert.deepStrictEqual(created.rules, []);
    assert.strictEqual(store.open_state[id], true);
    assert.strictEqual(store.tracker.isDirtyWithin(store.data[0]), true);
    assert.strictEqual(store.tracker.isDirtyWithin(store.data[1]), false);
    assert.strictEqual(store.canSave, true);

    store.dataLoaded = false;
    assert.strictEqual(await store.createBlockGroup("x", { allow: [], deny: [] }), "");
    assert.strictEqual(store.data.length, 2);
  });

  // Catches a second copy of a held name, or a disabled copy left off instead of switched on.
  it("blockName skips a name the group holds and switches a disabled one on", async () => {
    const store = createStore([
      makeGroup("g1", [makeRule("r1", "ya.ru"), { ...makeRule("r2", "vk.com"), enable: false }]),
    ]);
    await store.blockName("g1", "ya.ru");
    assert.deepStrictEqual(ruleIds(store, 0), ["r1", "r2"]);
    await store.blockName("g1", "vk.com");
    assert.deepStrictEqual(ruleIds(store, 0), ["r1", "r2"]);
    assert.strictEqual(store.data[0].rules[1].enable, true);
    assert.strictEqual(store.dataRevision, 1);
    await store.blockName("g1", "new.example");
    assert.deepStrictEqual(store.data[0].rules[0], {
      ...store.data[0].rules[0],
      rule: "new.example",
      type: "domain",
      enable: true,
    });
    assert.strictEqual(store.data[0].rules.length, 3);
    await store.blockName("nope", "x.example");
    assert.strictEqual(store.data[0].rules.length, 3);
  });

  it("deleteRuleFromGroup removes by index and keeps out-of-range behavior", () => {
    const store = createStore([makeGroup("g1", [makeRule("r1"), makeRule("r2"), makeRule("r3")])]);

    store.deleteRuleFromGroup(0, 1);
    assert.deepStrictEqual(ruleIds(store, 0), ["r1", "r3"]);
    assert.strictEqual(store.dataRevision, 1);

    store.deleteRuleFromGroup(0, 99);
    assert.deepStrictEqual(ruleIds(store, 0), ["r1", "r3"]);
    assert.strictEqual(store.dataRevision, 2);
  });

  it("changeRuleIndex reorders rules inside and across groups", () => {
    const store = createStore([
      makeGroup("g1", [makeRule("a"), makeRule("b"), makeRule("c")]),
      makeGroup("g2", [makeRule("d")]),
    ]);

    store.changeRuleIndex(0, 0, 0, 2, "c", "before");
    assert.deepStrictEqual(ruleIds(store, 0), ["b", "a", "c"]);

    store.changeRuleIndex(0, 0, 1, 0, "d", "after");
    assert.deepStrictEqual(ruleIds(store, 0), ["a", "c"]);
    assert.deepStrictEqual(ruleIds(store, 1), ["d", "b"]);
    assert.strictEqual(store.dataRevision, 2);
  });

  it("sortGroupRules and restoreGroupRulesOrder update order with return flags", () => {
    const store = createStore([
      makeGroup("g1", [makeRule("r1", "beta.example.com"), makeRule("r2", "alpha.example.com")]),
    ]);
    const initial = ruleIds(store, 0);

    const sorted = store.sortGroupRules(0, "asc");
    assert.strictEqual(sorted, true);
    assert.deepStrictEqual(ruleIds(store, 0), ["r2", "r1"]);

    const restored = store.restoreGroupRulesOrder(0, initial);
    assert.strictEqual(restored, true);
    assert.deepStrictEqual(ruleIds(store, 0), initial);

    const failed = store.restoreGroupRulesOrder(0, ["missing"]);
    assert.strictEqual(failed, false);
  });

  it("addGroups prepends in source order and overwriteGroups resets state", async () => {
    const store = createStore([makeGroup("base")]);

    await store.addGroups([]);
    assert.deepStrictEqual(groupIds(store), ["base"]);
    assert.strictEqual(store.dataRevision, 0);

    await store.addGroups([makeGroup("g1"), makeGroup("g2")]);
    assert.deepStrictEqual(groupIds(store), ["g1", "g2", "base"]);
    assert.strictEqual(store.open_state.g1, true);
    assert.strictEqual(store.open_state.g2, true);

    store.renderGroupsLimit = 5;
    store.finishedGroupsCount = 9;
    await store.overwriteGroups([makeGroup("new1")]);
    assert.deepStrictEqual(groupIds(store), ["new1"]);
    assert.strictEqual("g1" in store.open_state, false);
    assert.strictEqual(store.open_state.new1, true);
    assert.strictEqual(store.renderGroupsLimit, 1);
    assert.strictEqual(store.finishedGroupsCount, 0);
  });

  it("addRulesToGroup prepends rules and no-ops for empty or invalid target", async () => {
    const store = createStore([makeGroup("g1", [makeRule("r1")])]);

    await store.addRulesToGroup(0, []);
    assert.deepStrictEqual(ruleIds(store, 0), ["r1"]);
    assert.strictEqual(store.dataRevision, 0);

    await store.addRulesToGroup(0, [makeRule("r2"), makeRule("r3")]);
    assert.deepStrictEqual(ruleIds(store, 0), ["r2", "r3", "r1"]);
    assert.strictEqual(store.dataRevision, 1);

    await store.addRulesToGroup(99, [makeRule("r4")]);
    assert.deepStrictEqual(ruleIds(store, 0), ["r2", "r3", "r1"]);
    assert.strictEqual(store.dataRevision, 1);
  });

  it("toConfigPayload returns detached snapshot of current groups", () => {
    const store = createStore([makeGroup("g1", [makeRule("r1")])]);

    const payload = store.toConfigPayload();
    payload.groups[0].name = "mutated";
    payload.groups[0].rules[0].rule = "mutated.example.com";

    assert.strictEqual(store.data[0].name, "group-g1");
    assert.strictEqual(store.data[0].rules[0].rule, "r1.example.com");
  });
});

describe("mergeOutside", () => {
  const r = (id: string, extra = {}) => ({ id, rule: id, type: "domain", enable: true, ...extra });
  const g = (id: string, rules: any[], extra = {}) =>
    ({ id, name: id, interface: "nwg0", enable: true, rules, ...extra }) as any;
  const merge = (current: any[], base: any[], daemon: any[]) =>
    mergeOutside(structuredClone(current), structuredClone(base), structuredClone(daemon));
  const ids = (groups: any[]) => groups.map((x) => [x.id, x.rules.map((y: any) => y.id)]);

  /* catches: a save putting back a rule the daemon added or removed since the load */
  it("rules: daemon additions and removals in, the operator's own kept", () => {
    const base = [g("a", [r("r1"), r("r2"), r("r3")])];
    const current = [g("a", [r("r1"), r("r3"), r("mine")])];
    const daemon = [g("a", [r("r1"), r("r2"), r("out")])];
    assert.deepStrictEqual(ids(merge(current, base, daemon)), [["a", ["r1", "mine", "out"]]]);
  });

  /* catches: an id-only merge switching an automatic-list rule back on and dropping its marker */
  it("a rule the daemon changed in place takes the daemon's fields the operator left alone", () => {
    const base = [g("a", [r("r1", { autolist: "h" }), r("r2")])];
    const current = [g("a", [r("r1", { autolist: "h" }), r("r2", { rule: "edited" })])];
    const daemon = [
      g("a", [r("r1", { autolist: "h", enable: false }), r("r2", { enable: false })]),
    ];
    const [a] = merge(current, base, daemon);
    assert.deepStrictEqual(a.rules[0], r("r1", { autolist: "h", enable: false }));
    assert.deepStrictEqual(a.rules[1], r("r2", { rule: "edited", enable: false }));
  });

  /* catches: a removed rule coming back, or an edited one lost, when the daemon deleted it */
  it("a rule the daemon deleted goes unless the operator changed it", () => {
    const base = [g("a", [r("r1"), r("r2")])];
    const current = [g("a", [r("r1"), r("r2", { rule: "edited" })])];
    const [a] = merge(current, base, [g("a", [])]);
    assert.deepStrictEqual(a.rules, [r("r2", { rule: "edited" })]);
  });

  /* catches: groups the daemon created or deleted overwritten, or the operator's choice undone */
  it("groups: born and lost on the daemon, created and deleted by the operator", () => {
    const base = [g("a", []), g("b", []), g("c", []), g("d", [])];
    const current = [g("a", []), g("c", [], { name: "renamed" }), g("d", []), g("new", [])];
    const daemon = [
      g("a", [], { live: true, liveReason: "x", active: "nwg0", interfaces: [] }),
      g("b", []),
      g("born", [r("x")], { live: true }),
    ];
    const out = merge(current, base, daemon);
    assert.deepStrictEqual(
      out.map((x: any) => x.id),
      ["a", "c", "new", "born"],
    );
    assert.strictEqual(out[1].name, "renamed");
    assert.ok(out.every((x: any) => !("live" in x) && !("interfaces" in x)));
  });

  /* catches: a list group another tab deleted put back because a sync changed its state here */
  it("a list group lost on the daemon goes although its sync state changed here", () => {
    const list = {
      url: "https://l/x.txt",
      interval: 86400,
      rulesTotal: 3,
      sync: { state: "idle" },
    };
    const base = [g("a", [], { list })];
    const current = [g("a", [], { list: { ...list, rulesTotal: 9, sync: { state: "fetching" } } })];
    assert.deepStrictEqual(merge(current, base, []), []);
  });

  /* catches: group fields from the daemon ignored, or the operator's edit of a field lost */
  it("group fields: the daemon's where the operator left a field, the operator's where changed", () => {
    const base = [g("a", [], { name: "A", enable: true, devices: { allow: [], deny: [] } })];
    const current = [g("a", [], { name: "mine", enable: true, devices: { allow: [], deny: [] } })];
    const daemon = [
      g("a", [], { name: "theirs", enable: false, devices: { allow: ["x"], deny: [] } }),
    ];
    const [a] = merge(current, base, daemon);
    assert.strictEqual(a.name, "mine");
    assert.strictEqual(a.enable, false);
    assert.deepStrictEqual(a.devices, { allow: ["x"], deny: [] });
  });
});
