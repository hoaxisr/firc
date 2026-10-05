import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import {
  selectableIds,
  selectedInOrder,
  selectionCountText,
  toggleId,
} from "../../src/modules/groups/selection.ts";
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

const makeGroup = (id: string, iface = "wg0", enable = true) => ({
  id,
  name: `group-${id}`,
  interface: iface,
  enable,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [{ id: `r${id}`, enable: true, rule: `${id}.example.com`, type: "domain" }],
});

function seeded(groups: ReturnType<typeof makeGroup>[]) {
  const store = new GroupsStore();
  const cloned = structuredClone(groups);
  store.tracker.reset(cloned);
  store.resetListMetaBaseline(cloned);
  return store;
}

const ids = (groups: { id: string }[]) => groups.map((g) => g.id);

function withConfirm<T>(answer: boolean, action: () => T): { result: T; asked: string[] } {
  const asked: string[] = [];
  const restore = patchGlobal("confirm", (message: string) => {
    asked.push(message);
    return answer;
  });
  try {
    return { result: action(), asked };
  } finally {
    restore();
  }
}

describe("the selection, as pure functions", () => {
  // Catches a second click leaving the group selected, or the toggle mutating its input array.
  it("toggles an id in and out without touching the input", () => {
    const start = ["a"];
    const added = toggleId(start, "b");
    assert.deepStrictEqual(added, ["a", "b"]);
    assert.deepStrictEqual(start, ["a"]);
    assert.deepStrictEqual(toggleId(added, "a"), ["b"]);
  });

  // Catches a deleted group still counted, or the order following the clicks instead of the page.
  it("keeps only groups that still exist, in page order", () => {
    const groups = [{ id: "a" }, { id: "b" }, { id: "c" }];
    assert.deepStrictEqual(selectedInOrder(["c", "gone", "a"], groups), ["a", "c"]);
    assert.deepStrictEqual(selectedInOrder([], groups), []);
  });

  // Catches Select all under a search picking hidden groups, or fewer than all without one.
  it("selects all groups, or only the ones a search shows", () => {
    const groups = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }];
    const shown = new Map<number, null>([
      [1, null],
      [3, null],
    ]);
    assert.deepStrictEqual(selectableIds(groups, false, shown), ["a", "b", "c", "d"]);
    assert.deepStrictEqual(selectableIds(groups, true, shown), ["b", "d"]);
    assert.deepStrictEqual(selectableIds(groups, true, new Map()), []);
  });

  // Catches the wrong Russian plural form in the count.
  it("counts the selection in Russian and English", () => {
    const tr = (key: string) => (ru as Record<string, string>)[key] ?? key;
    const en = (key: string) => key;
    const want: [number, string][] = [
      [1, "1 выбрана"],
      [3, "3 выбраны"],
      [5, "5 выбрано"],
      [11, "11 выбрано"],
      [21, "21 выбрана"],
      [24, "24 выбраны"],
    ];
    for (const [n, text] of want) assert.strictEqual(selectionCountText(n, "ru", tr), text);
    assert.strictEqual(selectionCountText(1, "en", en), "1 group selected");
    assert.strictEqual(selectionCountText(3, "en", en), "3 groups selected");
  });
});

describe("GroupsStore bulk actions", () => {
  // Catches selecting a group marking the form edited (Save lit).
  it("selecting is not an edit", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.toggleSelected("a");
    assert.deepStrictEqual(store.selection, ["a"]);
    assert.strictEqual(store.isSelected("a"), true);
    assert.strictEqual(store.isSelected("b"), false);
    assert.strictEqual(store.canSave, false);
    store.clearSelection();
    assert.deepStrictEqual(store.selection, []);
  });

  // Catches the selection following the index instead of the id after a reorder.
  it("a selection survives a reorder", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.changeGroupIndex(0, 2, "after");
    assert.deepStrictEqual(ids(store.data), ["b", "c", "a"]);
    assert.deepStrictEqual(store.selection, ["a"]);
  });

  // Catches the bulk interface skipping a selected group, touching another, or bypassing the tracker.
  it("sets the interface of every selected group as an edit", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");
    store.setSelectedInterface("nwg1");
    assert.deepStrictEqual(
      store.data.map((g) => g.interface),
      ["nwg1", "wg0", "nwg1"],
    );
    assert.strictEqual(store.canSave, true);
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    assert.strictEqual(store.groupDirty(store.data[1]), false);
  });

  // Catches enable/disable applying the wrong value or to the wrong groups.
  it("enables and disables the selected groups", () => {
    const store = seeded([makeGroup("a"), makeGroup("b", "wg0", false), makeGroup("c")]);
    store.toggleSelected("b");
    store.toggleSelected("c");
    store.setSelectedEnable(true);
    assert.deepStrictEqual(
      store.data.map((g) => g.enable),
      [true, true, true],
    );
    store.setSelectedEnable(false);
    assert.deepStrictEqual(
      store.data.map((g) => g.enable),
      [true, false, false],
    );
  });

  // Catches Select all without a search missing a group.
  it("selects all groups without a search", async () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    await store.selectAll();
    assert.deepStrictEqual(store.selection, ["a", "b", "c"]);
  });

  // Catches a cancelled confirm deleting, a confirm without the count, or deleted groups lingering selected.
  it("deletes the selected groups after one confirm", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");

    const cancelled = withConfirm(false, () => store.deleteSelected());
    assert.strictEqual(cancelled.asked.length, 1);
    assert.match(cancelled.asked[0], /\(2\)/);
    assert.deepStrictEqual(ids(store.data), ["a", "b", "c"]);
    assert.deepStrictEqual(store.selection, ["a", "c"]);

    const accepted = withConfirm(true, () => store.deleteSelected());
    assert.strictEqual(accepted.asked.length, 1);
    assert.deepStrictEqual(ids(store.data), ["b"]);
    assert.deepStrictEqual(store.selection, []);
    assert.strictEqual(store.canSave, true);
  });

  // Catches a group deleted from its own card staying selected.
  it("a group deleted from its card leaves the selection", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.toggleSelected("a");
    store.toggleSelected("b");
    withConfirm(true, () => store.deleteGroup(0));
    assert.deepStrictEqual(store.selection, ["b"]);
    assert.deepStrictEqual(store.selectedIds, ["b"]);
  });
});
