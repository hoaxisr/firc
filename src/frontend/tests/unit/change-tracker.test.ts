import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { ChangeTracker } = await import("../../src/utils/change-tracker.svelte");

type RuleItem = {
  id: string;
  name: string;
  type: string;
  rule: string;
  enable: boolean;
};

const createItem = (overrides: Partial<RuleItem> = {}): RuleItem => ({
  id: "1",
  name: "Test Rule",
  type: "namespace",
  rule: "example.com",
  enable: true,
  ...overrides,
});

describe("ChangeTracker", () => {
  it("should initialize clean", () => {
    const data = [createItem({ id: "1" })];
    const tracker = new ChangeTracker(data);

    assert.strictEqual(tracker.isDirty, false);
    assert.strictEqual(tracker.changes.added.length, 0);
    assert.strictEqual(tracker.changes.deleted.length, 0);
    assert.strictEqual(tracker.changes.mutated.length, 0);
  });

  describe("Changes: Mutated", () => {
    it("should track mutated objects", () => {
      const data = [createItem({ id: "1", name: "Old" })];
      const tracker = new ChangeTracker(data);
      const proxy = tracker.data;

      proxy[0].name = "New";

      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.mutated.length, 1);
      assert.strictEqual(tracker.changes.mutated[0].id, "1");
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should stop tracking mutation if reverted", () => {
      const data = [createItem({ id: "1", name: "Old" })];
      const tracker = new ChangeTracker(data);
      const proxy = tracker.data;

      proxy[0].name = "New";
      assert.strictEqual(tracker.changes.mutated.length, 1);

      proxy[0].name = "Old";
      assert.strictEqual(tracker.changes.mutated.length, 0);
      assert.strictEqual(tracker.isDirty, false);
    });
  });

  describe("Changes: Added", () => {
    it("should track added objects", () => {
      const tracker = new ChangeTracker<RuleItem[]>([]);
      const proxy = tracker.data;
      const newItem = createItem({ id: "new1" });

      proxy.push(newItem);

      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.added.length, 1);
      assert.strictEqual(tracker.changes.added[0].id, "new1");
      assert.strictEqual(tracker.changes.mutated.length, 0);
    });

    it("should not track added object if it is subsequently removed", () => {
      const tracker = new ChangeTracker<RuleItem[]>([]);
      const proxy = tracker.data;
      const newItem = createItem({ id: "new1" });

      proxy.push(newItem);
      assert.strictEqual(tracker.changes.added.length, 1);

      proxy.pop();
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
      assert.strictEqual(tracker.isDirty, false);
    });
  });

  describe("Changes: Deleted", () => {
    it("should track deleted objects", () => {
      const data = [createItem({ id: "1" })];
      const tracker = new ChangeTracker(data);
      const proxy = tracker.data;

      proxy.pop();

      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.deleted.length, 1);
      assert.strictEqual(tracker.changes.deleted[0].id, "1");
      assert.strictEqual(tracker.changes.added.length, 0);
    });

    it("should not track deleted object if it is added back", () => {
      const item = createItem({ id: "1" });
      const tracker = new ChangeTracker([item]);
      const proxy = tracker.data;

      const removed = proxy.pop();
      assert.strictEqual(tracker.changes.deleted.length, 1);

      proxy.push(removed!);
      assert.strictEqual(tracker.changes.deleted.length, 0);
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.isDirty, false);
    });
  });

  describe("Changes: Mixed Scenarios", () => {
    it("should track add, delete and mutate simultaneously", () => {
      const i1 = createItem({ id: "1" });
      const i2 = createItem({ id: "2" });
      const tracker = new ChangeTracker([i1, i2]);
      const proxy = tracker.data;

      proxy[0].name = "Mutated";
      proxy.pop();
      proxy.push(createItem({ id: "3" }));

      const { added, deleted, mutated } = tracker.changes;

      assert.strictEqual(mutated.length, 1);
      assert.strictEqual(mutated[0].id, "1");

      assert.strictEqual(deleted.length, 1);
      assert.strictEqual(deleted[0].id, "2");

      assert.strictEqual(added.length, 1);
      assert.strictEqual(added[0].id, "3");
    });

    it("should not consider reordering as mutation of objects", () => {
      const i1 = createItem({ id: "1" });
      const i2 = createItem({ id: "2" });
      const tracker = new ChangeTracker([i1, i2]);
      const proxy = tracker.data;

      proxy.reverse();

      assert.strictEqual(tracker.isDirty, true);

      assert.strictEqual(tracker.changes.mutated.length, 0);
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should handle nested structures correctly", () => {
      const root = {
        id: "root",
        list: [createItem({ id: "child1" })],
      };
      const tracker = new ChangeTracker(root);
      const proxy = tracker.data;

      proxy.list.push(createItem({ id: "child2" }));

      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.added.length, 1);
      assert.strictEqual(tracker.changes.added[0].id, "child2");

      proxy.list[0].name = "Changed";
      assert.strictEqual(tracker.changes.mutated.length, 1);
      assert.strictEqual(tracker.changes.mutated[0].id, "child1");
    });
  });

  describe("Reset", () => {
    it("should clear changes on reset", () => {
      const tracker = new ChangeTracker([createItem({ id: "1" })]);
      tracker.data.pop();

      assert.strictEqual(tracker.changes.deleted.length, 1);

      tracker.reset([]);

      assert.strictEqual(tracker.isDirty, false);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should update data in place on reset", () => {
      const oldData = [createItem({ id: "1" })];
      const newData = [createItem({ id: "2" })];
      const tracker = new ChangeTracker(oldData);

      tracker.reset(newData);

      assert.strictEqual(tracker.data[0].id, "2");
      assert.strictEqual(tracker.isDirty, false);
    });

    it("should expose a fresh root proxy after reset so add/delete acknowledgements still work", () => {
      const tracker = new ChangeTracker([createItem({ id: "1" })]);
      const firstProxy = tracker.data;

      tracker.reset([createItem({ id: "1" })]);

      const secondProxy = tracker.data;
      const added = createItem({ id: "2" });

      assert.notStrictEqual(secondProxy, firstProxy);

      secondProxy.push(added);
      tracker.acknowledgeNewItem(secondProxy, added, "end");
      assert.strictEqual(tracker.isDirty, false);

      secondProxy.pop();
      tracker.acknowledgeDelete(secondProxy, "2");
      assert.strictEqual(tracker.isDirty, false);
    });
  });

  describe("Nested Data (Groups -> Rules)", () => {
    const getComplexData = () => [
      {
        id: "g1",
        name: "Group 1",
        enable: true,
        rules: [
          { id: "r1", name: "Rule 1", type: "ns", rule: "abc.com", enable: true },
          { id: "r2", name: "Rule 2", type: "ns", rule: "xyz.com", enable: true },
        ],
      },
      {
        id: "g2",
        name: "Group 2",
        enable: true,
        rules: [],
      },
    ];

    it("should track adding a rule to a nested group", () => {
      const tracker = new ChangeTracker(getComplexData());
      const proxy = tracker.data;

      const newRule = { id: "r3", name: "New Rule", type: "ns", rule: "new.com", enable: true };
      proxy[1].rules.push(newRule);

      assert.strictEqual(tracker.isDirty, true);

      const { added, mutated } = tracker.changes;
      assert.strictEqual(added.length, 1);
      assert.strictEqual(added[0].id, "r3");

      assert.strictEqual(mutated.length, 0);
    });

    it("should track deleting a rule from a nested group", () => {
      const tracker = new ChangeTracker(getComplexData());
      const proxy = tracker.data;

      proxy[0].rules.shift();

      assert.strictEqual(tracker.isDirty, true);

      const { deleted } = tracker.changes;
      assert.strictEqual(deleted.length, 1);
      assert.strictEqual(deleted[0].id, "r1");
    });

    it("should track mutating a field deeply nested", () => {
      const tracker = new ChangeTracker(getComplexData());
      const proxy = tracker.data;

      proxy[0].rules[1].name = "Renamed Rule 2";

      assert.strictEqual(tracker.isDirty, true);

      const { mutated } = tracker.changes;
      assert.strictEqual(mutated.length, 1);
      assert.strictEqual(mutated[0].id, "r2");
    });

    it("should track mutation of the group itself mixed with rule changes", () => {
      const tracker = new ChangeTracker(getComplexData());
      const proxy = tracker.data;

      proxy[0].name = "Renamed Group 1";
      proxy[0].rules.push({ id: "r99", name: "", type: "", rule: "", enable: true });

      const { added, mutated } = tracker.changes;

      const groupChange = mutated.find((x: any) => x.id === "g1");
      assert.ok(groupChange);

      const ruleAdd = added.find((x: any) => x.id === "r99");
      assert.ok(ruleAdd);
    });

    it("should handle group deletion (cascading delete)", () => {
      const tracker = new ChangeTracker(getComplexData());
      const proxy = tracker.data;

      proxy.shift();

      const { deleted } = tracker.changes;

      assert.strictEqual(deleted.length, 3);
      assert.ok(deleted.find((x: any) => x.id === "g1"));
      assert.ok(deleted.find((x: any) => x.id === "r1"));
      assert.ok(deleted.find((x: any) => x.id === "r2"));
    });
  });
  describe("Partial Commits (acknowledge methods)", () => {
    it("should acknowledge a mutation and make it clean", () => {
      const data = [createItem({ id: "1", name: "Old" })];
      const tracker = new ChangeTracker(data);
      const proxy = tracker.data;

      proxy[0].name = "New";
      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.mutated.length, 1);

      tracker.acknowledgeUpdate(proxy[0]);

      assert.strictEqual(tracker.isDirty, false);
      assert.strictEqual(tracker.changes.mutated.length, 0);
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should acknowledge a new item and make it clean", () => {
      const tracker = new ChangeTracker<RuleItem[]>([]);
      const proxy = tracker.data;
      const newItem = createItem({ id: "new1", name: "Added" });

      proxy.push(newItem);
      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.added.length, 1);

      tracker.acknowledgeNewItem(proxy, newItem, "end");

      assert.strictEqual(tracker.isDirty, false);
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.mutated.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should acknowledge a new item at start and maintain order", () => {
      const existing = createItem({ id: "1" });
      const tracker = new ChangeTracker([existing]);
      const proxy = tracker.data;

      const newItem = createItem({ id: "new1" });
      proxy.unshift(newItem);

      assert.strictEqual(tracker.isDirty, true);

      tracker.acknowledgeNewItem(proxy, newItem, "start");

      assert.strictEqual(tracker.isDirty, false);
      assert.strictEqual(proxy[0].id, "new1");
      assert.strictEqual(proxy[1].id, "1");
    });

    it("should handle acknowledged update mixed with other dirty states", () => {
      const i1 = createItem({ id: "1", name: "A" });
      const i2 = createItem({ id: "2", name: "B" });
      const tracker = new ChangeTracker([i1, i2]);
      const proxy = tracker.data;

      proxy[0].name = "A_Changed";
      proxy[1].name = "B_Changed";

      assert.strictEqual(tracker.changes.mutated.length, 2);

      tracker.acknowledgeUpdate(proxy[1]);

      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.mutated.length, 1);
      assert.strictEqual(tracker.changes.mutated[0].id, "1");
    });

    it("should preserve unrelated dirty fields when acknowledging specific persisted fields", () => {
      const tracker = new ChangeTracker([
        {
          id: "sub1",
          name: "Original",
          interface: "all",
          interval: 60,
          enable: true,
          lastUpdate: 0,
          rules: [createItem({ id: "rule1" })],
        },
      ]);
      const proxy = tracker.data;

      proxy[0].name = "Unsaved";
      proxy[0].rules.push(createItem({ id: "rule-local" }));

      tracker.acknowledgeUpdate(proxy[0], {
        rules: [createItem({ id: "rule-server" })],
        lastUpdate: 123,
      });

      assert.strictEqual(proxy[0].name, "Unsaved");
      assert.strictEqual(proxy[0].lastUpdate, 123);
      assert.deepStrictEqual(
        proxy[0].rules.map((rule: RuleItem) => rule.id),
        ["rule-server"],
      );
      assert.strictEqual(tracker.isDirty, true);
      assert.deepStrictEqual(
        tracker.changes.mutated.map((item: { id: string }) => item.id),
        ["sub1"],
      );
      assert.strictEqual(tracker.changes.added.length, 0);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should acknowledge a deletion and make array clean", () => {
      const item = createItem({ id: "1" });
      const tracker = new ChangeTracker([item]);
      const proxy = tracker.data;

      proxy.pop();
      assert.strictEqual(tracker.isDirty, true);
      assert.strictEqual(tracker.changes.deleted.length, 1);

      tracker.acknowledgeDelete(proxy, "1");

      assert.strictEqual(tracker.isDirty, false);
      assert.strictEqual(tracker.changes.deleted.length, 0);
    });

    it("should clean up dirty state of children when parent is updated", () => {
      const tracker = new ChangeTracker([
        { id: "p1", name: "Parent", children: [{ id: "c1", name: "Child" }] },
      ]);
      const proxy = tracker.data;

      proxy[0].children[0].name = "Child Modified";
      assert.strictEqual(tracker.isDirty, true);

      tracker.acknowledgeUpdate(proxy[0]);

      assert.strictEqual(
        tracker.isDirty,
        false,
        "Tracker should be clean after acknowledging parent update",
      );
    });

    it("should clean up dirty state of children when parent is deleted", () => {
      const tracker = new ChangeTracker([
        { id: "p1", name: "Parent", children: [{ id: "c1", name: "Child" }] },
      ]);
      const proxy = tracker.data;

      proxy[0].children[0].name = "Child Modified";
      assert.strictEqual(tracker.isDirty, true);

      proxy.pop();
      tracker.acknowledgeDelete(proxy, "p1");

      if (tracker.isDirty) {
        console.log("Dirty Objects:", tracker["dirtyObjectProps"]);
        console.log("Dirty Arrays:", tracker["dirtyArrays"]);
      }

      assert.strictEqual(
        tracker.isDirty,
        false,
        "Tracker should be clean after acknowledging parent delete",
      );
    });
  });
});
