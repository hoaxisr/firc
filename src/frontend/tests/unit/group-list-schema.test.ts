import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";
import { array, parse } from "valibot";

import { GroupSchema } from "../../src/types";

const record = (over: Record<string, unknown> = {}) => ({
  id: "a1b2c3d4",
  name: "group",
  interface: "eth0",
  enable: true,
  rules: [],
  list: {
    url: "https://example.com/list.txt",
    rulesTotal: 3,
    lastUpdate: 1700000000,
    interval: 86400,
    sync: { state: "idle", error: "", lastCheck: 0 },
  },
  ...over,
});

describe("a group's list, from the daemon", () => {
  // Catches a fallback id drawn once at load, so every unusable id becomes the same one.
  it("gives two unusable ids two different ones", () => {
    const [first, second] = parse(array(GroupSchema), [
      record({ id: "nonsense" }),
      record({ id: "" }),
    ]);

    assert.match(first.id, /^[0-9a-f]{8}$/);
    assert.match(second.id, /^[0-9a-f]{8}$/);
    assert.notStrictEqual(first.id, second.id, "two records must not be handed the same id");
  });

  // Catches a list schema stricter than the daemon, refusing a config over one thin record.
  it("survives a list with no url", () => {
    const thin: Record<string, unknown> = record();
    delete (thin.list as Record<string, unknown>).url;

    const [parsed] = parse(array(GroupSchema), [thin]);
    assert.strictEqual(parsed.list?.url, "");
    assert.strictEqual(parsed.id, "a1b2c3d4", "and the rest of it is untouched");
  });

  // GET /groups never sends a list's rules; the schema must keep only the count and sync state.
  it("keeps a list to its count, never its rules", () => {
    const [parsed] = parse(array(GroupSchema), [record()]);
    assert.strictEqual(parsed.list?.rulesTotal, 3);
    assert.deepStrictEqual(parsed.list?.sync, { state: "idle", error: "", lastCheck: 0 });
    assert.strictEqual((parsed.list as any).rules, undefined);
  });

  // Catches a list being conjured from fallbacks for a group that has none.
  it("leaves a group with no list as having none", () => {
    const thin: Record<string, unknown> = record();
    delete thin.list;
    const [parsed] = parse(array(GroupSchema), [thin]);
    assert.strictEqual(parsed.list, undefined);
  });

  // Catches the schema stripping a group's device selector.
  it("keeps a group's device selector", () => {
    const [parsed] = parse(array(GroupSchema), [
      record({ devices: { allow: ["192.168.1.0/24"], deny: ["192.168.1.5"] } }),
    ]);
    assert.deepStrictEqual(parsed.devices, {
      allow: ["192.168.1.0/24"],
      deny: ["192.168.1.5"],
    });
  });
});
