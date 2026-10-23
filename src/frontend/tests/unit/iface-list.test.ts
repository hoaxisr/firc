import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

const {
  ifaceList,
  ifaceValue,
  toggleEntry,
  entryNumber,
  canBackup,
  chainLabel,
  backupNote,
  backupText,
} = await import("../../src/modules/groups/iface-list");

describe("a group's interface list", () => {
  it("reads a string as one entry and a list as itself", () => {
    assert.deepStrictEqual(ifaceList({ interface: "nwg0" }), ["nwg0"]);
    assert.deepStrictEqual(ifaceList({ interface: ["nwg0", "tunvless0"] }), ["nwg0", "tunvless0"]);
    assert.deepStrictEqual(ifaceList({ interface: "" }), [""]);
  });
  it("hands out a copy, never the group's own list", () => {
    const group = { interface: ["nwg0", "nwg1"] };
    ifaceList(group).push("nwg2");
    assert.deepStrictEqual(group.interface, ["nwg0", "nwg1"]);
  });
  it("writes a list of one as a string", () => {
    assert.strictEqual(ifaceValue(["nwg0"]), "nwg0");
    assert.deepStrictEqual(ifaceValue(["nwg0", "nwg1"]), ["nwg0", "nwg1"]);
  });
});

describe("toggleEntry", () => {
  it("appends a free interface as the next backup", () => {
    assert.deepStrictEqual(toggleEntry(["wg0"], "nwg0"), ["wg0", "nwg0"]);
    assert.deepStrictEqual(toggleEntry(["wg0", "nwg0"], "eth1"), ["wg0", "nwg0", "eth1"]);
  });
  it("removes a listed interface and keeps the order of the rest", () => {
    assert.deepStrictEqual(toggleEntry(["wg0", "nwg0", "eth1"], "nwg0"), ["wg0", "eth1"]);
    assert.deepStrictEqual(toggleEntry(["wg0", "nwg0"], "wg0"), ["nwg0"]);
  });
  it("never removes the last entry", () => {
    assert.deepStrictEqual(toggleEntry(["wg0"], "wg0"), ["wg0"]);
  });
  it("never adds a fifth entry", () => {
    assert.deepStrictEqual(toggleEntry(["a", "b", "c", "d"], "e"), ["a", "b", "c", "d"]);
  });
  it("never puts blackhole in a list", () => {
    assert.deepStrictEqual(toggleEntry(["wg0"], "blackhole"), ["wg0"]);
    assert.deepStrictEqual(toggleEntry(["blackhole"], "wg0"), ["blackhole"]);
  });
  it("returns a new array", () => {
    const l = ["wg0"];
    assert.notStrictEqual(toggleEntry(l, "wg0"), l);
  });
});

describe("entryNumber", () => {
  it("numbers entries from 1, null for a free interface", () => {
    assert.strictEqual(entryNumber(["wg0", "nwg0"], "wg0"), 1);
    assert.strictEqual(entryNumber(["wg0", "nwg0"], "nwg0"), 2);
    assert.strictEqual(entryNumber(["wg0", "nwg0"], "eth1"), null);
  });
});

describe("canBackup", () => {
  it("offers a circle on listed rows and on free rows below the cap", () => {
    assert.strictEqual(canBackup(["wg0"], "nwg0"), true);
    assert.strictEqual(canBackup(["wg0"], "wg0"), true);
    assert.strictEqual(canBackup(["a", "b", "c", "d"], "e"), false);
    assert.strictEqual(canBackup(["a", "b", "c", "d"], "b"), true);
  });
  it("offers no circle for blackhole, nor on a blackhole group", () => {
    assert.strictEqual(canBackup(["wg0"], "blackhole"), false);
    assert.strictEqual(canBackup(["blackhole"], "wg0"), false);
  });
  // Catches block offered as a backup, or a block group given circles, so a list could hold it.
  it("offers no circle for block, nor on a block group", () => {
    assert.strictEqual(canBackup(["wg0"], "block"), false);
    assert.strictEqual(canBackup(["block"], "wg0"), false);
    assert.deepStrictEqual(toggleEntry(["wg0"], "block"), ["wg0"]);
  });
});

describe("chainLabel", () => {
  it("joins entries with an arrow", () => {
    assert.strictEqual(chainLabel(["wg0"]), "wg0");
    assert.strictEqual(chainLabel(["wg0", "nwg0", "eth1"]), "wg0 → nwg0 → eth1");
  });
});

describe("backupNote", () => {
  const live = (active: string, since = 1790000000) => ({
    live: true,
    active,
    interfaces: [
      { name: "wg0", state: "dead" as const, since, error: "timed out" },
      { name: "nwg0", state: "alive" as const, since: 1789990000, error: "" },
    ],
  });
  it("is null on the first entry, for a single entry, or without live data", () => {
    assert.strictEqual(backupNote(["wg0", "nwg0"], live("wg0")), null);
    assert.strictEqual(backupNote(["wg0"], { live: true, active: "nwg0" }), null);
    assert.strictEqual(backupNote(["wg0", "nwg0"], undefined), null);
  });
  it("names the backup, the first entry and since when the first is down", () => {
    assert.deepStrictEqual(backupNote(["wg0", "nwg0"], live("nwg0")), {
      active: "nwg0",
      first: "wg0",
      since: 1790000000,
    });
  });
  it("is null when every entry is down, and only then among the not-live groups", () => {
    const blocked = { ...live("nwg0"), live: false, liveReason: "no-interface" as const };
    assert.strictEqual(backupNote(["wg0", "nwg0"], blocked), null);
    const unwritten = { ...live("nwg0"), live: false, liveReason: "not-written" as const };
    assert.strictEqual(backupNote(["wg0", "nwg0"], unwritten)?.active, "nwg0");
  });
  it("uses the saved first entry, not the live list order", () => {
    assert.strictEqual(backupNote(["eth1", "nwg0"], live("nwg0"))?.first, "eth1");
  });
});

describe("backupText", () => {
  const t = (key: string) => key;
  const clock = (unix: number) => `@${unix}`;
  it("names the backup, the first entry and the time it went down", () => {
    assert.strictEqual(
      backupText({ active: "nwg0", first: "wg0", since: 1790000000 }, t, clock),
      "Running on backup nwg0 · first wg0 down since @1790000000",
    );
  });
  it("drops the time when the first entry's state has none", () => {
    assert.strictEqual(
      backupText({ active: "nwg0", first: "wg0", since: 0 }, t, clock),
      "Running on backup nwg0 · first wg0 down",
    );
  });
});
