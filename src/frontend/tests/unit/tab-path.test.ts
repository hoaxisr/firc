import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { journalViewFromPath, pathOfTab, tabFromPath } from "../../src/utils/tab-path.ts";

describe("a tab's address", () => {
  // Catches a tab reached by its internal id instead of the title the UI shows.
  it("is named after the title", () => {
    assert.deepStrictEqual(["groups", "tunnels", "logs", "settings"].map(pathOfTab), [
      "/groups",
      "/tunnels",
      "/journal",
      "/settings",
    ]);
  });

  // Catches the root, an internal id or an unknown path opening anything but Groups.
  it("opens Groups for every address that is not a tab", () => {
    for (const p of ["/", "/logs", "/nope", "/journal/x", ""]) {
      assert.strictEqual(tabFromPath(p), "groups", p);
    }
  });

  // Catches an address mapped back to the wrong tab.
  it("reads each tab back from its address", () => {
    for (const tab of ["groups", "tunnels", "logs", "settings"]) {
      assert.strictEqual(tabFromPath(pathOfTab(tab)), tab);
    }
  });

  // Catches a Journal sub-tab with no address of its own, or a sub-tab suffix on another tab.
  it("gives each Journal sub-tab its own address under /journal", () => {
    assert.deepStrictEqual(
      (["events", "stats", "capture"] as const).map((v) => pathOfTab("logs", v)),
      ["/journal", "/journal/stats", "/journal/capture"],
    );
    assert.strictEqual(pathOfTab("settings", "stats"), "/settings");
  });

  // Catches a sub-tab address opening Groups, or the wrong sub-tab.
  it("reads the Journal and its sub-tab back from a sub-tab's address", () => {
    for (const view of ["events", "stats", "capture"] as const) {
      assert.strictEqual(tabFromPath(pathOfTab("logs", view)), "logs");
      assert.strictEqual(journalViewFromPath(pathOfTab("logs", view)), view);
    }
    for (const p of ["/journal/x", "/journal/", "/stats", "/groups"]) {
      assert.strictEqual(journalViewFromPath(p), "events", p);
    }
  });
});
