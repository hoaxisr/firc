import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { interfaces, groupInterfaces } = await import("../../src/data/interfaces.svelte");
const { defaultGroup } = await import("../../src/utils/defaults");

describe("group interfaces", () => {
  // Catches an uplink-only interface offered to groups, or given to a new group as its default.
  it("leave out uplink-only interfaces, also as a new group's default", () => {
    interfaces.list = [
      { id: "ppp0", name: "Broadband", uplinkOnly: true },
      { id: "wg0" },
      { id: "eth3", uplinkOnly: false },
    ];
    assert.deepStrictEqual(
      groupInterfaces().map((i) => i.id),
      ["wg0", "eth3"],
    );
    assert.strictEqual(defaultGroup().interface, "wg0");
  });
});
