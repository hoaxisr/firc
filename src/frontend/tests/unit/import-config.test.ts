import { deepStrictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { groupsFromFile } from "../../src/modules/groups/groups-data.ts";

const FILE = JSON.stringify({
  groups: [
    {
      id: "a3509784",
      name: "Tests",
      color: "#4e405f",
      interface: "blackhole",
      enable: false,
      rules: [{ id: "37e03b4c", name: "1", type: "namespace", rule: "a.ru", enable: true }],
    },
    {
      id: "8442a01d",
      name: "Roblox",
      color: "#76384a",
      interface: "blackhole",
      enable: false,
      rules: [
        { id: "eb06efbc", name: "", type: "subnet", rule: "128.116.0.0/17", enable: true },
        { id: "51e6776c", name: "", type: "domain", rule: "roblox.com", enable: true },
      ],
    },
  ],
});

describe("an imported config file", () => {
  // Catches a .mtrickle file kept in its own order, where the last group wins.
  it("turns a .mtrickle file's groups upside down", () => {
    const groups = groupsFromFile("export.mtrickle", FILE);
    deepStrictEqual(
      groups.map((g) => g.name),
      ["Roblox", "Tests"],
    );
    deepStrictEqual(
      groups[0].rules.map((r) => r.rule),
      ["128.116.0.0/17", "roblox.com"],
    );
    deepStrictEqual(
      groupsFromFile("EXPORT.MTRICKLE", FILE).map((g) => g.name),
      ["Roblox", "Tests"],
    );
  });

  // Catches firc's own file reversed too.
  it("keeps a .firc file's order", () => {
    deepStrictEqual(
      groupsFromFile("config.firc", FILE).map((g) => g.name),
      ["Tests", "Roblox"],
    );
  });
});
