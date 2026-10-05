import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import type { Rule } from "../../src/types";
import { sortRules } from "../../src/utils/rule-sorter";

const createRule = (overrides: Partial<Rule>): Rule => ({
  id: "1",
  enable: true,
  rule: "",
  type: "domain", // default
  ...overrides,
});

describe("Rule Sorter", () => {
  it("should prioritize patterns correctly (Subnet > Wildcard > Domain > Regex)", () => {
    const rules = [
      createRule({ rule: "example.com", type: "domain" }),
      createRule({ rule: "192.168.1.0/24", type: "subnet" }),
      createRule({ rule: ".*", type: "regex" }),
      createRule({ rule: "*.example.com", type: "wildcard" }),
    ];

    const sorted = sortRules(rules, "asc");

    assert.strictEqual(sorted[0].type, "subnet");
    assert.strictEqual(sorted[1].type, "domain");
    assert.strictEqual(sorted[2].type, "wildcard");
    assert.strictEqual(sorted[3].type, "regex");
  });

  it("should sort subnets by IP and mask", () => {
    const rules = [
      createRule({ rule: "10.0.0.0/8", type: "subnet" }),
      createRule({ rule: "192.168.1.0/24", type: "subnet" }),
      createRule({ rule: "10.0.0.0/16", type: "subnet" }),
    ];

    const sorted = sortRules(rules, "asc");

    assert.strictEqual(sorted[0].rule, "10.0.0.0/16");
    assert.strictEqual(sorted[1].rule, "10.0.0.0/8");
    assert.strictEqual(sorted[2].rule, "192.168.1.0/24");
  });

  it("should sort domains by TLD, Base, Sub", () => {
    const rules = [
      createRule({ rule: "a.example.com", type: "domain" }),
      createRule({ rule: "b.example.com", type: "domain" }),
      createRule({ rule: "google.com", type: "domain" }),
      createRule({ rule: "example.org", type: "domain" }),
    ];

    const sorted = sortRules(rules, "asc");

    assert.strictEqual(sorted[0].rule, "a.example.com");
    assert.strictEqual(sorted[1].rule, "b.example.com");
    assert.strictEqual(sorted[2].rule, "example.org");
    assert.strictEqual(sorted[3].rule, "google.com");
  });
});
