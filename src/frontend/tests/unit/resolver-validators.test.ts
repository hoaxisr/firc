import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { resolverAddrProblem } from "../../src/utils/resolver-validators.ts";

describe("resolverAddrProblem", () => {
  it("accepts each shape the daemon accepts", () => {
    for (const ok of [
      "9.9.9.9",
      "9.9.9.9:5353",
      "2620:fe::fe",
      "[2620:fe::fe]:853",
      "[2620:fe::fe]",
      "2620:fe::fe:53",
      "9.9.9.9:65535",
      "9.9.9.9:1",
      "126.255.255.255",
      "128.0.0.1",
      "0.0.0.1",
      "::2",
    ]) {
      assert.strictEqual(resolverAddrProblem(ok), null, ok);
    }
  });

  it("refuses what is not an address literal", () => {
    for (const bad of [
      "",
      "dns.google",
      "9.9.9",
      "9.9.9.9:",
      "[9.9.9.9]",
      "[9.9.9.9]:53",
      "[2620:fe::fe",
      "2620:fe::fe]",
      "9.9.9.9:53x",
      " 9.9.9.9",
      "9.9.9.9 ",
      "[2620:fe::fe]53",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "syntax", bad);
    }
  });

  it("refuses a port outside 1..65535", () => {
    for (const bad of [
      "9.9.9.9:0",
      "9.9.9.9:65536",
      "9.9.9.9:+53",
      "9.9.9.9:053535",
      "[2620:fe::fe]:0",
      "9.9.9.9:-1",
      "9.9.9.9:+",
      "[::1]:-",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "port", bad);
    }
  });

  it("refuses sinks and IPv4-mapped addresses", () => {
    for (const bad of [
      "0.0.0.0",
      "127.0.0.1",
      "127.255.255.254:53",
      "::",
      "::1",
      "[::1]:53",
      "[::]:5353",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "sink", bad);
    }
    assert.strictEqual(resolverAddrProblem("::ffff:127.0.0.1"), "mapped");
    assert.strictEqual(resolverAddrProblem("::ffff:9.9.9.9"), "mapped");
  });
});
