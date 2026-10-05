import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  autoEffectiveServers,
  fallbackCountText,
  firmwareServersFor,
  isSavedAutoUnchanged,
  modeOf,
  resolveOf,
  resolverTag,
  serverSuggestions,
  submittedResolve,
} from "../../src/modules/groups/resolve-choice.ts";

const BENCH = [
  { interface: "nwg0", servers: ["9.9.9.9", "1.0.0.1"] },
  { interface: "nwg1", servers: ["1.1.1.1", "1.0.0.1"] },
];

describe("the dialog's DNS choice", () => {
  // Catches a group with a server reading as "auto", or "off" keeping a server.
  it("reads the three modes from resolve and writes them back", () => {
    assert.strictEqual(modeOf({ tunnel: true, server: "" }), "auto");
    assert.strictEqual(modeOf(undefined), "auto");
    assert.strictEqual(modeOf({ tunnel: true, server: "8.8.8.8" }), "own");
    assert.strictEqual(modeOf({ tunnel: false, server: "" }), "off");
    assert.strictEqual(modeOf({ tunnel: false, server: "8.8.8.8" }), "off");
    assert.deepStrictEqual(resolveOf("auto", "8.8.8.8"), { tunnel: true, server: "" });
    assert.deepStrictEqual(resolveOf("own", " 8.8.8.8 "), { tunnel: true, server: "8.8.8.8" });
    assert.deepStrictEqual(resolveOf("off", "8.8.8.8"), { tunnel: false, server: "" });
  });

  // Catches the effective list taken from another interface.
  it("shows the firmware's resolvers for the chosen interface only", () => {
    assert.deepStrictEqual(firmwareServersFor(BENCH, "nwg0"), ["9.9.9.9", "1.0.0.1"]);
    assert.deepStrictEqual(firmwareServersFor(BENCH, "nwg1"), ["1.1.1.1", "1.0.0.1"]);
    assert.deepStrictEqual(firmwareServersFor(BENCH, "ppp0"), []);
  });

  // Catches a missing or duplicated suggestion (1.0.0.1, 1.1.1.1, 9.9.9.9 overlap).
  it("suggests every firmware resolver and the well-known three, once each", () => {
    assert.deepStrictEqual(serverSuggestions(BENCH), ["9.9.9.9", "1.0.0.1", "1.1.1.1", "8.8.8.8"]);
    assert.deepStrictEqual(serverSuggestions([]), ["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
  });

  // Catches a new group, changed interface or changed mode still trusted as the saved auto state.
  it("trusts group.resolver only while nothing has moved the dialog off the group's saved auto state", () => {
    const group = { interface: "nwg0", resolve: { tunnel: true, server: "" } };
    assert.strictEqual(isSavedAutoUnchanged(group, "edit", "nwg0", "auto"), true);
    assert.strictEqual(isSavedAutoUnchanged(null, "create", "nwg0", "auto"), false);
    assert.strictEqual(isSavedAutoUnchanged(group, "edit", "nwg1", "auto"), false);
    assert.strictEqual(isSavedAutoUnchanged(group, "edit", "nwg0", "own"), false);
    const ownGroup = { interface: "nwg0", resolve: { tunnel: true, server: "9.9.9.9" } };
    assert.strictEqual(isSavedAutoUnchanged(ownGroup, "edit", "nwg0", "auto"), false);
  });

  // Catches the raw firmware list shown instead of what the daemon resolved through.
  it("shows what the daemon actually resolved through, not the raw firmware list, while editing a group's untouched auto state", () => {
    const firmwareServers = ["2606:4700::1111"];
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "firmware", servers: [], fallbacks: 0 },
        firmwareServers,
      }),
      [],
    );
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 },
        firmwareServers,
      }),
      ["9.9.9.9"],
    );
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "none", servers: [], fallbacks: 0 },
        firmwareServers,
      }),
      firmwareServers,
    );
    assert.deepStrictEqual(
      autoEffectiveServers({ isEditingSavedAuto: false, resolver: undefined, firmwareServers }),
      firmwareServers,
    );
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: false,
        resolver: { source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 },
        firmwareServers,
      }),
      firmwareServers,
    );
  });

  // Catches a blackhole group's stale dnsMode and server reaching the payload instead of its own resolve.
  it("a blackhole group submits its own resolve untouched, never the dialog's DNS control", () => {
    const stored = { tunnel: false, server: "" };
    assert.deepStrictEqual(submittedResolve(true, stored, "own", "127.0.0.1"), stored);
    assert.deepStrictEqual(submittedResolve(true, undefined, "own", "9.9.9.9"), {
      tunnel: true,
      server: "",
    });
    assert.deepStrictEqual(submittedResolve(false, stored, "own", " 9.9.9.9 "), {
      tunnel: true,
      server: "9.9.9.9",
    });
  });
});

const id = (s: string) => s;

describe("the panel's resolver tag", () => {
  // Catches hidden servers, "none"/"off" read as a tunnel, a tag with no report, or a zero count shown.
  it("says where the group's names are resolved", () => {
    assert.strictEqual(
      resolverTag({ source: "firmware", servers: ["9.9.9.9", "1.0.0.1"], fallbacks: 0 }, id),
      "DNS 9.9.9.9, 1.0.0.1",
    );
    assert.strictEqual(
      resolverTag({ source: "group", servers: ["[2620:fe::fe]:853"], fallbacks: 0 }, id),
      "DNS [2620:fe::fe]:853",
    );
    assert.strictEqual(
      resolverTag({ source: "none", servers: [], fallbacks: 0 }, id),
      "DNS: common upstream",
    );
    assert.strictEqual(
      resolverTag({ source: "off", servers: [], fallbacks: 0 }, id),
      "DNS: not through the tunnel",
    );
    assert.strictEqual(
      resolverTag({ source: "group", servers: [], fallbacks: 0 }, id),
      "DNS: common upstream",
    );
    assert.strictEqual(resolverTag(undefined, id), null);
  });

  it("counts fallbacks only when there are some", () => {
    assert.strictEqual(
      fallbackCountText({ source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 }, id),
      null,
    );
    assert.strictEqual(
      fallbackCountText({ source: "firmware", servers: ["9.9.9.9"], fallbacks: 12 }, id),
      "fallbacks: 12",
    );
    assert.strictEqual(fallbackCountText(undefined, id), null);
  });
});
