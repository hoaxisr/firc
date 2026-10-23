import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import {
  autoEffectiveServers,
  firmwareServersFor,
  healthTag,
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

  it("reads a list group's saved auto state by the dialog's pick against its first entry", () => {
    const listed = { interface: ["nwg0", "nwg1"], resolve: { tunnel: true, server: "" } };
    assert.strictEqual(isSavedAutoUnchanged(listed, "edit", "nwg0", "auto"), true);
    assert.strictEqual(isSavedAutoUnchanged(listed, "edit", "nwg1", "auto"), false);
  });

  // Catches the raw firmware list shown instead of what the daemon resolved through.
  it("shows what the daemon actually resolved through, not the raw firmware list, while editing a group's untouched auto state", () => {
    const firmwareServers = ["2606:4700::1111"];
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "firmware", servers: [], health: CALM },
        firmwareServers,
      }),
      [],
    );
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "firmware", servers: ["9.9.9.9"], health: CALM },
        firmwareServers,
      }),
      ["9.9.9.9"],
    );
    assert.deepStrictEqual(
      autoEffectiveServers({
        isEditingSavedAuto: true,
        resolver: { source: "none", servers: [], health: CALM },
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
        resolver: { source: "firmware", servers: ["9.9.9.9"], health: CALM },
        firmwareServers,
      }),
      firmwareServers,
    );
  });

  // Catches a blackhole or block group's stale dnsMode and server reaching the payload instead of its own resolve.
  it("a blackhole or block group submits its own resolve untouched, never the dialog's DNS control", () => {
    const stored = { tunnel: false, server: "" };
    assert.deepStrictEqual(submittedResolve("block", undefined, "own", "9.9.9.9"), {
      tunnel: true,
      server: "",
    });
    assert.deepStrictEqual(submittedResolve("block", stored, "own", "127.0.0.1"), stored);
    assert.deepStrictEqual(submittedResolve("blackhole", stored, "own", "127.0.0.1"), stored);
    assert.deepStrictEqual(submittedResolve("nwg0", stored, "own", " 9.9.9.9 "), {
      tunnel: true,
      server: "9.9.9.9",
    });
  });
});

const id = (s: string) => s;
const toRu = (s: string) => (ru as Record<string, string>)[s] ?? s;
const on = (resolver: any) => ({ interface: "nwg0", resolver });
const CALM = { window: 600, total: 0, fallbacks: 0, last: 0, reason: "", resting: false, since: 0 };
const at = (h: number, m: number) => new Date(2026, 9, 20, h, m).getTime() / 1000;
const firmware = (health: Partial<typeof CALM>, source = "firmware") =>
  ({ source, servers: ["9.9.9.9"], health: { ...CALM, ...health } }) as any;

describe("the panel's resolver tag", () => {
  // Catches hidden servers, "none"/"off" read as a tunnel, a tag with no report, or a zero count shown.
  it("says where the group's names are resolved", () => {
    assert.strictEqual(
      resolverTag(on({ source: "firmware", servers: ["9.9.9.9", "1.0.0.1"], health: CALM }), id),
      "DNS 9.9.9.9, 1.0.0.1",
    );
    assert.strictEqual(
      resolverTag(on({ source: "group", servers: ["[2620:fe::fe]:853"], health: CALM }), id),
      "DNS [2620:fe::fe]:853",
    );
    assert.strictEqual(
      resolverTag(on({ source: "none", servers: [], health: CALM }), id),
      "DNS: common upstream",
    );
    assert.strictEqual(
      resolverTag(on({ source: "off", servers: [], health: CALM }), id),
      "DNS: not through the tunnel",
    );
    assert.strictEqual(
      resolverTag(on({ source: "group", servers: [], health: CALM }), id),
      "DNS: common upstream",
    );
    assert.strictEqual(resolverTag(undefined, id), null);
    assert.strictEqual(resolverTag({ interface: "nwg0" }, id), null);
  });

  // Catches a block group tagged with its resolver, the code not named, an unset code not read as 0.0.0.0, or a blackhole group tagged as blocking.
  it("a_block_group_has_the_blocking_badge", () => {
    const none = { source: "none" as const, servers: [], health: CALM };
    assert.strictEqual(
      resolverTag({ interface: "block", block: "nxdomain", resolver: none }, id),
      "DNS: blocking · NXDOMAIN",
    );
    assert.strictEqual(
      resolverTag({ interface: "block", block: "refused", resolver: none }, id),
      "DNS: blocking · REFUSED",
    );
    assert.strictEqual(
      resolverTag({ interface: "block", block: "null", resolver: none }, id),
      "DNS: blocking · 0.0.0.0",
    );
    assert.strictEqual(resolverTag({ interface: "block" }, id), "DNS: blocking · 0.0.0.0");
    assert.strictEqual(
      resolverTag({ interface: "block", block: "nxdomain" }, toRu),
      "DNS: блокировка · NXDOMAIN",
    );
    assert.strictEqual(
      resolverTag({ interface: "blackhole", block: "nxdomain", resolver: none }, id),
      "DNS: common upstream",
    );
  });
});

describe("the card's DNS health tag", () => {
  // Catches a tag shown for no resolver, a calm window, or a group not asked through the tunnel.
  it("shows nothing without a resolver, without failures, or with the resolver off", () => {
    assert.strictEqual(healthTag(undefined, id), null);
    assert.strictEqual(healthTag(firmware({ total: 40 }), id), null);
    assert.strictEqual(
      healthTag(firmware({ total: 9, fallbacks: 4, last: at(14, 32) }, "off"), id),
      null,
    );
  });

  // Catches the count, the total or the window minutes swapped or left unfilled.
  it("reads the amber tag from the counts and the window", () => {
    const tag = healthTag(
      firmware({ total: 37, fallbacks: 4, last: at(14, 32), reason: "fallback_timeout" }),
      toRu,
    );
    assert.strictEqual(tag?.kind, "amber");
    assert.strictEqual(tag?.text, "DNS группы сбоит: 4 из 37 за 10 мин");
    assert.strictEqual(
      tag?.tip,
      "Последний сбой в 14:32: DNS группы не ответил вовремя, ответил общий upstream. Нажмите, чтобы открыть журнал группы.",
    );
    const wide = healthTag(firmware({ window: 1200, total: 5, fallbacks: 1, last: 1 }), id);
    assert.ok(wide?.text.includes("in 20 min"));
  });

  // Catches a resting group staying amber, or the red tag waiting for a count.
  it("goes red when the group rests, whatever the counts say", () => {
    const tag = healthTag(firmware({ resting: true, since: at(9, 5) }), toRu);
    assert.strictEqual(tag?.kind, "red");
    assert.strictEqual(tag?.text, "DNS группы не отвечает");
    assert.strictEqual(
      tag?.tip,
      "С 09:05 DNS группы не отвечает, на запросы отвечает общий upstream. firc проверяет его раз в 30 с. Нажмите, чтобы открыть журнал группы.",
    );
    assert.strictEqual(
      healthTag(firmware({ resting: true, fallbacks: 3, total: 3 }), id)?.kind,
      "red",
    );
  });
});
