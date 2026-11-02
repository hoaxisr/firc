import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { autolistTip } = await import("../../src/utils/autolist-tip");
const { latestResult, prefixContains, ruleCovering, ruleOf, whyClass, whyLabel } =
  await import("../../src/data/autolist.svelte");

const say = (key: string) => (ru as Record<string, string>)[key] ?? key;

describe("whyClass", () => {
  it("gives an unanswered SYN the colour of an unanswered ClientHello", () => {
    assert.strictEqual(whyClass("no-connect"), "drop");
    assert.strictEqual(whyClass("no-answer"), "drop");
  });

  it("keeps the other reasons apart and greys an unknown one", () => {
    assert.strictEqual(whyClass("reset"), "rst");
    assert.strictEqual(whyClass("freeze"), "frz");
    assert.strictEqual(whyClass("odd"), "off");
  });
});

describe("whyLabel", () => {
  it("names the four failures in Russian, a freeze with its kilobytes", () => {
    assert.strictEqual(whyLabel("no-answer", 0, say), "нет ответа на ClientHello");
    assert.strictEqual(whyLabel("reset", 0, say), "сброс до ответа сервера");
    assert.strictEqual(whyLabel("freeze", 15360, say), "заморозка на 15 КБ");
    assert.strictEqual(whyLabel("no-connect", 0, say), "нет соединения (SYN без ответа)");
  });

  it("names no-connect in English by its key", () => {
    assert.strictEqual(
      whyLabel("no-connect", 0, (k) => k),
      "no connection (SYN unanswered)",
    );
  });

  it("rounds the kilobytes to the nearest", () => {
    assert.strictEqual(whyLabel("freeze", 15872, say), "заморозка на 16 КБ");
    assert.strictEqual(whyLabel("freeze", 15800, say), "заморозка на 15 КБ");
  });

  it("shows a freeze of under a kilobyte without a size", () => {
    assert.strictEqual(whyLabel("freeze", 500, say), "заморозка");
    assert.strictEqual(whyLabel("freeze", 0, say), "заморозка");
  });

  it("passes an unknown reason through", () => {
    assert.strictEqual(whyLabel("odd", 0, say), "odd");
  });
});

describe("latestResult", () => {
  const results = [
    { host: "a.example", verdict: "open", why: "", bytes: 9, at: 300, error: "" },
    { host: "b.example", verdict: "blocked", why: "freeze", bytes: 15360, at: 200, error: "" },
    { host: "b.example", verdict: "unknown", why: "", bytes: 0, at: 100, error: "" },
  ];

  it("returns the newest result of that host only", () => {
    assert.strictEqual(latestResult(results, "b.example")?.at, 200);
    assert.strictEqual(latestResult(results, "c.example"), null);
  });
});

describe("ruleOf", () => {
  const groups = [
    { id: "g1", rules: [{ id: "r1", rule: "rutracker.org", type: "namespace", enable: true }] },
    { id: "g2", rules: [{ id: "r2", rule: "rutracker.org", type: "namespace", enable: true }] },
  ] as never;

  it("finds the rule by its text inside the target group only", () => {
    assert.strictEqual(ruleOf(groups, "g2", "rutracker.org")?.id, "r2");
    assert.strictEqual(ruleOf(groups, "g1", "linkedin.com"), null);
    assert.strictEqual(ruleOf(groups, "nope", "rutracker.org"), null);
  });
});

describe("prefixContains", () => {
  it("matches an IPv6 address inside a /32 by its first 32 bits", () => {
    assert.strictEqual(prefixContains("2606:4700::/32", "2606:4700::6810:84e5"), true);
    assert.strictEqual(prefixContains("2606:4700::/32", "2606:4701::1"), false);
    assert.strictEqual(prefixContains("2a00::/16", "2b00::1"), false);
    assert.strictEqual(prefixContains("2a00::/16", "2A00:ffff::1"), true);
  });

  it("never matches across families", () => {
    assert.strictEqual(prefixContains("0.0.0.0/0", "2606:4700::1"), false);
    assert.strictEqual(prefixContains("::/0", "104.16.132.229"), false);
  });

  it("lets 0.0.0.0/0 hold any IPv4 address", () => {
    assert.strictEqual(prefixContains("0.0.0.0/0", "104.16.132.229"), true);
    assert.strictEqual(prefixContains("0.0.0.0/0", "255.255.255.255"), true);
  });

  it("refuses a length past the family or not a number", () => {
    assert.strictEqual(prefixContains("10.0.0.0/33", "10.0.0.0"), false);
    assert.strictEqual(prefixContains("10.0.0.0/x", "10.0.0.0"), false);
  });

  it("takes a bare address as a full-length prefix", () => {
    assert.strictEqual(prefixContains("10.0.0.1", "10.0.0.1"), true);
    assert.strictEqual(prefixContains("10.0.0.1", "10.0.0.2"), false);
  });
});

describe("ruleCovering", () => {
  const groups = [
    {
      id: "g1",
      rules: [{ id: "off", rule: "104.16.0.0/12", type: "subnet", enable: false }],
    },
    {
      id: "g2",
      rules: [{ id: "on", rule: "104.16.0.0/13", type: "subnet", enable: true }],
    },
  ] as never;

  it("skips a switched-off rule that holds the address", () => {
    assert.strictEqual(ruleCovering(groups, ["g1"], "104.16.132.229"), null);
    assert.strictEqual(ruleCovering(groups, ["g1", "g2"], "104.16.132.229")?.id, "on");
  });
});

describe("autolistTip", () => {
  const cand = (over = {}) => ({
    domain: "rutracker.org",
    host: "rutracker.org",
    why: "no-answer",
    fails: 3,
    clients: ["192.168.1.51"],
    lastAt: new Date(2026, 9, 30, 17, 41).getTime() / 1000,
    state: "added" as const,
    notes: 0,
    ...over,
  });
  const names = new Map([["192.168.1.51", "iPad"]]);
  const tip = (candidates: ReturnType<typeof cand>[], pattern = "rutracker.org") =>
    autolistTip(pattern, candidates, names, (k) => k, "en");

  it("names the time, host, reason and device when the candidate is still known", () => {
    const text = tip([cand()]);
    assert.strictEqual(
      text,
      "Added automatically 30.10 17:41: rutracker.org did not answer ClientHello 3 times in a row (iPad).\nIf you switch the rule off or change it, it becomes yours and the automation no longer touches it.",
    );
  });

  it("falls back to the pattern when no candidate matches", () => {
    assert.strictEqual(
      tip([cand({ domain: "other.org" })]),
      "Added automatically for rutracker.org.\nIf you switch the rule off or change it, it becomes yours and the automation no longer touches it.",
    );
  });

  it("a freeze names no count", () => {
    assert.match(
      tip([cand({ why: "freeze", fails: 0 })]),
      /rutracker\.org froze after the first bytes \(iPad\)\./,
    );
  });

  it("shows an unknown device by its address", () => {
    assert.match(tip([cand({ clients: ["192.168.1.9"] })]), /\(192\.168\.1\.9\)/);
  });
});
