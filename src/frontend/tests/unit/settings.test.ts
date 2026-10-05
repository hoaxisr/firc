import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  changedKeys,
  followUrl,
  groupChanges,
  pluralForm,
  putBody,
  rebaseDraft,
  restartFailure,
  restartPhase,
  restartSettled,
  type SettingsRes,
} from "../../src/modules/settings/settings";

describe("changedKeys", () => {
  // Catches arrays compared by identity, a key the draft lacks counted, or an order other than the daemon's.
  it("names what differs, in the daemon's order", () => {
    const saved = { a: 1, b: "x", c: ["br0"], d: true, e: 5 };
    const draft = { e: 6, d: true, c: ["br0", "br1"], b: "y", a: 1 };
    assert.deepStrictEqual(changedKeys(saved, draft), ["b", "c", "e"]);
  });
  it("an equal copy of a list is not a change", () => {
    assert.deepStrictEqual(changedKeys({ l: ["br0"] }, { l: ["br0"] }), []);
  });
  it("a key the draft does not have is not a change", () => {
    assert.deepStrictEqual(changedKeys({ a: 1, b: 2 }, { a: 1 }), []);
  });
});

describe("rebaseDraft", () => {
  // Catches the whole draft kept or replaced, or arrays compared by identity so a copy reads as edited.
  it("takes what was not edited, keeps what was", () => {
    const oldSaved = { a: 1, b: "x", l: ["br0"] };
    const draft = { a: 1, b: "y", l: ["br0"] };
    const newSaved = { a: 2, b: "x", l: ["br0", "br1"] };
    assert.deepStrictEqual(rebaseDraft(oldSaved, draft, newSaved), {
      a: 2,
      b: "y",
      l: ["br0", "br1"],
    });
  });
  // Catches the new draft sharing the answer's arrays.
  it("copies, so the draft and the answer share nothing", () => {
    const newSaved = { l: ["br0"] };
    const draft = rebaseDraft({}, {}, newSaved);
    assert.deepStrictEqual(draft, { l: ["br0"] });
    assert.notStrictEqual(draft.l, newSaved.l);
  });
  // The first load: nothing saved, nothing drafted, all of the answer.
  it("an empty draft becomes the answer", () => {
    assert.deepStrictEqual(rebaseDraft({}, {}, { a: 1, b: true }), { a: 1, b: true });
  });
});

describe("groupChanges", () => {
  // Catches an unclassified key counted as live.
  it("splits by the daemon's classes, unknown as restart", () => {
    assert.deepStrictEqual(groupChanges(["x", "y", "z"], { x: "live", y: "restart" }), {
      live: ["x"],
      restart: ["y", "z"],
    });
  });
});

describe("putBody", () => {
  // Catches sending the whole draft, so a second tab writes its stale copy of every key.
  it("carries only the changed keys", () => {
    assert.deepStrictEqual(putBody(["b"], { a: 1, b: "y", c: [] }), { settings: { b: "y" } });
  });
});

describe("pluralForm", () => {
  // Catches the 11-14 exception forgotten, or the Russian rule applied to English.
  it("Russian", () => {
    const want: Array<[number, string]> = [
      [0, "many"],
      [1, "one"],
      [2, "few"],
      [4, "few"],
      [5, "many"],
      [11, "many"],
      [12, "many"],
      [14, "many"],
      [21, "one"],
      [22, "few"],
      [25, "many"],
      [111, "many"],
      [112, "many"],
      [121, "one"],
    ];
    for (const [n, form] of want) assert.strictEqual(pluralForm(n, "ru"), form, `n=${n}`);
  });
  it("English has one and many only", () => {
    assert.strictEqual(pluralForm(1, "en"), "one");
    assert.strictEqual(pluralForm(2, "en"), "many");
    assert.strictEqual(pluralForm(21, "en"), "many");
  });
});

describe("restartSettled", () => {
  const res = (boot: string, pendingRestart: string[] = [], restarting = true): SettingsRes => ({
    settings: {},
    classes: {},
    pendingRestart,
    boot,
    restarting,
  });
  it("an answer with the boot from before is the old daemon", () => {
    assert.strictEqual(restartSettled("a", res("a", ["app.link"])), false);
    assert.strictEqual(restartSettled("a", res("a")), false);
  });
  it("an answer with another boot is the new daemon", () => {
    assert.strictEqual(restartSettled("a", res("b", ["app.link"])), true);
    assert.strictEqual(restartSettled("a", res("b")), true);
  });
  it("no answer is not settled", () => {
    assert.strictEqual(restartSettled("a", null), false);
  });
  it("the same boot with a restart still under way is the old daemon", () => {
    assert.strictEqual(restartPhase("a", res("a")), "old-daemon");
  });
  it("the same boot with no restart under way is a restart that did not start", () => {
    assert.strictEqual(restartPhase("a", res("a", [], false)), "failed");
  });
  it("another boot is back even when the answer says no restart is under way", () => {
    assert.strictEqual(restartPhase("a", res("b", [], false)), "back");
  });
  it("no answer is no-answer", () => {
    assert.strictEqual(restartPhase("a", null), "no-answer");
  });
  it("an answer without a boot is an older daemon still waiting", () => {
    const old = { settings: {}, classes: {}, pendingRestart: [] } as unknown as SettingsRes;
    assert.strictEqual(restartPhase("a", old), "old-daemon");
    assert.strictEqual(restartPhase("", old), "old-daemon");
  });
  it("a restart that was under way and then stopped being so did not restart", () => {
    assert.strictEqual(restartFailure(true), "not-restarted");
  });
  it("a restart never seen under way did not start", () => {
    assert.strictEqual(restartFailure(false), "not-started");
  });
});

describe("followUrl", () => {
  const loc = { protocol: "http:", hostname: "192.168.1.1", port: "8080", pathname: "/" };
  const port = "app.httpWeb.host.port";
  // Catches following on every restart, a lost path, or a page already on the new port sent to itself.
  it("goes to the same host and path on the new port", () => {
    assert.strictEqual(followUrl(loc, { [port]: 8081 }, [port]), "http://192.168.1.1:8081/");
  });
  it("stays when the port is not pending", () => {
    assert.strictEqual(followUrl(loc, { [port]: 8081 }, ["app.link"]), null);
  });
  it("stays when the page is already on that port", () => {
    assert.strictEqual(followUrl(loc, { [port]: 8080 }, [port]), null);
  });
  it("an empty port is the scheme's default", () => {
    const https = { protocol: "https:", hostname: "r.lan", port: "", pathname: "/x" };
    assert.strictEqual(followUrl(https, { [port]: 443 }, [port]), null);
    assert.strictEqual(followUrl(https, { [port]: 8443 }, [port]), "https://r.lan:8443/x");
  });
  // location.hostname never carries brackets; new URL() refuses an unbracketed IPv6 literal.
  it("brackets an IPv6 literal host", () => {
    const v6 = { protocol: "http:", hostname: "fd00::1", port: "8080", pathname: "/" };
    assert.strictEqual(followUrl(v6, { [port]: 8081 }, [port]), "http://[fd00::1]:8081/");
  });
});
