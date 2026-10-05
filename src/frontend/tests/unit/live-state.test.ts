import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  checkedText,
  LIVE_LOOK,
  liveKind,
  liveTooltip,
  type LiveKind,
} from "../../src/modules/groups/live-state.ts";

const t = (key: string) => key;
const clock = (unix: number) => `@${unix}`;

const enabled = { enable: true };

describe("a group's live state", () => {
  // Catches the daemon's answer shown over an unsaved edit or a switched-off group, or a reason mapped to another kind.
  it("reads unsaved first, then the switch, then the daemon", () => {
    const failing = { live: false, liveReason: "not-enabled" as const };
    assert.strictEqual(liveKind(enabled, true, { live: true }), "unsaved");
    assert.strictEqual(liveKind({ enable: false }, true, { live: true }), "unsaved");
    assert.strictEqual(liveKind({ enable: false }, false, failing), "disabled");
    assert.strictEqual(liveKind({ enable: false }, false, { live: true }), "disabled");
    assert.strictEqual(liveKind(enabled, false, { live: true }), "live");
    assert.strictEqual(liveKind(enabled, false, failing), "not-enabled");
    assert.strictEqual(
      liveKind(enabled, false, { live: false, liveReason: "no-interface" }),
      "no-interface",
    );
    assert.strictEqual(
      liveKind(enabled, false, { live: false, liveReason: "not-written" }),
      "not-written",
    );
    assert.strictEqual(
      liveKind(enabled, false, { live: false, liveReason: "disabled" }),
      "disabled",
    );
  });

  // Catches an invented icon for a group the daemon said nothing about.
  it("shows nothing it was not told", () => {
    assert.strictEqual(liveKind(enabled, false, undefined), null);
    assert.strictEqual(liveKind(enabled, false, { live: false }), null);
    assert.strictEqual(
      liveKind(enabled, false, { live: false, liveReason: "on-fire" as any }),
      null,
    );
  });

  // Catches a state getting another's icon or colour.
  it("gives each state its icon and colour", () => {
    const expected: Record<LiveKind, [string, string]> = {
      live: ["CircleCheck", "var(--green)"],
      "not-enabled": ["CircleX", "var(--red)"],
      "no-interface": ["Unplug", "var(--orange)"],
      "not-written": ["RefreshCw", "var(--orange)"],
      disabled: ["PowerOff", "var(--text-2)"],
      unsaved: ["CircleDashed", "var(--text-2)"],
    };
    for (const [kind, [icon, color]] of Object.entries(expected)) {
      assert.deepStrictEqual(LIVE_LOOK[kind as LiveKind], { icon, color }, kind);
    }
  });

  // Catches the interface not named where the sentence names it.
  it("names the group's interface when live and when waiting for one", () => {
    const live = liveTooltip("live", { iface: "wg0" }, t, clock);
    assert.strictEqual(live.title, "Working");
    assert.deepStrictEqual(live.lines, [
      "The group's rules are written into the router's kernel; its traffic goes through wg0.",
    ]);
    assert.strictEqual(live.footer, true);

    const waiting = liveTooltip("no-interface", { iface: "nwg1" }, t, clock);
    assert.strictEqual(waiting.title, "Waiting for interface nwg1");
    assert.deepStrictEqual(waiting.lines, [
      "Tunnel nwg1 is off or not connected, so the group's sites do not open right now.",
      "The group will start working by itself when nwg1 comes up. Or choose another interface for it.",
    ]);
    assert.strictEqual(waiting.footer, true);
  });

  it("says the daemon keeps retrying a group that did not come up", () => {
    const tip = liveTooltip("not-enabled", { iface: "wg0" }, t, clock);
    assert.strictEqual(tip.title, "Did not come up — the daemon keeps trying");
    assert.strictEqual(tip.lines.length, 2);
    assert.match(tip.lines[1], /after 1 s, then less often, down to once a minute/);
    assert.strictEqual(tip.error, undefined);
    assert.strictEqual(tip.footer, true);
  });

  // Catches the failure time or error being dropped, or shown when the daemon did not send it.
  it("gives not-written its time and error when the daemon has them", () => {
    const failing = liveTooltip(
      "not-written",
      {
        iface: "wg0",
        netfilter: { ok: false, error: "iptables-restore: line 56 failed", since: 1790000000 },
      },
      t,
      clock,
    );
    assert.strictEqual(failing.title, "Rules are being rewritten");
    assert.strictEqual(
      failing.lines[0],
      "Since @1790000000 the router has not accepted firc's rules, and the daemon keeps rewriting them by itself. This usually happens while the firmware rebuilds its tables, and passes within a few seconds.",
    );
    assert.match(failing.lines[1], /open the Journal/);
    assert.strictEqual(failing.error, "iptables-restore: line 56 failed");
    assert.strictEqual(failing.footer, true);

    const bare = liveTooltip("not-written", { iface: "wg0", netfilter: { ok: true } }, t, clock);
    assert.strictEqual(bare.title, "Rules are being rewritten");
    assert.ok(bare.lines[0].startsWith("The router is not accepting firc's rules"), bare.lines[0]);
    assert.ok(!bare.lines[0].includes("@"), "no time without since");
    assert.strictEqual(bare.error, undefined);

    const unknown = liveTooltip("not-written", { iface: "wg0" }, t, clock);
    assert.ok(unknown.lines[0].startsWith("The router is not accepting firc's rules"));
  });

  // Catches a first write after start read as a failure, or hiding its error when it also fails.
  it("tells the first write after start apart, unless it is failing too", () => {
    const pending = liveTooltip(
      "not-written",
      { iface: "wg0", netfilter: { ok: false, firstWritePending: true } },
      t,
      clock,
    );
    assert.strictEqual(pending.title, "First write of the rules since start");
    assert.deepStrictEqual(pending.lines, [
      "The daemon has just started and is writing the rules. This usually takes a fraction of a second.",
    ]);
    assert.strictEqual(pending.error, undefined);
    assert.strictEqual(pending.footer, true);

    const pendingFailing = liveTooltip(
      "not-written",
      {
        iface: "wg0",
        netfilter: { ok: false, firstWritePending: true, error: "i/o error", since: 5 },
      },
      t,
      clock,
    );
    assert.strictEqual(pendingFailing.title, "Rules are being rewritten");
    assert.strictEqual(pendingFailing.error, "i/o error");
    assert.ok(pendingFailing.lines[0].startsWith("Since @5 "));
  });

  // Catches the "checked N s ago" footer on states the daemon's answer does not describe.
  it("puts the freshness footer only on the daemon's states", () => {
    assert.strictEqual(liveTooltip("disabled", { iface: "wg0" }, t, clock).footer, false);
    assert.strictEqual(liveTooltip("unsaved", { iface: "wg0" }, t, clock).footer, false);
    assert.strictEqual(liveTooltip("disabled", { iface: "wg0" }, t, clock).title, "Group off");
    assert.strictEqual(
      liveTooltip("unsaved", { iface: "wg0" }, t, clock).title,
      "Changes not saved",
    );
  });

  // Catches silence not overriding daemon states, or hiding an unsaved edit.
  it("reads no answer over every daemon state, but under an unsaved edit", () => {
    assert.strictEqual(liveKind(enabled, false, { live: true }, true), "no-answer");
    assert.strictEqual(
      liveKind(enabled, false, { live: false, liveReason: "not-enabled" }, true),
      "no-answer",
    );
    assert.strictEqual(liveKind({ enable: false }, false, undefined, true), "no-answer");
    assert.strictEqual(liveKind(enabled, false, undefined, true), "no-answer");
    assert.strictEqual(liveKind(enabled, true, { live: true }, true), "unsaved");
    assert.deepStrictEqual(LIVE_LOOK["no-answer"], {
      icon: "CircleHelp",
      color: "var(--text-2)",
    });
  });

  it("says how long the daemon has been silent", () => {
    const tip = liveTooltip("no-answer", { iface: "wg0", silentFor: 17_900 }, t, clock);
    assert.strictEqual(tip.title, "No answer from the daemon");
    assert.strictEqual(
      tip.lines[0],
      "The page has had no answer from firc for 17 s. The groups' state is unknown: the router is rebooting, the daemon is stopped or the connection is lost. The page keeps asking by itself.",
    );
    assert.strictEqual(tip.footer, false, "the age is in the sentence already");
    const long = liveTooltip("no-answer", { iface: "wg0", silentFor: 185_000 }, t, clock);
    assert.match(long.lines[0], /for 3 min\./);
  });

  // Catches a long silence reading as hundreds of seconds.
  it("counts minutes past a minute", () => {
    assert.match(checkedText(0, 59_999, t), /^Checked 59 s ago/);
    assert.match(checkedText(0, 60_000, t), /^Checked 1 min ago/);
    assert.match(checkedText(0, 150_000, t), /^Checked 2 min ago/);
  });

  it("counts whole seconds since the last check, never below zero", () => {
    assert.strictEqual(
      checkedText(10_000, 12_400, t),
      "Checked 2 s ago · updates by itself, no need to reload the page",
    );
    assert.strictEqual(checkedText(10_000, 9_000, t), checkedText(10_000, 10_000, t));
    assert.match(checkedText(10_000, 9_000, t), /Checked 0 s ago/);
  });
});
