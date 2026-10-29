import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  EXPIRE_SOON_S,
  expiryText,
  expiryTone,
  formatSize,
  trafficText,
  trafficTone,
  usageAlert,
} from "../../src/modules/tunnels/sub-usage.ts";

const id = (k: string) => k;
const GiB = 2 ** 30;
const NOW = 1_800_000_000;

describe("formatSize", () => {
  // Catches decimal units where providers count in 1024s, or a unit switch one step off.
  it("counts in powers of 1024", () => {
    assert.strictEqual(formatSize(100 * GiB, id), "100 GB");
    assert.strictEqual(formatSize(12.5 * GiB, id), "12.5 GB");
    assert.strictEqual(formatSize(1023 * 2 ** 20, id), "1023 MB");
    assert.strictEqual(formatSize(2 * 2 ** 40, id), "2 TB");
    assert.strictEqual(formatSize(0, id), "0 KB");
  });
});

describe("traffic and expiry", () => {
  // Catches a zero total shown as a limit of nothing, or a zero expire shown as 1970.
  it("names no limit and no end date", () => {
    const u = { used: 3 * GiB, total: 0, expire: 0 };
    assert.strictEqual(trafficText(u, id), "3 GB, no limit");
    assert.strictEqual(expiryText(u, NOW, id), "no end date");
    assert.strictEqual(trafficTone(u), "");
    assert.strictEqual(expiryTone(u, NOW), "");
  });

  // Catches the thresholds off by one at either side.
  it("turns orange at 90% and three days, red at the end", () => {
    const at = (used: number, expire: number) => ({ used, total: 100, expire });
    assert.strictEqual(trafficTone(at(89, 0)), "");
    assert.strictEqual(trafficTone(at(90, 0)), "orange");
    assert.strictEqual(trafficTone(at(100, 0)), "red");
    assert.strictEqual(expiryTone(at(0, NOW + EXPIRE_SOON_S + 1), NOW), "");
    assert.strictEqual(expiryTone(at(0, NOW + EXPIRE_SOON_S), NOW), "orange");
    assert.strictEqual(expiryTone(at(0, NOW), NOW), "red");
    assert.strictEqual(
      trafficText({ used: 12.5 * GiB, total: 100 * GiB, expire: 0 }, id),
      "12.5 GB of 100 GB",
    );
  });
});

describe("usageAlert", () => {
  // Catches a warning for a healthy plan, or the lesser trouble shown over an ended one.
  it("warns of the worst trouble only", () => {
    assert.strictEqual(usageAlert(null, NOW, id), null);
    assert.strictEqual(
      usageAlert({ used: 1, total: 100, expire: NOW + 86400 * 30 }, NOW, id),
      null,
    );
    assert.deepStrictEqual(usageAlert({ used: 100, total: 100, expire: NOW - 1 }, NOW, id), {
      text: "has ended",
      tone: "red",
    });
    assert.deepStrictEqual(usageAlert({ used: 100, total: 100, expire: NOW + 3600 }, NOW, id), {
      text: "traffic used up",
      tone: "red",
    });
    assert.deepStrictEqual(usageAlert({ used: 95, total: 100, expire: NOW + 3600 }, NOW, id), {
      text: "ends in 1 d",
      tone: "orange",
    });
    assert.deepStrictEqual(usageAlert({ used: 95, total: 100, expire: 0 }, NOW, id), {
      text: "95% of traffic used",
      tone: "orange",
    });
  });
});
