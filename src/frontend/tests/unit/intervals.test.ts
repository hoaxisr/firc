import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  intervalLabel,
  intervalOptionsFor,
  parseIntervalSeconds,
} from "../../src/modules/groups/intervals.ts";

const RU: Record<string, string> = {
  "once an hour": "раз в час",
  "once a day": "раз в день",
  manually: "вручную",
  "every {n} d": "каждые {n} дн.",
  "every {n} h": "каждые {n} ч",
  "every {n} min": "каждые {n} мин",
  "every {n} s": "каждые {n} с",
};
const t = (k: string) => RU[k] ?? `?${k}`;

describe("a list's update interval", () => {
  // Catches 0 not meaning "manually", or a listed value read as a computed one.
  it("names the offered intervals by their own labels", () => {
    assert.strictEqual(intervalLabel(0, t), "вручную");
    assert.strictEqual(intervalLabel(3600, t), "раз в час");
    assert.strictEqual(intervalLabel(86400, t), "раз в день");
  });

  // Catches an unoffered interval printing as raw seconds, or in a smaller unit than the largest whole one.
  it("names any other interval in the largest whole unit", () => {
    assert.strictEqual(intervalLabel(43200, t), "каждые 12 ч");
    assert.strictEqual(intervalLabel(172800, t), "каждые 2 дн.");
    assert.strictEqual(intervalLabel(5400, t), "каждые 90 мин");
    assert.strictEqual(intervalLabel(90, t), "каждые 90 с");
  });

  // Catches the select missing the current value as an option, or duplicating one it has.
  it("offers the current interval when it is not one of the five", () => {
    const standard = intervalOptionsFor(86400, t);
    assert.deepStrictEqual(
      standard.map((o) => o.value),
      ["3600", "21600", "86400", "604800", "0"],
    );
    const odd = intervalOptionsFor(43200, t);
    assert.strictEqual(odd.length, 6);
    assert.deepStrictEqual(odd[5], { value: "43200", label: "каждые 12 ч" });
  });

  // Catches "manually" refused as falsy, or garbage becoming an interval.
  it("reads the select's value back as seconds", () => {
    assert.strictEqual(parseIntervalSeconds("0"), 0);
    assert.strictEqual(parseIntervalSeconds("21600"), 21600);
    assert.strictEqual(parseIntervalSeconds(""), null);
    assert.strictEqual(parseIntervalSeconds("abc"), null);
    assert.strictEqual(parseIntervalSeconds("-5"), null);
    assert.strictEqual(parseIntervalSeconds("1.5"), null);
  });
});
