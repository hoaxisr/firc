import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { counted } from "../../src/utils/plural.ts";

const RU = ["+{n} новое событие", "+{n} новых события", "+{n} новых событий"] as const;
const EN = ["+{n} new event", "+{n} new events (2-4)", "+{n} new events"] as const;

describe("a count declined by number", () => {
  // Catches 11/111 taking "one", 12-14 taking "few", or 21/22 losing their forms.
  it("gives Russian its three forms", () => {
    const want: [number, string][] = [
      [1, "+1 новое событие"],
      [2, "+2 новых события"],
      [5, "+5 новых событий"],
      [11, "+11 новых событий"],
      [21, "+21 новое событие"],
      [22, "+22 новых события"],
      [25, "+25 новых событий"],
      [111, "+111 новых событий"],
    ];
    for (const [n, text] of want) assert.strictEqual(counted(n, "ru", ...RU), text, `n=${n}`);
  });

  // Catches English picking up the Russian "few" form.
  it("gives English one and many", () => {
    assert.strictEqual(counted(1, "en", ...EN), "+1 new event");
    assert.strictEqual(counted(3, "en", ...EN), "+3 new events");
    assert.strictEqual(counted(22, "en", ...EN), "+22 new events");
  });
});
