import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  added,
  changedCount,
  headerRows,
  headersProblem,
  overridesOf,
  removed,
  restored,
  withName,
  withValue,
} from "../../src/modules/tunnels/headers";

const DEFAULTS = [
  { name: "User-Agent", value: "firc/0.4.1" },
  { name: "X-HWID", value: "6e58d9776d738a31" },
  { name: "X-Device-OS", value: "KeeneticOS" },
];
const t = (key: string) => key;

describe("header rows", () => {
  // Catches an override matched by exact case only, a removed default shown as gone, or an own header lost.
  it("lays the overrides over the defaults by name in any case", () => {
    const rows = headerRows(DEFAULTS, {
      "x-hwid": "",
      "user-agent": "sing-box/1.12.0",
      Authorization: "Bearer x",
    });
    assert.deepStrictEqual(rows, [
      { name: "user-agent", value: "sing-box/1.12.0", kind: "changed" },
      { name: "x-hwid", value: "6e58d9776d738a31", kind: "removed" },
      { name: "X-Device-OS", value: "KeeneticOS", kind: "default" },
      { name: "Authorization", value: "Bearer x", kind: "added" },
    ]);
    assert.strictEqual(changedCount(rows), 3);
  });

  // Catches a save carrying the defaults, a removed default saved as absent, or an own header saved under a padded name.
  it("saves only the difference, a removed default as an empty value", () => {
    let rows = headerRows(DEFAULTS);
    rows = withValue(DEFAULTS, rows, 0, "sing-box/1.12.0");
    rows = removed(DEFAULTS, rows, 1);
    rows = added(rows);
    rows = withName(rows, 3, " Authorization ");
    rows = withValue(DEFAULTS, rows, 3, "Bearer x");
    assert.deepStrictEqual(overridesOf(rows), {
      "User-Agent": "sing-box/1.12.0",
      "X-HWID": "",
      Authorization: "Bearer x",
    });
  });

  // Catches a value typed back to the default still saved, or a restored default still sent as removed.
  it("a value equal to the default and a restored row save nothing", () => {
    let rows = withValue(DEFAULTS, headerRows(DEFAULTS), 0, "x");
    rows = withValue(DEFAULTS, rows, 0, "firc/0.4.1");
    rows = restored(DEFAULTS, removed(DEFAULTS, rows, 1), 1);
    assert.deepStrictEqual(overridesOf(rows), {});
    assert.strictEqual(changedCount(rows), 0);
  });

  // Catches an own header deleted by marking it removed instead of dropping the row.
  it("removing an own header drops its row", () => {
    const rows = removed(DEFAULTS, headerRows(DEFAULTS, { "X-A": "1" }), 3);
    assert.strictEqual(rows.length, 3);
    assert.deepStrictEqual(overridesOf(rows), {});
  });

  // Catches an untouched header saved under another spelling, which renames its cache file.
  it("keeps an override's own spelling through rows and back", () => {
    assert.deepStrictEqual(overridesOf(headerRows(DEFAULTS, { "user-agent": "x", "x-hwid": "" })), {
      "user-agent": "x",
      "x-hwid": "",
    });
  });

  // Catches overrides read without defaults losing a removed default on the way back.
  it("round-trips the overrides when the defaults are not loaded", () => {
    const own = { "X-HWID": "", "User-Agent": "sing-box/1.12.0" };
    assert.deepStrictEqual(overridesOf(headerRows([], own)), own);
  });

  // Catches a nameless header with a value saved silently, or a repeat of a default in another case let through.
  it("names a header without a name and a repeated one", () => {
    let rows = added(headerRows(DEFAULTS));
    assert.strictEqual(headersProblem(rows, t), "");
    rows = withValue(DEFAULTS, rows, 3, "v");
    assert.strictEqual(headersProblem(rows, t), "A header needs a name");
    rows = withName(rows, 3, "x-hwid");
    assert.strictEqual(
      headersProblem(rows, t),
      "Header {name} is given twice".replace("{name}", "x-hwid"),
    );
  });

  const problem = (name: string, value = "v") =>
    headersProblem(
      withValue(DEFAULTS, withName(added(headerRows(DEFAULTS)), 3, name), 3, value),
      t,
    );
  const NAME_BAD = "A header name is 1 to 64 letters, digits or !#$%&'*+-.^_`|~";

  // Catches a header the fetch sets itself (Host, Content-Length, Transfer-Encoding, Connection) accepted in any case.
  it("refuses the names the fetch sets itself, in any case, naming the header", () => {
    for (const name of ["Host", "content-length", "TRANSFER-ENCODING", "cOnNeCtIoN"]) {
      assert.strictEqual(
        problem(name),
        "Header {name} is set by the fetch itself".replace("{name}", name),
      );
    }
  });

  // Catches a name with a space, colon, slash, non-ASCII or empty token let through, or the 64-byte bound off by one.
  it("refuses a name that is not an HTTP token or is over 64 bytes", () => {
    for (const name of ["My Header", "a:b", "a/b", "Заголовок", "a(b)"]) {
      assert.strictEqual(problem(name), NAME_BAD);
    }
    assert.strictEqual(problem("a".repeat(64)), "");
    assert.strictEqual(problem("a".repeat(65)), NAME_BAD);
    assert.strictEqual(problem("!#$%&'*+-.^_`|~09azAZ"), "");
  });

  // Catches a value bound counted in characters instead of bytes, off by one, or a control character let through.
  it("refuses a value over 512 bytes or with a control character, naming the header", () => {
    const bad = (n: string) =>
      "The value of {name} is up to 512 bytes without control characters".replace("{name}", n);
    assert.strictEqual(problem("X-A", "a".repeat(512)), "");
    assert.strictEqual(problem("X-A", "a".repeat(513)), bad("X-A"));
    assert.strictEqual(problem("X-A", "я".repeat(256)), "");
    assert.strictEqual(problem("X-A", "я".repeat(257)), bad("X-A"));
    for (const c of ["\n", "\r", "\t", "\u0000", "\u001f", "\u007f", "\u0085"]) {
      assert.strictEqual(problem("X-A", `a${c}b`), bad("X-A"));
    }
    assert.strictEqual(problem("X-A", "a b~\u00a0"), "");
  });

  // Catches an over-long value on a changed default, or on a removed default, going unchecked.
  it("checks the value of a changed default too", () => {
    const rows = withValue(DEFAULTS, headerRows(DEFAULTS), 0, "a\nb");
    assert.strictEqual(
      headersProblem(rows, t),
      "The value of {name} is up to 512 bytes without control characters".replace(
        "{name}",
        "User-Agent",
      ),
    );
  });

  // Catches a header name used as a replacement pattern, so a name with $& or $' reads as other text.
  it("names a header with dollar patterns as it is written", () => {
    assert.strictEqual(
      problem("X-$&", "a\nb"),
      "The value of X-$& is up to 512 bytes without control characters",
    );
    let rows = headerRows(DEFAULTS);
    for (const at of [3, 4]) rows = withValue(DEFAULTS, withName(added(rows), at, "X-$'"), at, "v");
    assert.strictEqual(headersProblem(rows, t), "Header X-$' is given twice");
  });

  // Catches the 16-header limit off by one, or own headers not counted.
  it("allows 16 own headers and refuses 17", () => {
    let rows = headerRows(DEFAULTS);
    const addOne = (i: number) => {
      const at = rows.length;
      rows = withValue(DEFAULTS, withName(added(rows), at, `X-${i}`), at, "v");
    };
    for (let i = 0; i < 16; i++) addOne(i);
    assert.strictEqual(headersProblem(rows, t), "");
    addOne(16);
    assert.strictEqual(headersProblem(rows, t), "At most 16 own headers");
  });
});
