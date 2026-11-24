import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { listName } from "../../src/modules/groups/list-name.ts";

describe("a list's short name", () => {
  it("is the last path segment, without query, fragment or trailing slash", () => {
    assert.strictEqual(
      listName(
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-telegram.srs",
      ),
      "geosite-telegram.srs",
    );
    assert.strictEqual(listName("https://example.com/lists/ads.txt?token=1#x"), "ads.txt");
    assert.strictEqual(listName("https://example.com/lists/"), "lists");
  });

  it("is the host when the url has no path", () => {
    assert.strictEqual(listName("https://example.com"), "example.com");
    assert.strictEqual(listName("https://example.com/"), "example.com");
  });
});
