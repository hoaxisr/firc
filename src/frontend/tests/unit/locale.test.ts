import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { browserLocale } from "../../src/utils/browser-locale";

describe("browserLocale", () => {
  // catches a match on the full tag, so ru-RU would fall to en
  it("takes ru for ru-RU", () => {
    assert.strictEqual(browserLocale({ languages: ["ru-RU", "en-US"] }), "ru");
  });

  // catches a default of ru, or a match on any language
  it("takes en for en-US", () => {
    assert.strictEqual(browserLocale({ languages: ["en-US"] }), "en");
  });

  // catches scanning past the first entry for a ru
  it("lets the first listed language decide", () => {
    assert.strictEqual(browserLocale({ languages: ["de", "ru"] }), "en");
    assert.strictEqual(browserLocale({ languages: ["ru", "de"] }), "ru");
  });

  // catches ignoring navigator.language when languages is empty
  it("falls back to navigator.language", () => {
    assert.strictEqual(browserLocale({ languages: [], language: "ru" }), "ru");
  });

  // catches a throw or a ru default without any navigator data
  it("takes en without a navigator or with empty lists", () => {
    assert.strictEqual(browserLocale(undefined), "en");
    assert.strictEqual(browserLocale({ languages: [] }), "en");
    assert.strictEqual(browserLocale({}), "en");
  });
});
