import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const g = globalThis as any;
Object.defineProperty(g, "localStorage", {
  configurable: true,
  value: {
    getItem: (k: string) => (k === "locale" ? '{"value":"en"}' : null),
    setItem: () => {},
  },
});
Object.defineProperty(g, "navigator", { configurable: true, value: { languages: ["ru-RU"] } });

const { locale } = await import("../../src/data/locale.svelte");

describe("locale state", () => {
  // catches the browser language overriding a saved choice
  it("keeps a saved en over a ru browser", () => {
    assert.strictEqual(locale.current, "en");
  });
});
