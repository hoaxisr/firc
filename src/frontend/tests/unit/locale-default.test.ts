import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const g = globalThis as any;
Object.defineProperty(g, "localStorage", {
  configurable: true,
  value: {
    getItem: (k: string) => (k === "locale" ? null : null),
    setItem: () => {},
  },
});
Object.defineProperty(g, "navigator", {
  configurable: true,
  value: { languages: ["ru-RU", "en-US"] },
});

const { locale } = await import("../../src/data/locale.svelte");

describe("locale state", () => {
  // catches the default staying en when nothing is saved
  it("opens in ru for a ru browser with nothing saved", () => {
    assert.strictEqual(locale.current, "ru");
  });
});
