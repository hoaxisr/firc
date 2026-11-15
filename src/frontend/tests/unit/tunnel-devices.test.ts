import assert from "node:assert";
import { afterEach, describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { loadTunnelDevices, tunnelDevices } = await import("../../src/data/tunnel-devices.svelte");

let answers: (() => unknown)[] = [];
let calls = 0;
(globalThis as any).fetch = async () => {
  calls++;
  const next = answers.shift();
  const body = next ? next() : { __status: 500 };
  if (body && typeof body === "object" && "__status" in body) {
    return {
      ok: false,
      status: 500,
      statusText: "error",
      text: async () => "{}",
      json: async () => ({}),
    };
  }
  return { ok: true, status: 200, json: async () => body };
};

describe("the tunnel devices the LAN picker hides", () => {
  afterEach(() => {
    answers = [];
    calls = 0;
  });

  // Catches a failed fetch read as "no tunnels", which would offer a configured tunnel as a LAN after it was known.
  it("keeps the last known devices when a load fails, and loads again on the next call", async () => {
    answers = [() => ({ __status: 500 })];
    await loadTunnelDevices();
    assert.deepStrictEqual(tunnelDevices.list, []);
    answers = [() => ({ tunnels: [{ id: "t0", device: "tunvless0" }] })];
    await loadTunnelDevices();
    assert.deepStrictEqual(tunnelDevices.list, [{ device: "tunvless0" }]);
    answers = [() => ({ __status: 500 })];
    await loadTunnelDevices();
    assert.deepStrictEqual(tunnelDevices.list, [{ device: "tunvless0" }]);
    assert.strictEqual(calls, 3);
  });

  // Catches every picker on the page sending its own request.
  it("asks once for loads that overlap", async () => {
    answers = [() => ({ tunnels: [{ id: "t1", device: "opkgtun1" }] })];
    await Promise.all([loadTunnelDevices(), loadTunnelDevices()]);
    assert.strictEqual(calls, 1);
    assert.deepStrictEqual(tunnelDevices.list, [{ device: "opkgtun1" }]);
  });
});
