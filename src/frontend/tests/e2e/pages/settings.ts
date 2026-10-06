import type { Page, Route } from "@playwright/test";

import { signedIn } from "./session";

// Default units: timeout ms, ttlClamp s, idleWindow h, startMarkTableIndex hex.
export const DEFAULTS: Record<string, unknown> = {
  "app.dnsProxy.upstream.address": "127.0.0.1",
  "app.dnsProxy.upstream.port": 53,
  "app.dnsProxy.disableDropAAAA": false,
  "app.dnsProxy.unmatchedTtl": 60,
  "app.dnsProxy.timeout": 5000,
  "app.dnsProxy.maxConcurrent": 100,
  "app.dnsProxy.maxIdleConns": 10,
  "app.dnsProxy.host.address": "[::]",
  "app.dnsProxy.host.port": 3553,
  "app.dnsProxy.disableRemap53": false,
  "app.addressPool.ttlClamp": 300,
  "app.addressPool.idleWindow": 24,
  "app.addressPool.maxNames": 65536,
  "app.addressPool.v4.pool": "198.18.0.0/15",
  "app.addressPool.v4.chunk": 24,
  "app.addressPool.v6.pool": "",
  "app.addressPool.v6.chunk": 64,
  "app.netfilter.disableIPv4": false,
  "app.netfilter.disableIPv6": false,
  "app.link": ["br0"],
  "app.netfilter.iptables.chainPrefix": "FIRC_",
  "app.netfilter.startMarkTableIndex": "0x66697263",
  "app.showAllInterfaces": false,
  "app.httpWeb.host.address": "[::]",
  "app.httpWeb.host.port": 666,
  "app.logLevel": "info",
};

const LIVE = new Set([
  "app.dnsProxy.upstream.address",
  "app.dnsProxy.upstream.port",
  "app.dnsProxy.disableDropAAAA",
  "app.dnsProxy.unmatchedTtl",
  "app.showAllInterfaces",
  "app.logLevel",
]);

export const CLASSES: Record<string, string> = Object.fromEntries(
  Object.keys(DEFAULTS).map((k) => [k, LIVE.has(k) ? "live" : "restart"]),
);

export function answer(
  overrides: Record<string, unknown> = {},
  pendingRestart: string[] = [],
  classes: Record<string, string> = CLASSES,
  boot = "boot-1",
  restarting = false,
) {
  return { settings: { ...DEFAULTS, ...overrides }, classes, pendingRestart, boot, restarting };
}

export const oldDaemon = (pendingRestart: string[] = []) =>
  answer({}, pendingRestart, undefined, "boot-1", true);

export type Handler = (route: Route) => Promise<void> | void;

export async function openSettings(
  page: Page,
  onSettings: Handler,
  opts: { onRestart?: Handler; locale?: string } = {},
) {
  await signedIn(page);
  if (opts.locale) {
    await page.addInitScript((l) => {
      localStorage.setItem("locale", JSON.stringify({ value: l }));
    }, opts.locale);
  }
  await page.route("**/groups?with_rules=true", (r) => r.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (r) =>
    r.fulfill({ json: { interfaces: [{ id: "blackhole" }, { id: "br0" }, { id: "br1" }] } }),
  );
  await page.route("**/system/settings", onSettings);
  if (opts.onRestart) await page.route("**/system/restart", opts.onRestart);
  await page.goto("/");
  await page.getByRole("tab", { name: opts.locale === "ru" ? "Настройки" : "Settings" }).click();
}
