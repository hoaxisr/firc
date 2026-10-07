import { expect, type Locator, type Page, type Route } from "@playwright/test";

import { signedIn } from "./session";

type Json = Record<string, any>;

export const tunnel = (id: string, device: string, extra: Json = {}): Json => ({
  id,
  device,
  description: "",
  enable: true,
  active: 1,
  by: "connection",
  interval: 60,
  silence: 20,
  filter: "",
  order: [],
  exclude: [],
  sources: [],
  uplink: { kind: "auto", ref: "" },
  advanced: { ca: "", insecure: false, timeout: 8 },
  ...extra,
});

export const state = (id: string, device: string, extra: Json = {}): Json => ({
  id,
  device,
  status: "up",
  since: 1790000000,
  backoffS: 0,
  active: [],
  groups: [],
  nodes: [],
  subscriptions: [],
  rxBps: 0,
  txBps: 0,
  lastExit: 0,
  uplinkOk: true,
  ...extra,
});

export const NODES = [
  { key: "0000000a:A", name: "A", source: "Provider" },
  { key: "0000000a:B", name: "B", source: "Provider" },
  { key: "0000000a:C", name: "C", source: "Provider" },
];

export type Daemon = {
  tunnels: Json[];
  states: Json[];
  interfaces: string[];
  names: Record<string, string>;
  groups: Json[];
  puts: Json[];
  previews: Json[];
  probes: Json[];
  polls: number;
  interfaceFetches: number;
  putAnswer: ((body: Json, route: Route) => Promise<void> | void) | null;
  probeAnswer: ((body: Json, route: Route) => Promise<void> | void) | null;
  previewAnswer: ((body: Json, route: Route) => Promise<void> | void) | null;
  nodes: Json[];
};

export async function stubDaemon(page: Page, init: Partial<Daemon> = {}): Promise<Daemon> {
  const daemon: Daemon = {
    tunnels: [],
    states: [],
    interfaces: ["wg0"],
    names: {},
    groups: [],
    puts: [],
    previews: [],
    probes: [],
    polls: 0,
    interfaceFetches: 0,
    putAnswer: null,
    probeAnswer: null,
    previewAnswer: null,
    nodes: NODES,
    ...init,
  };
  await signedIn(page);
  await page.route("**/interfaces", (route) => {
    daemon.interfaceFetches++;
    return route.fulfill({
      json: { interfaces: daemon.interfaces.map((id) => ({ id, name: daemon.names[id] ?? id })) },
    });
  });
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({ json: { groups: daemon.groups } }),
  );
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/tunnels", async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      return route.fulfill({ json: { tunnels: daemon.tunnels } });
    }
    const body = request.postDataJSON();
    daemon.puts.push(body);
    if (daemon.putAnswer) return daemon.putAnswer(body, route);
    daemon.tunnels = body.tunnels;
    return route.fulfill({ json: { tunnels: body.tunnels, restarted: [], updated: [] } });
  });
  await page.route("**/tunnels/state", (route) => {
    daemon.polls++;
    return route.fulfill({ json: { tunnels: daemon.states } });
  });
  await page.route("**/tunnels/preview", async (route) => {
    const body = route.request().postDataJSON();
    daemon.previews.push(body);
    if (daemon.previewAnswer) return daemon.previewAnswer(body, route);
    let matcher: RegExp | null = null;
    try {
      matcher = body.tunnel.filter ? new RegExp(body.tunnel.filter, "i") : null;
    } catch {
      matcher = null;
    }
    const known = daemon.nodes.filter((n) => !matcher || matcher.test(n.name));
    const order: string[] = body.tunnel.order ?? [];
    const rows = [...known]
      .sort((a, b) => {
        const ia = order.indexOf(a.key);
        const ib = order.indexOf(b.key);
        return (ia < 0 ? 1e6 : ia) - (ib < 0 ? 1e6 : ib);
      })
      .map((n) => ({
        key: n.key,
        name: n.name,
        source: n.source,
        excluded: (body.tunnel.exclude ?? []).includes(n.key),
        isNew: false,
        missing: false,
        overCap: false,
        skipReason: "",
      }));
    return route.fulfill({
      json: { matched: known.length, total: daemon.nodes.length, nodes: rows, subscriptions: [] },
    });
  });
  await page.route("**/tunnels/probe", async (route) => {
    const body = route.request().postDataJSON();
    daemon.probes.push(body);
    if (daemon.probeAnswer) return daemon.probeAnswer(body, route);
    return route.fulfill({ json: { nodes: [] } });
  });
  return daemon;
}

export class TunnelsPage {
  readonly page: Page;
  readonly save: Locator;
  readonly add: Locator;
  readonly note: Locator;

  constructor(page: Page) {
    this.page = page;
    const pane = page.locator('[data-tabs-content][data-state="active"]');
    this.save = pane.getByRole("button", { name: "Save", exact: true });
    this.add = pane.getByRole("button", { name: "Add tunnel", exact: true });
    this.note = page.getByRole("status").filter({ hasText: "restart on save" });
  }

  async open() {
    await this.page.goto("/");
    await this.tab("Tunnels").click();
  }

  async addTunnel() {
    await expect(this.add).not.toHaveClass(/inactive/);
    await this.add.click();
  }

  tab(name: string): Locator {
    return this.page.getByRole("tab", { name });
  }

  card(id: string): Locator {
    return this.page.locator(`[data-tunnel="${id}"]`);
  }

  async expand(id: string) {
    await this.card(id).getByRole("button", { name: "Expand", exact: true }).click();
  }

  nodeRows(id: string): Locator {
    return this.card(id).locator(".node[data-key]");
  }

  nodeNames(id: string): Locator {
    return this.nodeRows(id).locator(".name");
  }

  filter(id: string): Locator {
    return this.card(id).getByRole("textbox", { name: "Filter by name" });
  }

  async addSubscription(id: string, name: string, url: string) {
    await this.card(id).getByRole("button", { name: "Subscription" }).click();
    const dialog = this.page.getByRole("dialog");
    await dialog.getByLabel("Name").fill(name);
    await dialog.getByLabel("URL").fill(url);
    await dialog.getByRole("button", { name: "Add", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
  }

  async addLink(id: string, link: string) {
    await this.card(id).getByRole("button", { name: "Link", exact: true }).click();
    const dialog = this.page.getByRole("dialog");
    await dialog.getByLabel("vless:// link").fill(link);
    await dialog.getByRole("button", { name: "Add", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
  }

  async drag(source: Locator, target: Locator, where: "before" | "after") {
    const from = await source.locator(".grip").boundingBox();
    const to = await target.boundingBox();
    if (!from || !to) throw new Error("no box to drag");
    await this.page.mouse.move(from.x + from.width / 2, from.y + from.height / 2);
    await this.page.mouse.down();
    await this.page.mouse.move(
      to.x + to.width / 2,
      to.y + to.height * (where === "before" ? 0.25 : 0.75),
      { steps: 10 },
    );
    await this.page.mouse.up();
  }

  async settle() {
    for (let i = 0; i < 2; i++)
      await this.page.evaluate(() => fetch("/api/v1/system/hosts").then((r) => r.text()));
  }

  async setVisibility(state: "hidden" | "visible") {
    await this.page.evaluate((s) => {
      Object.defineProperty(document, "visibilityState", { value: s, configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    }, state);
  }
}
