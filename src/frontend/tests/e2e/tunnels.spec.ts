import { expect, test } from "@playwright/test";

import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

test.describe("Tunnels page", () => {
  // Catches a save sending a different body than the editor shows, or the picker not learning the new device.
  test("a new tunnel with a subscription and a link saves exactly and joins the group interface list", async ({
    page,
  }) => {
    const daemon = await stubDaemon(page, {
      groups: [
        {
          id: "aaaaaaaa",
          name: "g",
          interface: "wg0",
          enable: true,
          rules: [],
          devices: { allow: [], deny: [] },
          resolve: { tunnel: true, server: "" },
        },
      ],
    });
    daemon.putAnswer = (body, route) => {
      daemon.interfaces = ["wg0", "tunvless0"];
      return route.fulfill({
        json: { tunnels: body.tunnels, restarted: ["tunvless0"], updated: [] },
      });
    };
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await expect(page.getByText("No tunnels yet")).toBeVisible();

    await tunnels.add.click();
    await tunnels.addSubscription("tunnel1", "Provider", "https://sub.example/feed");
    await tunnels.addLink("tunnel1", "vless://u@h.example:443?security=tls#Solo");
    const before = daemon.interfaceFetches;
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(daemon.puts).toEqual([
      {
        tunnels: [
          {
            id: "tunnel1",
            device: "tunvless0",
            enable: true,
            active: 1,
            by: "connection",
            interval: 60,
            silence: 20,
            filter: "",
            order: [],
            exclude: [],
            sources: [
              {
                kind: "subscription",
                name: "Provider",
                url: "https://sub.example/feed",
                interval: 21600,
              },
              { kind: "link", link: "vless://u@h.example:443?security=tls#Solo" },
            ],
            uplink: { kind: "auto", ref: "" },
            advanced: { ca: "", insecure: false, timeout: 8 },
          },
        ],
      },
    ]);
    await expect.poll(() => daemon.interfaceFetches).toBeGreaterThan(before);

    await tunnels.tab("Groups").click();
    await page.locator(".iface-select [data-select-trigger]").first().click();
    await expect(page.locator('[data-select-item][data-value="tunvless0"]')).toBeVisible();
  });

  // Catches a state looked up by list position instead of the daemon's tunnel id, or a status word lost on the card.
  test("every state renders on its own card by tunnel id", async ({ page }) => {
    const sub = {
      name: "Provider",
      url: "https://sub.example/feed",
      kind: "subscription",
      id: "s1",
      interval: 21600,
    };
    await stubDaemon(page, {
      tunnels: [
        tunnel("t0", "tunvless0", { sources: [sub] }),
        tunnel("t1", "tunvless1"),
        tunnel("t2", "tunvless2", { enable: false }),
        tunnel("t3", "tunvless3", { sources: [sub] }),
        tunnel("t4", "tunvless4"),
      ],
      states: [
        state("t4", "tunvless4", { status: "uplink_down", uplinkOk: false }),
        state("t3", "tunvless3", {
          status: "up",
          active: ["B"],
          nodes: [
            {
              key: "k:A",
              name: "A",
              source: "Provider",
              state: "reserve",
              since: 0,
              skipReason: "",
            },
            {
              key: "k:B",
              name: "B",
              source: "Provider",
              state: "active",
              since: 0,
              skipReason: "",
            },
          ],
          subscriptions: [
            {
              name: "Provider",
              nodes: 2,
              lastOk: 1790000000,
              lastTry: 1790000100,
              fetching: false,
              error: "fetch failed: 503",
            },
          ],
        }),
        state("t2", "tunvless2", { status: "off" }),
        state("t1", "tunvless1", { status: "no_node", backoffS: 0 }),
        state("t0", "tunvless0", { status: "bad_config" }),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();

    await expect(tunnels.card("t3")).toContainText("active: B");
    await expect(tunnels.card("t3")).toContainText("1 of 2 nodes");
    await expect(tunnels.card("t1")).toContainText("No node answers");
    await expect(tunnels.card("t2")).toContainText("Off");
    await expect(tunnels.card("t4")).toContainText("Uplink unavailable");
    await expect(tunnels.card("t0")).toContainText("Configuration error");
    await expect(tunnels.card("t3")).not.toContainText("Off");

    await tunnels.expand("t3");
    await expect(tunnels.card("t3")).toContainText("error: fetch failed: 503");
    await expect(tunnels.card("t3")).toContainText("(last good)");
  });

  // Catches a refusal naming one tunnel being shown as a banner, or on the wrong card.
  test("a rejected save marks the field on the tunnel the daemon names", async ({ page }) => {
    const daemon = await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0"), tunnel("b", "tunvless1")],
      states: [state("b", "tunvless1"), state("a", "tunvless0")],
    });
    daemon.putAnswer = (_body, route) =>
      route.fulfill({
        status: 400,
        json: { error: "active must be 1..8", field: "active", tunnel: "b" },
      });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("b");
    await tunnels.card("b").getByLabel("Active nodes").fill("9");
    await tunnels.save.click();

    const inline = tunnels.card("b").getByRole("alert").filter({ hasText: "active must be 1..8" });
    await expect(inline).toBeVisible();
    await expect(inline.locator("code")).toHaveText("active");
    await expect(tunnels.card("a").getByRole("alert")).toHaveCount(0);
    await expect(page.locator(".tunnels-page > [role=alert]")).toHaveCount(0);
  });

  // Catches the restart note naming every tunnel, or a node or subscription interval edit counting as a restart.
  test("the restart note names the tunnel whose run changed, not a node or interval edit", async ({
    page,
  }) => {
    const sub = {
      id: "s1",
      kind: "subscription",
      name: "Provider",
      url: "https://sub.example/feed",
      interval: 21600,
    };
    await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0", { sources: [sub] }), tunnel("b", "tunvless1")],
      states: [state("a", "tunvless0"), state("b", "tunvless1")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await expect(tunnels.note).toHaveCount(0);

    await tunnels.expand("a");
    await tunnels.card("a").getByRole("button", { name: "Update interval" }).click();
    await page.locator('[data-select-item][data-value="3600"]').click();
    await expect(tunnels.save).not.toHaveClass(/inactive/);
    await expect(tunnels.note).toHaveCount(0);
    await tunnels.card("a").getByLabel("Filter by name").fill("NL");
    await expect(tunnels.card("a").getByLabel("Filter by name")).toHaveValue("NL");
    await expect(tunnels.note).toHaveCount(0);

    await tunnels.expand("b");
    await tunnels.card("b").getByLabel("Active nodes").fill("2");
    await expect(tunnels.note).toHaveText(/tunvless1 will restart on save/);
    await expect(tunnels.note).not.toContainText("tunvless0");
  });

  // Catches the poll running for a tab the user left, or for a hidden document, or not resuming.
  test("state polling stops off the tab and while the document is hidden", async ({ page }) => {
    await page.clock.install();
    const daemon = await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0")],
      states: [state("a", "tunvless0")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await expect(tunnels.card("a")).toBeVisible();

    const seen = daemon.polls;
    await page.clock.runFor(6000);
    await expect.poll(() => daemon.polls).toBeGreaterThan(seen);

    await tunnels.tab("Groups").click();
    await page.clock.runFor(500);
    const away = daemon.polls;
    await page.clock.runFor(10_000);
    await tunnels.settle();
    expect(daemon.polls, "no poll off the tab").toBe(away);

    await tunnels.tab("Tunnels").click();
    await expect.poll(() => daemon.polls).toBeGreaterThan(away);

    await tunnels.setVisibility("hidden");
    await page.clock.runFor(500);
    const hidden = daemon.polls;
    await page.clock.runFor(10_000);
    await tunnels.settle();
    expect(daemon.polls, "no poll while hidden").toBe(hidden);

    await tunnels.setVisibility("visible");
    await expect.poll(() => daemon.polls).toBeGreaterThan(hidden);
    const shown = daemon.polls;
    await page.clock.runFor(2500);
    await expect.poll(() => daemon.polls).toBeGreaterThan(shown);
  });

  // Catches an uplink list offering a loop, or the tunnels' own devices as an outgoing interface.
  test("the uplink select disables a loop and leaves out tunnel devices", async ({ page }) => {
    await stubDaemon(page, {
      interfaces: ["wg0", "tunvless0", "tunvless1", "tunvless2", "blackhole"],
      tunnels: [
        tunnel("a", "tunvless0", { uplink: { kind: "tunnel", ref: "b" } }),
        tunnel("b", "tunvless1", { uplink: { kind: "iface", ref: "wg0" } }),
        tunnel("c", "tunvless2"),
      ],
      states: [],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("b");
    await tunnels.card("b").getByRole("button", { name: "Way out to the internet" }).click();

    const item = (value: string) => page.locator(`[data-select-item][data-value="${value}"]`);
    await expect(item("auto")).toBeVisible();
    await expect(item("iface:wg0")).toBeVisible();
    await expect(item("tunnel:c")).not.toHaveAttribute("data-disabled", /.*/);
    await expect(item("tunnel:a")).toHaveAttribute("data-disabled", /.*/);
    await expect(item("iface:tunvless1")).toHaveCount(0);
    await expect(item("iface:blackhole")).toHaveCount(0);

    await item("tunnel:a").click({ force: true });
    await expect(
      tunnels.card("b").getByRole("button", { name: "Way out to the internet" }),
    ).toContainText("wg0");
    await expect(tunnels.save).toHaveClass(/inactive/);
  });

  // Catches an icon-only tunnel control, or a node switch, that a screen reader announces as nothing.
  test("every control on an open tunnel card has an accessible name", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [
        tunnel("a", "tunvless0", {
          sources: [
            {
              id: "s1",
              kind: "subscription",
              name: "Provider",
              url: "https://sub.example/feed",
              interval: 21600,
            },
            { id: "l1", kind: "link", link: "vless://u@h.example:443#Solo" },
          ],
        }),
      ],
      states: [state("a", "tunvless0")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    await expect(tunnels.nodeRows("a")).toHaveCount(3);
    await tunnels.card("a").getByRole("button", { name: "More: connect timeout" }).click();

    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll('[data-tunnel] button, [data-tunnel] [role="switch"]')]
        .filter((el) => {
          const label = el.getAttribute("aria-label") || el.getAttribute("title") || "";
          return !label.trim() && !(el.textContent || "").trim();
        })
        .map((el) => el.outerHTML.slice(0, 120)),
    );
    expect(unnamed).toEqual([]);
  });

  // Catches the groups line using the wrong count, order, or the empty wording.
  test("the groups line lists the groups a tunnel serves", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0"), tunnel("b", "tunvless1")],
      states: [state("a", "tunvless0", { groups: ["g1", "g2"] }), state("b", "tunvless1")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await expect(tunnels.card("a")).toContainText("2 groups: g1, g2");
    await expect(tunnels.card("a")).not.toContainText("not used by groups");
    await expect(tunnels.card("b")).toContainText("not used by groups");
  });
});
