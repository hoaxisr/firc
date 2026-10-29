import { expect, test } from "@playwright/test";

import { answerConfirm } from "./pages/confirm";
import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

test.describe("Tunnels page", () => {
  // Catches a restart sent without asking, sent after Cancel or Escape, or a dialog that lands on the confirming button.
  test("a restart asks first, and only the confirming button sends it", async ({ page }) => {
    await stubDaemon(page, { tunnels: [tunnel("a", "tunvless0")] });
    let restarts = 0;
    await page.route("**/tunnels/a/restart", (route) => {
      restarts += 1;
      return route.fulfill({ json: {} });
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    const restartButton = tunnels.card("a").getByRole("button", { name: "Restart" });
    const dialog = page.getByRole("alertdialog");

    await restartButton.click();
    await expect(dialog.locator(".confirm-title")).toHaveText("Restart tunvless0?");
    await expect(dialog.locator(".confirm-cancel")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);

    await restartButton.click();
    expect(await answerConfirm(page, false)).toBe("Restart tunvless0?");
    expect(restarts).toBe(0);

    await restartButton.click();
    await answerConfirm(page, true);
    await expect.poll(() => restarts).toBe(1);
  });

  // Catches a link or subscription address, which carry the account secret, shown before it is asked for.
  test("source addresses stay hidden until shown", async ({ page }) => {
    await stubDaemon(page, {});
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.addTunnel();
    await tunnels.addSubscription("tunnel1", "Provider", "https://sub.example/feed?token=s3cret");
    await tunnels.addLink("tunnel1", "vless://u-secret@h.example:443?security=tls#Solo");
    const card = tunnels.card("tunnel1");
    await expect(card).not.toContainText("s3cret");
    await expect(card).not.toContainText("u-secret");
    await card.getByRole("button", { name: "Show the address" }).nth(1).click();
    await expect(card).toContainText("u-secret");
    await expect(card).not.toContainText("s3cret");
  });

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

    await tunnels.addTunnel();
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
            description: "",
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
            advanced: { ca: "", insecure: false, timeout: 8, kernelTcp: false, fingerprint: "" },
            inbounds: [],
          },
        ],
      },
    ]);
    await expect.poll(() => daemon.interfaceFetches).toBeGreaterThan(before);

    await tunnels.tab("Groups").click();
    await page.locator(".iface-select [data-select-trigger]").first().click();
    await expect(page.locator('[data-select-item][data-value="tunvless0"]')).toBeVisible();
  });

  // Catches a description not sent in the save, missing from the card header, or not shown in the group interface list.
  test("a description is saved, shown on the card and named in the group interface list", async ({
    page,
  }) => {
    const daemon = await stubDaemon(page, {
      interfaces: ["wg0", "tunvless0"],
      tunnels: [tunnel("a", "tunvless0", { enable: false })],
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
      daemon.names = { tunvless0: body.tunnels[0].description };
      return route.fulfill({ json: { tunnels: body.tunnels, restarted: [], updated: [] } });
    };
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    const field = tunnels.card("a").getByRole("textbox", { name: "Description" });

    await field.fill("П".repeat(32));
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(tunnels.card("a")).toContainText("At most 63 bytes");
    await field.fill("PRAW-1");
    await expect(field).toHaveAttribute("aria-invalid", "false");
    await expect(tunnels.card("a").locator(".title-row input.description")).toHaveValue("PRAW-1");

    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].description).toBe("PRAW-1");

    await tunnels.tab("Groups").click();
    await page.locator(".iface-select [data-select-trigger]").first().click();
    await expect(page.locator('[data-select-item][data-value="tunvless0"]')).toContainText(
      "PRAW-1",
    );
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

  // Catches the provider's traffic and end date missing from the source row, an ending plan not warned about on the
  // card's head line, or a warning shown for a subscription the provider said nothing about.
  test("a subscription shows its traffic and end date and warns before it ends", async ({
    page,
  }) => {
    const sub = {
      name: "Provider",
      url: "https://sub.example/feed",
      kind: "subscription",
      id: "s1",
      interval: 21600,
    };
    const now = Math.floor(Date.now() / 1000);
    const GiB = 2 ** 30;
    const subState = (usage: object | null) => ({
      name: "Provider",
      nodes: 2,
      lastOk: now - 60,
      lastTry: now - 60,
      fetching: false,
      error: "",
      usage,
    });
    await stubDaemon(page, {
      tunnels: [
        tunnel("a", "tunvless0", { sources: [sub] }),
        tunnel("b", "tunvless1", { sources: [sub] }),
        tunnel("c", "tunvless2", { sources: [sub] }),
      ],
      states: [
        state("a", "tunvless0", {
          subscriptions: [
            subState({ used: 12.5 * GiB, total: 100 * GiB, expire: now + 30 * 86400 }),
          ],
        }),
        state("b", "tunvless1", {
          subscriptions: [subState({ used: 95 * GiB, total: 0, expire: now - 3600 })],
        }),
        state("c", "tunvless2", { subscriptions: [subState(null)] }),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();

    await expect(tunnels.card("a").locator("[data-sub-alert]")).toHaveCount(0);
    await expect(tunnels.card("b").locator('[data-sub-alert="Provider"]')).toHaveText(
      "«Provider»: has ended",
    );
    await expect(tunnels.card("c").locator("[data-sub-alert]")).toHaveCount(0);

    await tunnels.expand("a");
    const traffic = tunnels.card("a").locator('[data-usage="traffic"]');
    await expect(traffic).toHaveText("Traffic: 12.5 GB of 100 GB");
    await expect(traffic).not.toHaveClass(/orange|red/);
    await expect(tunnels.card("a").locator('[data-usage="expiry"]')).toContainText("until ");

    await tunnels.expand("b");
    await expect(tunnels.card("b").locator('[data-usage="traffic"]')).toHaveText(
      "Traffic: 95 GB, no limit",
    );
    const ended = tunnels.card("b").locator('[data-usage="expiry"]');
    await expect(ended).toContainText("ended ");
    await expect(ended).toHaveClass(/red/);

    await tunnels.expand("c");
    await expect(tunnels.card("c").locator("[data-usage]")).toHaveCount(0);
  });

  // Catches the IPv6 tag missing on an active v6 node, or shown on a v4-only one or a node that is not active.
  test("an active node that carries IPv6 shows the tag and the others do not", async ({ page }) => {
    const node = (name: string, nodeState: string, v6?: boolean) => ({
      key: `0000000a:${name}`,
      name,
      source: "Provider",
      state: nodeState,
      since: 0,
      skipReason: "",
      ...(v6 === undefined ? {} : { v6 }),
    });
    await stubDaemon(page, {
      tunnels: [tunnel("t3", "tunvless3")],
      states: [
        state("t3", "tunvless3", {
          status: "up",
          active: ["A", "B"],
          nodes: [node("A", "active", true), node("B", "active"), node("C", "reserve", true)],
        }),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("t3");
    const rows = tunnels.nodeRows("t3");
    await expect(rows.nth(0).locator(".badge.v6")).toHaveText("IPv6");
    await expect(rows.nth(1).locator(".badge.v6")).toHaveCount(0);
    await expect(rows.nth(2).locator(".badge.v6")).toHaveCount(0);
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

  // Catches the node table of an opened card waiting out the edit debounce, so the card jumps late.
  test("an opened card asks for its nodes at once", async ({ page }) => {
    await stubDaemon(page, { tunnels: [tunnel("a", "tunvless0")], states: [] });
    const tunnels = new TunnelsPage(page);
    await page.clock.install();
    await tunnels.open();
    await page.clock.pauseAt(Date.now() + 60_000);
    const asked = page.waitForRequest("**/tunnels/preview", { timeout: 2000 });
    await tunnels.card("a").getByRole("button", { name: "Expand", exact: true }).click();
    await asked;
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

  // Catches the rest of the interfaces shown open or unreachable, a wan or tunnel one folded away, or a description or the provider tag lost.
  test("the uplink offers wan and tunnel interfaces, the rest behind more", async ({ page }) => {
    await stubDaemon(page, {
      interfaces: ["ppp0", "nwg1", "br0", "eth2.1"],
      names: { ppp0: "Broadband", br0: "Home" },
      ndms: { nwg1: "Wireguard1" },
      roles: { ppp0: "wan", nwg1: "tunnel", br0: "lan", "eth2.1": "other" },
      tunnels: [tunnel("a", "tunvless0")],
      states: [],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    await tunnels.card("a").getByRole("button", { name: "Way out to the internet" }).click();
    const item = (value: string) => page.locator(`[data-select-item][data-value="${value}"]`);
    await expect(item("iface:ppp0")).toContainText("Broadband");
    await expect(item("iface:ppp0")).toContainText("ppp0");
    await expect(item("iface:ppp0")).toContainText("provider");
    await expect(item("iface:nwg1")).toContainText("Wireguard1");
    await expect(item("iface:br0")).toHaveCount(0);
    await expect(item("iface:eth2.1")).toHaveCount(0);

    await item("__more__").click();
    await expect(item("iface:br0")).toContainText("Home");
    await item("iface:eth2.1").click();
    await expect(
      tunnels.card("a").getByRole("button", { name: "Way out to the internet" }),
    ).toContainText("eth2.1");
  });

  // Catches a typeahead key on the closed uplink select landing on the more row and resetting the uplink to auto.
  test("a key on the closed uplink select keeps the uplink", async ({ page }) => {
    await stubDaemon(page, {
      interfaces: ["ppp0", "br0", "eth2.1"],
      names: { ppp0: "Broadband" },
      roles: { ppp0: "wan", br0: "lan", "eth2.1": "other" },
      tunnels: [tunnel("a", "tunvless0", { uplink: { kind: "iface", ref: "ppp0" } })],
      states: [],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    const trigger = tunnels.card("a").getByRole("button", { name: "Way out to the internet" });
    await trigger.focus();
    await page.keyboard.press("2");
    await expect(trigger).toContainText("Broadband");
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

  // Catches the Save and Add buttons drawn over the hint on a phone, where the page has no search to give their row a height.
  test("on a phone the hint sits below Save and Add", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0")],
      states: [state("a", "tunvless0")],
    });
    await page.setViewportSize({ width: 398, height: 880 });
    const tunnels = new TunnelsPage(page);
    await tunnels.openOnPhone();
    const add = (await page.getByRole("button", { name: "Add tunnel" }).boundingBox())!;
    const hint = (await page.locator("p.hint").boundingBox())!;
    expect(hint.y).toBeGreaterThanOrEqual(add.y + add.height);
  });

  // Catches a new tunnel card added below the fold on a phone with nothing bringing it into view.
  test("on a phone a new tunnel scrolls into view", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0"), tunnel("b", "tunvless1"), tunnel("c", "tunvless2")],
      states: [state("a", "tunvless0"), state("b", "tunvless1"), state("c", "tunvless2")],
    });
    await page.setViewportSize({ width: 360, height: 640 });
    const tunnels = new TunnelsPage(page);
    await tunnels.openOnPhone();
    await tunnels.expand("a");
    await tunnels.addTunnel();
    const card = page.locator("[data-tunnel]").last();
    await expect(card.getByRole("textbox", { name: "Description" })).toBeFocused();
    const bar = page.locator('[data-tabs-content][data-state="active"] .page-controls');
    await expect
      .poll(async () => {
        const box = (await card.boundingBox())!;
        const top = (await bar.boundingBox())!;
        return box.y >= top.y + top.height && box.y < 640 / 2;
      })
      .toBe(true);
  });
});
