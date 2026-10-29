import { expect, test } from "@playwright/test";

import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

const SUB = {
  id: "s1",
  kind: "subscription",
  name: "Provider",
  url: "https://sub.example/feed",
  interval: 21600,
};
const KEY = "0000000a:B";

async function open(
  page: import("@playwright/test").Page,
  inbounds: object[] = [],
  live: object[] = [],
  phone = false,
) {
  const daemon = await stubDaemon(page, {
    link: ["br0", "br1"],
    tunnels: [tunnel("a", "tunvless0", { sources: [SUB], inbounds })],
    states: [state("a", "tunvless0", { inbounds: live })],
  });
  const tunnels = new TunnelsPage(page);
  await (phone ? tunnels.openOnPhone() : tunnels.open());
  await tunnels.expand("a");
  await expect(tunnels.nodeRows("a")).toHaveCount(3);
  return { daemon, tunnels };
}

const saved = (extra = {}) => ({
  port: 1081,
  listen: "br0",
  node: KEY,
  user: "",
  password: "",
  ...extra,
});

test.describe("Tunnel inbounds", () => {
  // Catches a row that never reaches the PUT body, a default listen or node left empty, or a password sent masked.
  test("adds an inbound and saves it", async ({ page }) => {
    const { daemon, tunnels } = await open(page);
    const card = tunnels.card("a");
    await card.getByRole("button", { name: "Add port" }).click();
    const row = tunnels.inboundRows("a").first();
    await expect(row.getByRole("spinbutton", { name: "Port" })).toHaveValue("1080");
    await row.getByRole("spinbutton", { name: "Port" }).fill("1085");
    await row.getByRole("textbox", { name: "Login" }).fill("bob");
    await row.getByLabel("Password", { exact: true }).fill("s3cret");
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].inbounds).toEqual([
      { port: 1085, listen: "br0", node: "0000000a:A", user: "bob", password: "s3cret" },
    ]);
  });

  // Catches the whole group missing from the node list, or sent as anything but "*".
  test("a port can carry the whole group", async ({ page }) => {
    const { daemon, tunnels } = await open(page);
    await tunnels.card("a").getByRole("button", { name: "Add port" }).click();
    const row = tunnels.inboundRows("a").first();
    await row.getByRole("button", { name: "Node" }).click();
    await page.getByRole("option", { name: "Whole group" }).click();
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].inbounds).toEqual([
      { port: 1080, listen: "br0", node: "*", user: "", password: "" },
    ]);
  });

  // Catches a saved whole-group port shown as a raw "*" instead of its name.
  test("a saved whole-group port names the group", async ({ page }) => {
    const { tunnels } = await open(page, [saved({ node: "*" })]);
    const row = tunnels.inboundRows("a").first();
    await expect(row.getByRole("button", { name: "Node" })).toContainText("Whole group");
  });

  // Catches a password shown in clear before the eye is pressed, or the eye not revealing it.
  test("the password is masked until the eye is pressed", async ({ page }) => {
    const { tunnels } = await open(page, [saved({ user: "bob", password: "s3cret" })]);
    const field = tunnels.inboundRows("a").first().getByLabel("Password", { exact: true });
    await expect(field).toHaveAttribute("type", "password");
    await tunnels
      .inboundRows("a")
      .first()
      .getByRole("button", { name: "Show the password" })
      .click();
    await expect(field).toHaveAttribute("type", "text");
  });

  // Catches a busy state shown as listening, in the wrong colour, or matched to the wrong row by port.
  test("shows a busy port in red", async ({ page }) => {
    const { tunnels } = await open(
      page,
      [saved(), saved({ port: 1082 })],
      [
        { port: 1081, state: "up", why: "", rxBps: 0, txBps: 0 },
        { port: 1082, state: "busy", why: "", rxBps: 0, txBps: 0 },
      ],
    );
    const rows = tunnels.inboundRows("a");
    await expect(rows.nth(0).locator(".st")).toHaveText("listens");
    const busy = rows.nth(1).locator(".st");
    await expect(busy).toHaveText("port is busy");
    await expect(busy).toHaveClass(/red/);
  });

  // Catches the interface name missing from the no-address text, or a gone node not named as gone.
  test("a gone node is named and a missing address names the interface", async ({ page }) => {
    const { tunnels } = await open(
      page,
      [saved(), saved({ port: 1082, listen: "br1" })],
      [
        { port: 1081, state: "no-node", why: "", rxBps: 0, txBps: 0 },
        { port: 1082, state: "no-address", why: "", rxBps: 0, txBps: 0 },
      ],
    );
    const rows = tunnels.inboundRows("a");
    const gone = rows.nth(0).locator(".st");
    await expect(gone).toHaveText("node is gone");
    await expect(gone).toHaveClass(/orange/);
    await expect(rows.nth(1).locator(".st")).toHaveText("br1 has no IPv4");
  });

  // Catches the port badge missing from the node table or put on the wrong node.
  test("the node table shows the bound port", async ({ page }) => {
    const { tunnels } = await open(page, [saved(), saved({ port: 1090 })]);
    const rows = tunnels.nodeRows("a");
    await expect(rows.filter({ hasText: "B" }).locator(".port")).toHaveText([":1081", ":1090"]);
    await expect(tunnels.card("a").locator('.node[data-key="0000000a:A"] .port')).toHaveCount(0);
  });

  // Catches the head line showing rates for a port that is not up, or leaving the port out.
  test("the head line shows the rate of a listening port", async ({ page }) => {
    const live = [
      { port: 1081, state: "up", why: "", rxBps: 125000, txBps: 12500 },
      { port: 1082, state: "busy", why: "", rxBps: 999999, txBps: 999999 },
    ];
    const { tunnels } = await open(page, [saved(), saved({ port: 1082 })], live);
    const line = tunnels.card("a").locator(".head .line");
    await expect(line).toContainText(":1081 ↓ 1 Mbit/s · ↑ 100 Kbit/s");
    await expect(line).not.toContainText(":1082");
  });

  // Catches the early mirror not stopping a duplicate port before the request.
  test("a duplicate port is refused on the card before saving", async ({ page }) => {
    const { daemon, tunnels } = await open(page, [saved()]);
    const card = tunnels.card("a");
    await card.getByRole("button", { name: "Add port" }).click();
    await tunnels.inboundRows("a").nth(1).getByRole("spinbutton", { name: "Port" }).fill("1081");
    await expect(card.locator(".inb-refusal")).toHaveText(
      "inbounds[1].port used twice in this tunnel",
    );
    await tunnels.save.click();
    expect(daemon.puts.length).toBe(0);
  });

  // Catches the add button staying active at 16 rows.
  test("Add port is inactive at sixteen", async ({ page }) => {
    const sixteen = Array.from({ length: 16 }, (_, i) => saved({ port: 2000 + i }));
    const { tunnels } = await open(page, sixteen);
    await expect(tunnels.card("a").getByRole("button", { name: "Add port" })).toHaveClass(
      /inactive/,
    );
  });

  // Catches a daemon refusal of an inbound field not shown on its card.
  test("a daemon refusal of an inbound is shown on the card", async ({ page }) => {
    const { daemon, tunnels } = await open(page, [saved()]);
    daemon.putAnswer = (_body, route) =>
      route.fulfill({
        status: 400,
        json: { error: "port 1081 on br0 is busy", field: "inbounds[0].port", tunnel: "a" },
      });
    await tunnels.inboundRows("a").first().getByRole("spinbutton", { name: "Port" }).fill("1083");
    await tunnels.save.click();
    await expect(tunnels.card("a").locator(".refusal")).toContainText("port 1081 on br0 is busy");
  });

  // Catches the phone layout hiding the column header with nothing else telling Login from Password.
  test("on a phone each cell carries its own visible label", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    const { tunnels } = await open(page, [saved({ user: "bob", password: "x" })], [], true);
    const row = tunnels.inboundRows("a").first();
    for (const name of ["Port", "Interface", "Node", "Login", "Password"]) {
      const cell = row.locator(".cell").filter({ has: page.getByLabel(name, { exact: true }) });
      await expect(cell.locator(".lab")).toBeVisible();
      await expect(cell.locator(".lab")).toHaveText(name);
    }
  });

  // Catches the labels showing on a desktop row where the header already names the columns.
  test("on a desktop the cell labels stay hidden", async ({ page }) => {
    const { tunnels } = await open(page, [saved()]);
    await expect(tunnels.inboundRows("a").first().locator(".lab").first()).toBeHidden();
  });

  // Catches a long node label stretching the phone grid past the viewport.
  test("a long node name does not scroll the page sideways on a phone", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    const long = "N".repeat(120);
    const daemon = await stubDaemon(page, {
      nodes: [{ key: KEY, name: long, source: "Provider" }],
      tunnels: [tunnel("a", "tunvless0", { sources: [SUB], inbounds: [saved()] })],
      states: [state("a", "tunvless0")],
    });
    expect(daemon.nodes.length).toBe(1);
    const tunnels = new TunnelsPage(page);
    await tunnels.openOnPhone();
    await tunnels.expand("a");
    await expect(tunnels.inboundRows("a")).toHaveCount(1);
    await expect(tunnels.inboundRows("a").first()).toContainText("NNNN");
    const wide = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
    );
    expect(wide).toBe(false);
    const right = await page.evaluate(() =>
      Math.max(
        ...[...document.querySelectorAll("[data-inbound] .cell")].map(
          (el) => el.getBoundingClientRect().right,
        ),
      ),
    );
    expect(right).toBeLessThanOrEqual(360);
  });

  // Catches a daemon refusal naming inbounds[1].port that marks no field, or marks row 0.
  test("a refusal on inbounds[1].port marks that row's port only", async ({ page }) => {
    const { daemon, tunnels } = await open(page, [saved(), saved({ port: 1082 })]);
    daemon.putAnswer = (_body, route) =>
      route.fulfill({
        status: 400,
        json: { error: "port 1082 on br0 is busy", field: "inbounds[1].port", tunnel: "a" },
      });
    await tunnels.inboundRows("a").nth(1).getByRole("spinbutton", { name: "Port" }).fill("1083");
    await tunnels.save.click();
    await expect(tunnels.card("a").locator(".refusal")).toBeVisible();
    await expect(
      tunnels.inboundRows("a").nth(1).getByRole("spinbutton", { name: "Port" }),
    ).toHaveAttribute("aria-invalid", "true");
    await expect(
      tunnels.inboundRows("a").nth(0).getByRole("spinbutton", { name: "Port" }),
    ).toHaveAttribute("aria-invalid", "false");
  });

  // Catches a tunnel without the field breaking the section or saving without inbounds: [].
  test("a tunnel from a daemon that omits inbounds renders empty and saves []", async ({
    page,
  }) => {
    const bare = tunnel("a", "tunvless0", { sources: [SUB], description: "" });
    delete bare.inbounds;
    const daemon = await stubDaemon(page, {
      tunnels: [bare],
      states: [{ ...state("a", "tunvless0"), inbounds: undefined }],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    await expect(tunnels.card("a").getByRole("button", { name: "Add port" })).toBeVisible();
    await expect(tunnels.inboundRows("a")).toHaveCount(0);
    await tunnels.card("a").getByRole("textbox", { name: "Description" }).fill("x");
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].inbounds).toEqual([]);
  });

  for (const phone of [false, true]) {
    // Catches the login and password inputs overlapping or touching, which reads as one wide box.
    test(`login and password are separate inputs with a gap${phone ? " on a phone" : ""}`, async ({
      page,
    }) => {
      if (phone) await page.setViewportSize({ width: 360, height: 800 });
      const { tunnels } = await open(page, [saved({ user: "bob", password: "x" })], [], phone);
      const row = tunnels.inboundRows("a").first();
      const login = await row.getByRole("textbox", { name: "Login" }).boundingBox();
      const pass = await row.getByLabel("Password", { exact: true }).boundingBox();
      expect(login).not.toBeNull();
      expect(pass).not.toBeNull();
      expect(pass!.x - (login!.x + login!.width)).toBeGreaterThanOrEqual(4);
    });
  }

  // Catches the phone pairs sitting at different heights, or the trash falling onto a line of its own.
  test("on a phone Port and Interface share a baseline and the trash sits with the eye", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    const { tunnels } = await open(page, [saved({ user: "bob", password: "x" })], [], true);
    const row = tunnels.inboundRows("a").first();
    const top = async (name: string) =>
      (await row
        .locator(".cell")
        .filter({ has: page.getByLabel(name, { exact: true }) })
        .locator(".lab")
        .boundingBox())!.y;
    expect(Math.abs((await top("Port")) - (await top("Interface")))).toBeLessThanOrEqual(1);
    const eye = (await row.getByRole("button", { name: "Show the password" }).boundingBox())!;
    const bin = (await row.getByRole("button", { name: "Delete" }).boundingBox())!;
    expect(Math.abs(eye.y + eye.height / 2 - (bin.y + bin.height / 2))).toBeLessThanOrEqual(8);
  });

  // Catches the interface select touching the port input on a desktop row.
  test("the port and interface cells keep a gap on a desktop", async ({ page }) => {
    const { tunnels } = await open(page, [saved()]);
    const row = tunnels.inboundRows("a").first();
    const port = (await row.getByRole("spinbutton", { name: "Port" }).boundingBox())!;
    const iface = (await row.locator(".cell").nth(1).boundingBox())!;
    expect(iface.x - (port.x + port.width)).toBeGreaterThanOrEqual(4);
  });

  // Catches the column headers drifting off their inputs because the header grid sizes differently from the rows.
  test("on a desktop the Login and Password headers sit over their inputs", async ({ page }) => {
    const { tunnels } = await open(page, [saved({ user: "bob", password: "x" })]);
    const card = tunnels.card("a");
    const row = tunnels.inboundRows("a").first();
    for (const [name, field] of [
      ["Login", row.getByRole("textbox", { name: "Login" })],
      ["Password", row.getByLabel("Password", { exact: true })],
    ] as const) {
      const head = (await card
        .locator(".head > span", { hasText: new RegExp(`^${name}$`) })
        .boundingBox())!;
      const box = (await field.boundingBox())!;
      expect(Math.abs(head.x - box.x)).toBeLessThanOrEqual(1);
    }
  });

  // Catches a long interface name running its select into the Node column on a tablet.
  test("at 768 px the interface select keeps clear of the node select", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 900 });
    const daemon = await stubDaemon(page, {
      link: ["br0"],
      interfaces: ["wg0", "br0"],
      names: { br0: "Home network" },
      tunnels: [tunnel("a", "tunvless0", { sources: [SUB], inbounds: [saved({ listen: "br0" })] })],
      states: [state("a", "tunvless0")],
    });
    expect(daemon.link).toEqual(["br0"]);
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    const row = tunnels.inboundRows("a").first();
    await expect(row.locator(".cell").nth(1)).toContainText("Home network");
    const iface = (await row
      .locator(".cell")
      .nth(1)
      .locator("[data-select-trigger]")
      .boundingBox())!;
    const node = (await row
      .locator(".cell")
      .nth(2)
      .locator("[data-select-trigger]")
      .boundingBox())!;
    expect(node.x - (iface.x + iface.width)).toBeGreaterThanOrEqual(4);
  });

  // Catches a "·" separator left dangling at the end of a wrapped head line on a phone.
  test("on a phone the head line never ends a line with a separator", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    const live = [
      { port: 1080, state: "up", why: "", rxBps: 4800, txBps: 1200 },
      { port: 1081, state: "up", why: "", rxBps: 4800, txBps: 1200 },
    ];
    const daemon = await stubDaemon(page, {
      tunnels: [
        tunnel("a", "tunvless0", {
          sources: [SUB],
          inbounds: [saved({ port: 1080 }), saved({ port: 1081 })],
        }),
      ],
      states: [state("a", "tunvless0", { inbounds: live, rxBps: 9600, txBps: 2400 })],
    });
    expect(daemon.states.length).toBe(1);
    const tunnels = new TunnelsPage(page);
    await tunnels.openOnPhone();
    const line = tunnels.card("a").locator(".head .line");
    await expect(line).toContainText(":1081");
    const dangling = await line.evaluate((root) => {
      const clip = (root.parentElement ?? root).getBoundingClientRect();
      const all = [...root.querySelectorAll("*")].filter((el) => el.children.length === 0);
      const rects = all.map((el) => ({ el, r: el.getBoundingClientRect() }));
      return rects
        .filter(({ el, r }) => el.textContent?.trim() === "·" && r.left >= clip.left)
        .filter(
          ({ el, r }) =>
            !rects.some(
              (o) =>
                o.el !== el &&
                o.el.textContent?.trim() !== "·" &&
                o.r.width > 0 &&
                Math.abs(o.r.top + o.r.height / 2 - (r.top + r.height / 2)) <= 4 &&
                o.r.left >= r.right - 1,
            ),
        ).length;
    });
    expect(dangling).toBe(0);
  });
});
