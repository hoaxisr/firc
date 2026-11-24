import { expect, test, type Page } from "@playwright/test";

import { answerConfirm } from "./pages/confirm";
import { centerOf, dragTo, frame, glide, hover, mousePointer, pick } from "./pages/drag";
import { signedIn } from "./pages/session";

const group = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  interface: "wg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [
    { id: `r${id}`, enable: true, rule: `${name.toLowerCase()}.example.com`, type: "domain" },
  ],
  live: true,
  ...extra,
});

const NAMES = ["Speedtest", "Unavailable", "Insta", "Telegram", "Work"];

const LIST = {
  id: "0a0a0a0a",
  url: "https://services.should.be.blocked.com",
  interval: 86400,
  lastUpdate: 1790000000,
  rulesTotal: 2,
  sync: { state: "idle", error: "", lastCheck: 1790000000 },
};
const LIST_ONLY = "zz-listonly";

async function setup(page: Page, extra: Record<string, Record<string, unknown>> = {}) {
  const daemon = { puts: [] as any[], listSearchDelayMs: 0 };
  const groups = NAMES.map((name, i) =>
    group(`0b00000${i + 1}`, name, {
      ...(name === "Unavailable" ? { lists: [LIST] } : {}),
      ...extra[name],
    }),
  );

  await signedIn(page);
  await page.route("**/system/interfaces", (route) =>
    route.fulfill({
      json: {
        interfaces: [
          { id: "nwg0", name: "vdsina", role: "tunnel" },
          { id: "nwg1", ndmsName: "Wireguard1", role: "tunnel" },
          { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
        ],
      },
    }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) =>
    route.fulfill({ json: { ok: true, error: "", since: 0 } }),
  );
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/groups\/[^/]+\/lists\/[^/]+\/rules/, async (route) => {
    const q = new URL(route.request().url()).searchParams.get("q") ?? "";
    if (q) await new Promise((resolve) => setTimeout(resolve, daemon.listSearchDelayMs));
    const matched = !q ? 2 : q.includes(LIST_ONLY) ? 1 : 0;
    await route.fulfill({ json: { total: 2, matched, offset: 0, rules: [] } });
  });
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      await route.fulfill({
        json: { groups: body.groups.map((g: any) => ({ ...g, live: true })) },
      });
      return;
    }
    await route.fulfill({ json: { groups } });
  });
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(NAMES.length);
  return daemon;
}

const bar = (page: Page) => page.getByRole("region", { name: "Selected groups" });
const numberOf = (page: Page, name: string) =>
  page.getByRole("button", { name: `Select group ${name}`, exact: true });
const selectedNumberOf = (page: Page, name: string) =>
  page.getByRole("button", { name: `Deselect group ${name}`, exact: true });
const cardNames = (page: Page) =>
  page
    .locator("input.group-name")
    .evaluateAll((inputs) => inputs.map((i) => (i as HTMLInputElement).value));
const card = (page: Page, index: number) => page.locator(".group").nth(index);

test.describe("Group bulk actions", () => {
  // Catches a number that is not a real toggle, or a bar shown with nothing selected.
  test("a click or a key on the number selects, and the bar follows", async ({ page }) => {
    await setup(page);
    await expect(bar(page)).toHaveCount(0);

    await numberOf(page, "Unavailable").click();
    await expect(selectedNumberOf(page, "Unavailable")).toHaveAttribute("aria-pressed", "true");
    await expect(card(page, 1)).toHaveClass(/\bselected\b/);
    await expect(bar(page)).toBeVisible();
    await expect(bar(page).getByRole("status")).toHaveText("1 group selected");

    await numberOf(page, "Insta").focus();
    await page.keyboard.press("Enter");
    await numberOf(page, "Work").focus();
    await page.keyboard.press("Space");
    await expect(bar(page).getByRole("status")).toHaveText("3 groups selected");
    await expect(numberOf(page, "Speedtest")).toHaveAttribute("aria-pressed", "false");
    await expect(card(page, 0)).not.toHaveClass(/\bselected\b/);

    await selectedNumberOf(page, "Work").press("Enter");
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");

    await bar(page).getByRole("button", { name: "Clear selection" }).click();
    await expect(bar(page)).toHaveCount(0);
    await expect(page.locator(".group.selected")).toHaveCount(0);
  });

  // Catches a lost line, a non-domain rule, a disabled rule or a duplicate in the copy.
  test("copy domains puts the selected groups' domains on the clipboard, one per line", async ({
    page,
    context,
  }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await setup(page, {
      Insta: {
        rules: [
          { id: "ri1", enable: true, rule: "aaa.com", type: "namespace" },
          { id: "ri2", enable: true, rule: "^ads\\.", type: "regex" },
          { id: "ri3", enable: true, rule: "*.ccc.com", type: "wildcard" },
        ],
      },
      Work: {
        rules: [
          { id: "rw1", enable: true, rule: "bbb.com", type: "domain" },
          { id: "rw2", enable: true, rule: "10.0.0.0/8", type: "subnet" },
          { id: "rw3", enable: true, rule: "aaa.com", type: "domain" },
          { id: "rw4", enable: false, rule: "off.com", type: "domain" },
        ],
      },
    });
    await numberOf(page, "Insta").click();
    await numberOf(page, "Work").click();
    await bar(page).getByRole("button", { name: "Copy domains" }).click();
    await expect(page.getByText("3 domains copied")).toBeVisible();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied.replace(/\r\n/g, "\n")).toBe("aaa.com\n*.ccc.com\nbbb.com\n");
  });

  // Catches a copy that fails where the Clipboard API is refused, as on plain http.
  test("copy domains falls back when the Clipboard API refuses", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.addInitScript(() => {
      navigator.clipboard.writeText = () => Promise.reject(new Error("refused"));
    });
    await setup(page, {
      Insta: { rules: [{ id: "ri1", enable: true, rule: "aaa.com", type: "domain" }] },
    });
    await numberOf(page, "Insta").click();
    await bar(page).getByRole("button", { name: "Copy domains" }).click();
    await expect(page.getByText("1 domain copied")).toBeVisible();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied.replace(/\r\n/g, "\n")).toBe("aaa.com\n");
  });

  // Catches a silent no-op on a selection without domains.
  test("copy domains says so when the selection has none", async ({ page }) => {
    await setup(page, {
      Insta: { rules: [{ id: "ri1", enable: true, rule: "10.0.0.0/8", type: "subnet" }] },
    });
    await numberOf(page, "Insta").click();
    await bar(page).getByRole("button", { name: "Copy domains" }).click();
    await expect(page.getByText("No domains in the selected groups")).toBeVisible();
  });

  // Catches the wrong Russian plural form in the count.
  test("the count reads in Russian", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
    await setup(page);
    await page.getByRole("button", { name: "Выбрать группу Insta", exact: true }).click();
    const region = page.getByRole("region", { name: "Выбранные группы" });
    await expect(region.getByRole("status")).toHaveText("1 выбрана");
    await region.getByRole("button", { name: "Выбрать все" }).click();
    await expect(region.getByRole("status")).toHaveText("5 выбрано");
  });

  // Catches the bar growing wider than the page's column on a wide screen.
  for (const locale of ["en", "ru"]) {
    test(`the bar stays inside the content column at 1440 (${locale})`, async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 800 });
      await page.addInitScript(
        (value) => localStorage.setItem("locale", JSON.stringify({ value })),
        locale,
      );
      await setup(page);
      await page.locator(".group .place-number").nth(1).click();
      await expect(page.locator(".bulk-bar")).toBeVisible();
      const m = await page.evaluate(() => {
        const bar = document.querySelector(".bulk-bar")!.getBoundingClientRect();
        const column = document.querySelector(".group-list")!.getBoundingClientRect();
        return { bar: [bar.left, bar.right], column: [column.left, column.right] };
      });
      expect(m.bar[0]).toBeGreaterThanOrEqual(m.column[0] - 0.5);
      expect(m.bar[1]).toBeLessThanOrEqual(m.column[1] + 0.5);
    });
  }

  // Catches a bar whose buttons overlap, leave the bar or the window, or cut their labels at some width.
  for (const locale of ["en", "ru"]) {
    test(`the bar fits at every width (${locale})`, async ({ page }) => {
      test.setTimeout(60_000);
      await page.addInitScript(
        (value) => localStorage.setItem("locale", JSON.stringify({ value })),
        locale,
      );
      await setup(page);
      await page.locator(".group .place-number").nth(1).click();
      await page.locator(".group .place-number").nth(2).click();
      await expect(page.locator(".bulk-bar")).toBeVisible();
      const widths = [
        320, 360, 375, 390, 414, 480, 540, 600, 601, 640, 700, 768, 800, 834, 900, 960, 961, 963,
        1000, 1024, 1100, 1150, 1180, 1280, 1366, 1440, 1600, 1920,
      ];
      const faults: string[] = [];
      for (const width of widths) {
        await page.setViewportSize({ width, height: 800 });
        await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => done(null))));
        const found = await page.evaluate(() => {
          const out: string[] = [];
          const bar = document.querySelector(".bulk-bar")!.getBoundingClientRect();
          if (bar.left < 0 || bar.right > window.innerWidth) out.push("bar leaves the window");
          const parts = [
            ...document.querySelectorAll(".bulk-bar .bulk-count, .bulk-bar .bulk-button"),
          ];
          const boxes = parts.map((el) => ({ el, r: el.getBoundingClientRect() }));
          for (const { el, r } of boxes) {
            const name = el.textContent!.trim() || el.getAttribute("aria-label");
            if (r.left < bar.left - 0.5 || r.right > bar.right + 0.5 || r.bottom > bar.bottom + 0.5)
              out.push(`${name} leaves the bar`);
            for (const label of el.querySelectorAll<HTMLElement>(".bulk-label")) {
              if (label.offsetWidth > 0 && label.scrollWidth > label.clientWidth + 1)
                out.push(`${name} is cut`);
            }
          }
          for (let i = 0; i < boxes.length; i++) {
            for (let j = i + 1; j < boxes.length; j++) {
              const a = boxes[i].r;
              const b = boxes[j].r;
              const w = Math.min(a.right, b.right) - Math.max(a.left, b.left);
              const h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
              if (w > 0.5 && h > 0.5)
                out.push(
                  `${boxes[i].el.textContent!.trim()} overlaps ${boxes[j].el.textContent!.trim()}`,
                );
            }
          }
          return out;
        });
        faults.push(...found.map((f) => `${width}px: ${f}`));
      }
      expect(faults).toEqual([]);
    });
  }

  // Catches Ctrl or Shift click missing a part of the header, a range that is not inclusive, or a click that selects text.
  test("Ctrl+click toggles on any part of the header, Shift+click takes the range", async ({
    page,
  }) => {
    await setup(page);
    await card(page, 0)
      .locator("input.group-name")
      .click({ modifiers: ["Control"] });
    await card(page, 2)
      .locator(".group-header")
      .click({ modifiers: ["Control"], position: { x: 300, y: 4 } });
    await card(page, 4)
      .locator(".group-header")
      .click({ modifiers: ["Shift"], position: { x: 300, y: 4 } });
    await expect(page.locator(".group.selected")).toHaveCount(3);
    for (const i of [2, 3, 4]) await expect(card(page, i)).toHaveClass(/\bselected\b/);
    await expect(card(page, 0)).not.toHaveClass(/\bselected\b/);
    await card(page, 0)
      .locator("input.group-name")
      .click({ modifiers: ["Control", "Shift"] });
    await expect(bar(page).getByRole("status")).toHaveText("5 groups selected");
    expect(await page.evaluate(() => getSelection()?.toString())).toBe("");
  });

  // Catches a modified click reaching the switch, the interface menu, the grip or the collapse button.
  test("a modified click on a header control selects and leaves the control alone", async ({
    page,
  }) => {
    await setup(page);
    const names = await cardNames(page);
    const toggle = card(page, 3).locator("button.enable-group");
    const before = await toggle.getAttribute("aria-checked");
    await toggle.click({ modifiers: ["Control"] });
    await expect(card(page, 3)).toHaveClass(/\bselected\b/);
    await expect(toggle).toHaveAttribute("aria-checked", before!);

    const select = card(page, 4).locator(".iface-select [data-select-trigger]");
    await select.click({ modifiers: ["Control"] });
    await expect(card(page, 4)).toHaveClass(/\bselected\b/);
    await expect(select).toHaveAttribute("data-state", "closed");

    const trigger = card(page, 3).locator("[data-collapsible-trigger]");
    const open = await trigger.getAttribute("data-state");
    await trigger.click({ modifiers: ["Control"] });
    await expect(trigger).toHaveAttribute("data-state", open!);
    await expect(card(page, 3)).not.toHaveClass(/\bselected\b/);

    await card(page, 0)
      .locator(".group-grip")
      .click({ modifiers: ["Shift"] });
    await expect(page.locator(".group.selected")).toHaveCount(4);
    await expect(card(page, 4)).not.toHaveClass(/\bselected\b/);
    await expect(bar(page).getByRole("status")).toHaveText("4 groups selected");
    expect(await cardNames(page)).toEqual(names);
  });

  // Catches a Shift press on the grip starting a drag instead of selecting.
  test("a Shift press and move on the grip neither drags nor reorders", async ({ page }) => {
    await setup(page);
    const names = await cardNames(page);
    const pointer = mousePointer(page);
    await page.keyboard.down("Shift");
    await pick(page, pointer, card(page, 0).locator(".group-grip"));
    await glide(page, pointer, await centerOf(card(page, 2).locator(".group-header")));
    await expect(page.locator(".dnd-chip")).toHaveCount(0);
    await pointer.up();
    await page.keyboard.up("Shift");
    await frame(page);
    expect(await cardNames(page)).toEqual(names);
  });

  // Catches a Shift+Space on the switch or collapse button being taken as a selection click.
  test("a modified keyboard activation is left to the control", async ({ page }) => {
    await setup(page);
    const toggle = card(page, 3).locator("button.enable-group");
    const before = await toggle.getAttribute("aria-checked");
    await toggle.focus();
    await page.keyboard.press("Shift+Space");
    await expect(toggle).not.toHaveAttribute("aria-checked", before!);
    await expect(card(page, 3)).not.toHaveClass(/\bselected\b/);

    const trigger = card(page, 3).locator("[data-collapsible-trigger]");
    const open = await trigger.getAttribute("data-state");
    await trigger.focus();
    await page.keyboard.press("Shift+Enter");
    await expect(trigger).not.toHaveAttribute("data-state", open!);
    await expect(card(page, 3)).not.toHaveClass(/\bselected\b/);

    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Work").focus();
    await page.keyboard.press("Shift+Enter");
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");
    await expect(card(page, 4)).toHaveClass(/\bselected\b/);
    await expect(card(page, 2)).not.toHaveClass(/\bselected\b/);
  });

  // Catches a range running over groups a search hides.
  test("Shift+click ranges over the groups a search shows", async ({ page }) => {
    await setup(page);
    await card(page, 0)
      .locator("input.group-name")
      .click({ modifiers: ["Control"] });
    await page.locator(".search-container").click();
    await page.locator(".search-input").fill("t");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(3);
    await card(page, 3)
      .locator(".group-header")
      .click({ modifiers: ["Shift"], position: { x: 300, y: 4 } });
    await expect(page.locator(".group.selected")).toHaveCount(3);
    await page.locator(".search-input").fill("");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(5);
    await expect(card(page, 1)).not.toHaveClass(/\bselected\b/);
    expect(
      await page
        .locator(".group.selected input.group-name")
        .evaluateAll((l) => l.map((i) => (i as HTMLInputElement).value)),
    ).toEqual(["Speedtest", "Insta", "Telegram"]);
  });

  // Catches Select all ignoring the search, or selecting fewer than all without one.
  test("select all takes every group, or only the ones a search shows", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();
    await bar(page).getByRole("button", { name: "Select all" }).click();
    await expect(bar(page).getByRole("status")).toHaveText("5 groups selected");
    await bar(page).getByRole("button", { name: "Clear selection" }).click();

    await page.locator(".search-container").click();
    await page.locator(".search-input").fill("te");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(2);
    await numberOf(page, "Telegram").click();
    await bar(page).getByRole("button", { name: "Select all" }).click();
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");
    await page.locator(".search-input").fill("");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(5);
    expect(
      await page
        .locator(".group.selected input.group-name")
        .evaluateAll((l) => l.map((i) => (i as HTMLInputElement).value)),
    ).toEqual(["Speedtest", "Telegram"]);
  });

  // Catches the interface reaching an unselected group, missing a selected one, or going out before Save.
  test("the interface menu sets every selected group's interface, sent on Save", async ({
    page,
  }) => {
    const daemon = await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByRole("menuitem")).toHaveText([
      /vdsina\s*nwg0/,
      /Wireguard1\s*nwg1/,
      /WireGuard Interface\s*wg0/,
    ]);
    await menu.getByRole("menuitem", { name: /nwg1/ }).click();
    await expect(menu).toHaveCount(0);

    const shown = await page
      .locator(".iface-select .selected-description")
      .evaluateAll((els) => els.map((e) => e.textContent?.trim()));
    expect(shown).toEqual(["nwg1", "wg0", "nwg1", "wg0", "wg0"]);
    expect(daemon.puts).toHaveLength(0);
    await expect(page.locator("#save-changes")).toBeEnabled();

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups.map((g: any) => g.interface)).toEqual([
      "nwg1",
      "wg0",
      "nwg1",
      "wg0",
      "wg0",
    ]);
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");
  });

  // Catches a circle that closes the menu, numbers out of order, or a chain missing a selected group.
  test("the interface menu builds a chain with backups for every selected group", async ({
    page,
  }) => {
    const daemon = await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.locator('[data-circle="wg0"]')).toHaveText("1");
    await menu.locator('[data-circle="nwg1"]').click();
    await expect(menu.locator('[data-circle="nwg1"]')).toHaveText("2");
    await expect(menu).toBeVisible();
    await menu.locator('[data-circle="nwg0"]').click();
    await expect(menu.locator('[data-circle="nwg0"]')).toHaveText("3");
    await page.keyboard.press("Escape");
    await expect(menu).toHaveCount(0);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups.map((g: any) => g.interface)).toEqual([
      ["wg0", "nwg1", "nwg0"],
      "wg0",
      ["wg0", "nwg1", "nwg0"],
      "wg0",
      "wg0",
    ]);
  });

  // Catches an empty circle drawn only on the hovered or highlighted menu row.
  test("an empty circle shows on a menu row nobody points at", async ({ page }) => {
    await setup(page, { Insta: { interface: ["nwg0", "wg0"] } });
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();
    await bar(page).getByRole("button", { name: "Interface" }).click();
    const last = page.getByRole("menu").locator('[data-circle="nwg1"]');
    await expect(last).toHaveCSS("border-top-color", "rgb(106, 109, 133)");
  });

  // Catches circles numbered from one group's chain when the selected chains differ.
  test("with different chains the circles start empty", async ({ page }) => {
    const daemon = await setup(page, { Insta: { interface: ["nwg0", "wg0"] } });
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByText("The groups have different interfaces")).toBeVisible();
    await expect(menu.locator("[data-circle]")).toHaveText(["", "", ""]);
    await menu.locator('[data-circle="nwg1"]').click();
    await expect(menu.locator('[data-circle="nwg1"]')).toHaveText("1");
    await page.keyboard.press("Escape");

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.interface]));
    expect(sent.Speedtest).toBe("nwg1");
    expect(sent.Insta).toBe("nwg1");
  });

  // Catches Shift+Enter selecting the row and closing the menu instead of adding a backup.
  test("Shift+Enter adds the highlighted interface as a backup", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await page.keyboard.press("ArrowDown");
    await expect(menu.getByRole("menuitem", { name: /nwg0/ })).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Shift+Enter");
    await expect(menu).toBeVisible();
    await expect(menu.locator('[data-circle="nwg1"]')).toHaveText("2");
    await page.keyboard.press("Escape");

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.interface]));
    expect(sent.Speedtest).toEqual(["wg0", "nwg1"]);
    expect(sent.Insta).toEqual(["wg0", "nwg1"]);
  });

  // Catches Shift+Enter on a Block row selecting it and closing the menu, or a circle on a Block row.
  test("Shift+Enter on Block by DNS does nothing and the Block rows have no circle", async ({
    page,
  }) => {
    await setup(page);
    await page.route("**/system/interfaces", (route) =>
      route.fulfill({
        json: {
          interfaces: [
            { id: "nwg0", name: "vdsina", role: "tunnel" },
            { id: "blackhole" },
            { id: "block" },
          ],
        },
      }),
    );
    await page.reload();
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.locator('[data-circle="nwg0"]')).toHaveCount(1);
    await expect(
      menu.getByRole("menuitem", { name: "Block" }).locator("[data-circle]"),
    ).toHaveCount(0);
    const dns = menu.getByRole("menuitem", { name: "Block by DNS" });
    await expect(dns.locator("[data-circle]")).toHaveCount(0);
    await dns.hover();
    await expect(dns).toBeFocused();
    await page.keyboard.press("Shift+Enter");
    await expect(menu).toBeVisible();
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  // Catches Shift+Enter on a row that cannot join a full chain replacing the chain and closing the menu.
  test("Shift+Enter on a fifth interface leaves a full chain alone", async ({ page }) => {
    const chain = ["wg0", "nwg1", "nwg0", "nwg2"];
    await setup(page, { Speedtest: { interface: chain }, Insta: { interface: chain } });
    await page.route("**/system/interfaces", (route) =>
      route.fulfill({
        json: {
          interfaces: [
            { id: "nwg0", name: "vdsina", role: "tunnel" },
            { id: "nwg1", ndmsName: "Wireguard1", role: "tunnel" },
            { id: "nwg2", ndmsName: "Wireguard2", role: "tunnel" },
            { id: "nwg3", ndmsName: "Wireguard3", role: "tunnel" },
            { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
          ],
        },
      }),
    );
    await page.reload();
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.locator('[data-circle="nwg2"]')).toHaveText("4");
    const fifth = menu.getByRole("menuitem", { name: /nwg3/ });
    await expect(fifth.locator("[data-circle]")).toHaveCount(0);
    await fifth.hover();
    await expect(fifth).toBeFocused();
    await page.keyboard.press("Shift+Enter");
    await expect(menu).toBeVisible();
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  // Catches the bulk menu folding More over a backup the selected groups share.
  test("a shared backup under More opens the menu with More expanded", async ({ page }) => {
    const chain = ["wg0", "ppp0"];
    await setup(page, { Speedtest: { interface: chain }, Insta: { interface: chain } });
    await page.route("**/system/interfaces", (route) =>
      route.fulfill({
        json: {
          interfaces: [
            { id: "nwg0", name: "vdsina", role: "tunnel" },
            { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
            { id: "ppp0", name: "Broadband", role: "wan" },
          ],
        },
      }),
    );
    await page.reload();
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByRole("menuitem", { name: "1 more interface" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    await expect(menu.locator('[data-circle="wg0"]')).toHaveText("1");
    await expect(menu.locator('[data-circle="ppp0"]')).toBeVisible();
    await expect(menu.locator('[data-circle="ppp0"]')).toHaveText("2");
  });

  // Catches a shared entry the router no longer lists missing from the menu, so it cannot be removed.
  test("a shared entry the router no longer lists shows and its circle removes it", async ({
    page,
  }) => {
    const chain = ["wg0", "nwg5"];
    const daemon = await setup(page, {
      Speedtest: { interface: chain },
      Insta: { interface: chain },
    });
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    const gone = menu.getByRole("menuitem", { name: /nwg5/ });
    await expect(gone).toContainText("not on the router");
    await expect(menu.locator('[data-circle="nwg5"]')).toHaveText("2");
    await menu.locator('[data-circle="nwg5"]').click();
    await expect(menu).toBeVisible();
    await expect(gone).toHaveCount(0);
    await expect(menu.locator('[data-circle="wg0"]')).toHaveText("1");
    await page.keyboard.press("Escape");

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.interface]));
    expect(sent.Speedtest).toBe("wg0");
    expect(sent.Insta).toBe("wg0");
  });

  // Catches the bulk menu offering no Block by DNS, or sending another interface than "block".
  test("the interface menu blocks the selected groups by DNS", async ({ page }) => {
    const daemon = await setup(page);
    await page.route("**/system/interfaces", (route) =>
      route.fulfill({
        json: {
          interfaces: [
            { id: "nwg0", name: "vdsina", role: "tunnel" },
            { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
            { id: "blackhole" },
            { id: "block" },
          ],
        },
      }),
    );
    await page.reload();
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByRole("menuitem")).toHaveText([
      /vdsina\s*nwg0/,
      /WireGuard Interface\s*wg0/,
      "Block",
      "Block by DNS",
    ]);
    await menu.getByRole("menuitem", { name: "Block by DNS" }).click();
    await expect(menu).toHaveCount(0);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.interface]));
    expect(sent.Speedtest).toBe("block");
    expect(sent.Insta).toBe("block");
    expect(Object.values(sent).filter((i) => i === "block")).toHaveLength(2);
  });

  // Catches the DNS menu changing a blocking group, missing a selected one, not saying which it skips, or open on blocking groups alone.
  test("the DNS menu sets every selected group's mode and skips blocking groups", async ({
    page,
  }) => {
    const daemon = await setup(page, { Work: { interface: "block" } });
    await numberOf(page, "Work").click();
    await expect(bar(page).getByRole("button", { name: "DNS" })).toBeDisabled();
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "DNS" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByText("1 group blocks, its DNS is unchanged")).toBeVisible();
    await expect(
      menu.getByRole("menuitemradio", { name: "Through the tunnel — automatic" }),
    ).toHaveAttribute("aria-checked", "true");
    await menu.getByRole("menuitemradio", { name: "Not through the tunnel" }).click();
    await expect(menu).toHaveCount(0);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.resolve]));
    expect(sent.Speedtest).toEqual({ tunnel: false, server: "" });
    expect(sent.Insta).toEqual({ tunnel: false, server: "" });
    expect(sent.Work).toEqual({ tunnel: true, server: "" });
    expect(sent.Telegram).toEqual({ tunnel: true, server: "" });
  });

  // Catches the pointer over the menu stealing the input's focus, an invalid server applied, or a valid one lost.
  test("own server is typed in the menu and checked before it applies", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "DNS" }).click();
    const menu = page.getByRole("menu");
    const own = menu.getByRole("menuitemradio", { name: "Through the tunnel — own server" });
    await own.click();
    await expect(menu).toBeVisible();
    await expect(own).toHaveAttribute("aria-checked", "true");
    const input = menu.getByLabel("Server");
    await expect(input).toBeFocused();

    for (const name of [
      "Through the tunnel — automatic",
      "Not through the tunnel",
      "Through the tunnel — own server",
    ]) {
      const box = await menu.getByRole("menuitemradio", { name }).boundingBox();
      await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2, { steps: 5 });
    }
    const box = await input.boundingBox();
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2, { steps: 5 });
    await expect(input).toBeFocused();

    await page.keyboard.type("1.1.1.1:0");
    await expect(input).toHaveValue("1.1.1.1:0");
    await expect(input).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(menu.getByText("The port must be between 1 and 65535")).toBeVisible();
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);

    await page.keyboard.press("End");
    await page.keyboard.press("Shift+Home");
    await page.keyboard.press("Backspace");
    await expect(input).toHaveValue("");
    await expect(input).toBeFocused();
    await page.keyboard.type("1.1.1.1");
    await page.keyboard.press("Enter");
    await expect(menu).toHaveCount(0);
    await expect(page.locator("#save-changes")).not.toHaveClass(/inactive/);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.resolve]));
    expect(sent.Speedtest).toEqual({ tunnel: true, server: "1.1.1.1" });
    expect(sent.Insta).toEqual({ tunnel: true, server: "1.1.1.1" });
    expect(sent.Work).toEqual({ tunnel: true, server: "" });
  });

  // Catches an outside click dropping a valid server typed in the menu.
  test("an outside click applies the server typed in the menu", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "DNS" }).click();
    const menu = page.getByRole("menu");
    await menu.getByRole("menuitemradio", { name: "Through the tunnel — own server" }).click();
    await expect(menu.getByLabel("Server")).toBeFocused();
    await page.keyboard.type("9.9.9.9");
    const outside = await bar(page).getByRole("status").boundingBox();
    await page.mouse.click(outside!.x + outside!.width / 2, outside!.y + outside!.height / 2);
    await expect(menu).toHaveCount(0);
    await expect(page.locator("#save-changes")).not.toHaveClass(/inactive/);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = Object.fromEntries(daemon.puts[0].groups.map((g: any) => [g.name, g.resolve]));
    expect(sent.Speedtest).toEqual({ tunnel: true, server: "9.9.9.9" });
    expect(sent.Insta).toEqual({ tunnel: true, server: "9.9.9.9" });
    expect(sent.Work).toEqual({ tunnel: true, server: "" });
  });

  // Catches Escape applying the typed server on its way out, or clearing the selection.
  test("Escape in the own-server input applies nothing and keeps the selection", async ({
    page,
  }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "DNS" }).click();
    const menu = page.getByRole("menu");
    await menu.getByRole("menuitemradio", { name: "Through the tunnel — own server" }).click();
    await expect(menu.getByLabel("Server")).toBeFocused();
    await page.keyboard.type("9.9.9.9");
    await page.keyboard.press("Escape");
    await expect(menu).toHaveCount(0);
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");
  });

  // Catches the own-server input starting empty when every selected group has the same server.
  test("the own-server input starts from the server the groups share", async ({ page }) => {
    const own = { resolve: { tunnel: true, server: "8.8.8.8, 1.1.1.1" } };
    await setup(page, { Speedtest: own, Insta: own });
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "DNS" }).click();
    const menu = page.getByRole("menu");
    await expect(
      menu.getByRole("menuitemradio", { name: "Through the tunnel — own server" }),
    ).toHaveAttribute("aria-checked", "true");
    await expect(menu.getByLabel("Server")).toHaveValue("8.8.8.8, 1.1.1.1");
  });

  // Catches enable/disable hitting the wrong groups or value, or never reaching Save.
  test("enable and disable the selected groups", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Unavailable").click();
    await numberOf(page, "Work").click();

    await bar(page).getByRole("button", { name: "Enable / disable" }).click();
    await page.getByRole("menuitem", { name: "Disable selected" }).click();
    const states = () =>
      page
        .locator(".enable-group")
        .evaluateAll((els) => els.map((e) => e.getAttribute("aria-checked")));
    await expect.poll(states).toEqual(["true", "false", "true", "true", "false"]);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups.map((g: any) => g.enable)).toEqual([
      true,
      false,
      true,
      true,
      false,
    ]);

    await bar(page).getByRole("button", { name: "Enable / disable" }).click();
    await page.getByRole("menuitem", { name: "Enable selected" }).click();
    await expect.poll(states).toEqual(["true", "true", "true", "true", "true"]);
  });

  // Catches a cancelled confirm deleting, a confirm without the count, or a per-group confirm after it.
  test("delete asks once with the count, and cancel keeps everything", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();
    await numberOf(page, "Telegram").click();

    await bar(page).getByRole("button", { name: "Delete" }).click();
    await expect(page.getByRole("alertdialog").locator("li")).toHaveText(["Insta", "Telegram"]);
    expect(await answerConfirm(page, false)).toBe("Delete the selected groups (2)?");
    expect(await cardNames(page)).toEqual(NAMES);
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");

    await bar(page).getByRole("button", { name: "Delete" }).click();
    await answerConfirm(page, true);
    await expect(page.locator(".group")).toHaveCount(3);
    expect(await cardNames(page)).toEqual(["Speedtest", "Unavailable", "Work"]);
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(bar(page)).toHaveCount(0);
    await expect(page.locator("#save-changes")).toBeEnabled();
  });

  // Catches Escape clearing the selection while a menu is open or the operator types.
  test("Escape clears the selection, but not from a menu or a field", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();

    await bar(page).getByRole("button", { name: "Interface" }).click();
    await expect(page.getByRole("menu")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    await expect(bar(page)).toBeVisible();

    await page.locator("input.group-name").first().focus();
    await page.keyboard.press("Escape");
    await expect(bar(page)).toBeVisible();

    await page.locator("input.group-name").first().blur();
    await page.keyboard.press("Escape");
    await expect(bar(page)).toHaveCount(0);
  });

  // Catches Ctrl+F left to the browser, or focusing without selecting the typed text.
  test("Ctrl+F focuses and selects the groups search", async ({ page }) => {
    await setup(page);
    const input = page.locator(".search-input");
    await page.locator(".search-container").click();
    await input.fill("tele");
    await page.locator("input.group-name").first().focus();

    await page.keyboard.press("Control+f");
    await expect(input).toBeFocused();
    const selection = await input.evaluate((el: HTMLInputElement) => [
      el.selectionStart,
      el.selectionEnd,
    ]);
    expect(selection).toEqual([0, 4]);
  });

  // Catches the number stealing the drag, or a reorder moving the selection onto another group.
  test("the grip still reorders with a selection, and the selection follows the group", async ({
    page,
  }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();

    await dragTo(
      page,
      card(page, 0).locator(".group-grip"),
      page.locator(".group-wrapper").nth(1),
      "after",
    );

    await expect
      .poll(() => cardNames(page))
      .toEqual(["Unavailable", "Speedtest", "Insta", "Telegram", "Work"]);
    await expect(card(page, 1)).toHaveClass(/\bselected\b/);
    await expect(card(page, 0)).not.toHaveClass(/\bselected\b/);
    await expect(selectedNumberOf(page, "Speedtest")).toHaveText("2");
  });

  // Catches a selected drag moving only the grabbed group.
  test("dragging a selected group moves every selected group together", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    const pointer = mousePointer(page);
    await pick(page, pointer, card(page, 2).locator(".group-grip"));
    await hover(page, pointer, page.locator(".group-wrapper").nth(4), "after");
    await expect(page.locator(".dnd-chip")).toHaveText(/^\s*2 groups\s*$/);
    await pointer.up();

    await expect
      .poll(() => cardNames(page))
      .toEqual(["Unavailable", "Telegram", "Work", "Speedtest", "Insta"]);
    await expect(selectedNumberOf(page, "Speedtest")).toBeVisible();
    await expect(selectedNumberOf(page, "Insta")).toBeVisible();
    await expect(page.locator(".group.selected")).toHaveCount(2);
  });

  // Catches only the grabbed card looking lifted while a selected drag moves several groups.
  test("every group in a selected drag looks lifted until the drop", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Insta").click();

    const pointer = mousePointer(page);
    await pick(page, pointer, card(page, 2).locator(".group-grip"));
    await hover(page, pointer, page.locator(".group-wrapper").nth(4), "after");
    await expect(card(page, 0)).toHaveClass(/\bdnd-origin\b/);
    await expect(card(page, 2)).toHaveClass(/\bdnd-origin\b/);
    await expect(card(page, 1)).not.toHaveClass(/\bdnd-origin\b/);
    await expect(card(page, 3)).not.toHaveClass(/\bdnd-origin\b/);
    await pointer.up();

    await expect(page.locator(".dnd-origin")).toHaveCount(0);
  });

  // Catches a drop on another selected group's edge doing nothing.
  test("dropping onto another selected group moves the block next to it", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Telegram").click();

    await dragTo(
      page,
      card(page, 3).locator(".group-grip"),
      page.locator(".group-wrapper").nth(0),
      "after",
    );

    await expect
      .poll(() => cardNames(page))
      .toEqual(["Speedtest", "Telegram", "Unavailable", "Insta", "Work"]);
    await expect(page.locator(".group.selected")).toHaveCount(2);
  });

  // Catches hidden selected groups travelling with the shown ones.
  test("with a search, only the shown selected groups move", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Speedtest").click();
    await numberOf(page, "Unavailable").click();
    await numberOf(page, "Insta").click();
    await page.locator(".search-container").click();
    await page.locator(".search-input").fill("t");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(3);

    await dragTo(
      page,
      card(page, 0).locator(".group-grip"),
      page.locator(".group-wrapper").nth(3),
      "after",
    );

    await page.locator(".search-input").fill("");
    await expect(page.locator(".group-wrapper:not(.is-hidden)")).toHaveCount(5);
    await expect
      .poll(() => cardNames(page))
      .toEqual(["Unavailable", "Telegram", "Speedtest", "Insta", "Work"]);
    await expect(selectedNumberOf(page, "Unavailable")).toBeVisible();
  });

  // Catches the bar covering the last card when the page is scrolled to the end.
  test("the bar leaves the last card uncovered", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 500 });
    await setup(page);
    await numberOf(page, "Insta").click();
    await expect(bar(page)).toBeVisible();
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    const last = await card(page, NAMES.length - 1).boundingBox();
    const barBox = await bar(page).boundingBox();
    expect(last!.y + last!.height).toBeLessThanOrEqual(barBox!.y);
  });

  // Catches a phone bar wider than the screen, a sideways page scroll, or a crowded row.
  test("on a phone the bar spans the screen in two rows without overflow", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
    await page.setViewportSize({ width: 420, height: 860 });
    await setup(page);
    await page.getByRole("button", { name: "Выбрать группу Insta", exact: true }).click();
    const region = page.getByRole("region", { name: "Выбранные группы" });
    const box = await region.boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(420);
    expect(box!.width).toBeGreaterThan(380);

    const toggle = region.getByRole("button", { name: "Вкл/выкл", exact: true });
    await expect(toggle.locator(".label-short")).toBeVisible();
    await expect(toggle.locator(".label-short")).toHaveText("Вкл/выкл");
    await expect(toggle.locator(".label-long")).toBeHidden();
    const selectAll = await region.getByRole("button", { name: "Выбрать все" }).boundingBox();
    const del = await region.getByRole("button", { name: "Удалить" }).boundingBox();
    expect(del!.y).toBeGreaterThan(selectAll!.y + selectAll!.height - 1);
    for (const name of ["Интерфейс", "Устройства", "DNS", "Вкл/выкл", "Удалить"]) {
      const b = await region.getByRole("button", { name }).boundingBox();
      expect(b!.x + b!.width, name).toBeLessThanOrEqual(box!.x + box!.width);
    }

    const squeezed = await region.evaluate((root) => [
      ...Array.from(root.querySelectorAll<HTMLElement>(".bulk-label"))
        .filter((l) => l.offsetParent && l.scrollWidth > l.clientWidth)
        .map((l) => l.textContent),
      ...Array.from(root.querySelectorAll("svg"))
        .filter((svg) => svg.getClientRects().length > 0 && svg.getBoundingClientRect().width < 15)
        .map(() => "icon"),
    ]);
    expect(squeezed).toEqual([]);

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
  });
  // Catches the Escape that closes a status tooltip also clearing the selection.
  test("Escape closes a status tooltip first, and only the next one clears", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();
    await card(page, 2).locator(".live-status").focus();
    await expect(page.getByRole("tooltip")).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(page.getByRole("tooltip")).toHaveCount(0);
    await expect(bar(page)).toBeVisible();
    await expect(selectedNumberOf(page, "Insta")).toHaveAttribute("aria-pressed", "true");

    await page.keyboard.press("Escape");
    await expect(bar(page)).toHaveCount(0);
  });

  // Catches Escape on another tab clearing the Groups selection.
  test("Escape on another tab leaves the selection alone", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();
    await page.getByRole("tab", { name: "Journal" }).click();
    await page.locator("body").focus();
    await page.keyboard.press("Escape");
    await page.getByRole("tab", { name: "Groups" }).click();
    await expect(bar(page).getByRole("status")).toHaveText("1 group selected");
  });

  // Catches focus falling to <body> when the bar goes away.
  test("focus goes to the first card when the bar goes away with it", async ({ page }) => {
    await setup(page);
    await numberOf(page, "Insta").click();
    await bar(page).getByRole("button", { name: "Clear selection" }).click();
    await expect(bar(page)).toHaveCount(0);
    await expect(numberOf(page, "Speedtest")).toBeFocused();

    await numberOf(page, "Speedtest").click();
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await answerConfirm(page, true);
    await expect(bar(page)).toHaveCount(0);
    await expect(numberOf(page, "Unavailable")).toBeFocused();
  });

  // Catches Save still sending a bulk-deleted group, or disturbing a remaining list group's list.
  test("a bulk delete then Save sends the rest, lists untouched", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Insta").click();
    await numberOf(page, "Telegram").click();
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await answerConfirm(page, true);
    await expect(page.locator(".group")).toHaveCount(3);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = daemon.puts[0].groups;
    expect(sent.map((g: any) => g.name)).toEqual(["Speedtest", "Unavailable", "Work"]);
    expect(sent[1].lists).toEqual([{ id: LIST.id, url: LIST.url, interval: LIST.interval }]);
    expect(sent.filter((g: any) => g.name !== "Unavailable").map((g: any) => g.lists)).toEqual([
      [],
      [],
    ]);
  });

  // Catches Select all, pressed mid-search, selecting from the previous query's cards.
  test("select all waits for the search it is pressed under", async ({ page }) => {
    const daemon = await setup(page);
    daemon.listSearchDelayMs = 700;
    await numberOf(page, "Insta").click();

    await page.locator(".search-container").click();
    await page.locator(".search-input").fill(LIST_ONLY);
    await bar(page).getByRole("button", { name: "Select all" }).click();

    await expect(bar(page).getByRole("status")).toHaveText("1 group selected");
    await expect(page.locator(".group.selected")).toHaveCount(1);
    await expect(selectedNumberOf(page, "Unavailable")).toBeVisible();
  });

  // Catches Ctrl+F focusing an input that stays zero-width.
  test("Ctrl+F opens a collapsed search field", async ({ page }) => {
    await setup(page);
    const wrapper = page.locator(".input-wrapper");
    expect((await wrapper.boundingBox())!.width).toBeLessThan(5);
    await page.mouse.click(5, 700);

    await page.keyboard.press("Control+f");
    await expect(page.locator(".search-input")).toBeFocused();
    await expect.poll(async () => (await wrapper.boundingBox())!.width).toBeGreaterThan(100);
  });
});
