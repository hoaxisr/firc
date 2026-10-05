import { expect, test, type Page } from "@playwright/test";

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
  url: "https://services.should.be.blocked.com",
  interval: 86400,
  lastUpdate: 1790000000,
  rulesTotal: 2,
  sync: { state: "idle", error: "", lastCheck: 1790000000 },
};
const LIST_ONLY = "zz-listonly";

async function setup(page: Page) {
  const daemon = { puts: [] as any[], listSearchDelayMs: 0 };
  const groups = NAMES.map((name, i) =>
    group(`0b00000${i + 1}`, name, name === "Unavailable" ? { list: LIST } : {}),
  );

  await signedIn(page);
  await page.route("**/system/interfaces", (route) =>
    route.fulfill({
      json: {
        interfaces: [
          { id: "nwg0", name: "vdsina" },
          { id: "nwg1", name: "Wireguard1" },
          { id: "wg0", name: "WireGuard Interface" },
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
  await page.route(/\/groups\/[^/]+\/list\/rules/, async (route) => {
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
      "nwg0 vdsina",
      "nwg1 Wireguard1",
      "wg0 WireGuard Interface",
    ]);
    await menu.getByRole("menuitem", { name: /^nwg1/ }).click();
    await expect(menu).toHaveCount(0);

    const shown = await page
      .locator(".iface-select .selected-value")
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

    const asked: string[] = [];
    page.once("dialog", (dialog) => {
      asked.push(dialog.message());
      void dialog.dismiss();
    });
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await expect.poll(() => asked).toEqual(["Delete the selected groups (2)?"]);
    expect(await cardNames(page)).toEqual(NAMES);
    await expect(bar(page).getByRole("status")).toHaveText("2 groups selected");

    page.on("dialog", (dialog) => {
      asked.push(dialog.message());
      void dialog.accept();
    });
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await expect(page.locator(".group")).toHaveCount(3);
    expect(await cardNames(page)).toEqual(["Speedtest", "Unavailable", "Work"]);
    expect(asked).toHaveLength(2);
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

    const source = card(page, 0).locator(".group-grip");
    const sourceBox = await source.boundingBox();
    if (!sourceBox) throw new Error("grip not found");
    await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2);
    await page.mouse.down();
    const slot = page.locator(".group-wrapper").nth(1).locator(".group-drop-slot--bottom");
    const slotBox = await slot.boundingBox();
    if (!slotBox) throw new Error("slot not found");
    await page.mouse.move(slotBox.x + slotBox.width / 2, slotBox.y + slotBox.height / 2, {
      steps: 10,
    });
    await page.mouse.up();

    await expect
      .poll(() => cardNames(page))
      .toEqual(["Unavailable", "Speedtest", "Insta", "Telegram", "Work"]);
    await expect(card(page, 1)).toHaveClass(/\bselected\b/);
    await expect(card(page, 0)).not.toHaveClass(/\bselected\b/);
    await expect(selectedNumberOf(page, "Speedtest")).toHaveText("2");
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
    for (const name of ["Интерфейс", "Вкл/выкл", "Удалить"]) {
      const b = await region.getByRole("button", { name }).boundingBox();
      expect(b!.x + b!.width, name).toBeLessThanOrEqual(box!.x + box!.width);
    }

    const squeezed = await region.evaluate((root) => [
      ...Array.from(root.querySelectorAll<HTMLElement>(".bulk-label"))
        .filter((l) => l.offsetParent && l.scrollWidth > l.clientWidth)
        .map((l) => l.textContent),
      ...Array.from(root.querySelectorAll("svg"))
        .filter((svg) => svg.getBoundingClientRect().width < 15)
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
    page.once("dialog", (dialog) => void dialog.accept());
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await expect(bar(page)).toHaveCount(0);
    await expect(numberOf(page, "Unavailable")).toBeFocused();
  });

  // Catches Save still sending a bulk-deleted group, or disturbing a remaining list group's list.
  test("a bulk delete then Save sends the rest, lists untouched", async ({ page }) => {
    const daemon = await setup(page);
    await numberOf(page, "Insta").click();
    await numberOf(page, "Telegram").click();
    page.once("dialog", (dialog) => void dialog.accept());
    await bar(page).getByRole("button", { name: "Delete" }).click();
    await expect(page.locator(".group")).toHaveCount(3);

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = daemon.puts[0].groups;
    expect(sent.map((g: any) => g.name)).toEqual(["Speedtest", "Unavailable", "Work"]);
    expect(sent[1].list).toEqual({ url: LIST.url, interval: LIST.interval });
    expect(sent.filter((g: any) => g.name !== "Unavailable").map((g: any) => g.list)).toEqual([
      null,
      null,
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
