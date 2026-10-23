import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const IFACES = [
  { id: "blackhole" },
  { id: "block" },
  { id: "nwg0", name: "WARP", role: "tunnel" },
  { id: "ppp0", name: "Broadband", role: "wan" },
  { id: "ppp1", name: "Broadband connection of the second provider", role: "wan" },
];

const NONE = {
  source: "none",
  servers: [],
  health: { window: 600, total: 0, fallbacks: 0, last: 0, reason: "", resting: false, since: 0 },
};

const group = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  interface: "nwg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  resolver: NONE,
  live: true,
  ...extra,
});

async function setup(page: Page, groups: Record<string, unknown>[]) {
  const daemon = { groups, puts: [] as any[] };
  await signedIn(page);
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: IFACES } }));
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      daemon.groups = body.groups.map((g: any) => ({ ...g, resolver: NONE, live: true }));
      await route.fulfill({ json: { groups: daemon.groups } });
      return;
    }
    const withRules = request.url().includes("with_rules=true");
    await route.fulfill({
      json: {
        groups: daemon.groups.map(({ rules, ...g }: any) => (withRules ? { ...g, rules } : g)),
      },
    });
  });
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(groups.length);
  return { daemon, groupsPage: new GroupsPage(page) };
}

const card = (page: Page, n = 0) => page.locator(".group").nth(n);
const answer = (page: Page, n = 0) => card(page, n).locator(".block-answer");
const badge = (page: Page, n = 0) => card(page, n).locator(".resolver-badge");
const editor = (page: Page) => page.locator(".block-answer-editor");
const choice = (page: Page, code: string) =>
  editor(page).getByRole("radio", { name: new RegExp(`^${code}`) });

test.describe("A group blocked by DNS", () => {
  // Catches the entry missing, the card not reading it, the answer not shown under it, or the badge left on the resolver.
  test("choosing Block by DNS shows 0.0.0.0 under it and the blocking badge", async ({ page }) => {
    await setup(page, [group("0a000001", "Ads")]);
    await expect(badge(page)).toHaveText("DNS: common upstream");
    await expect(answer(page)).toHaveCount(0);
    await card(page).locator(".iface-select [data-select-trigger]").click();
    await page.locator('[data-select-item][data-value="block"]').click();
    const trigger = card(page).locator(".iface-select [data-select-trigger]");
    await expect(trigger.locator(".selected-value")).toHaveText("Block by DNS");
    await expect(trigger.locator(".selected-description")).toHaveCount(0);
    await expect(answer(page)).toHaveText("0.0.0.0");
    await expect(badge(page)).toHaveText("DNS: blocking · 0.0.0.0");
    await expect(badge(page)).toHaveClass(/blocked/);
  });

  // Catches the popover not changing the card, the badge, or the PUT, or a group moved off block still sending its answer.
  test("the answer popover switches to NXDOMAIN and Save sends it", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [
      group("0a000001", "Ads", { interface: "block", block: "null" }),
      group("0a000002", "Trackers", { interface: "block", block: "refused" }),
    ]);
    await expect(answer(page, 1)).toHaveText("REFUSED");
    await answer(page).click();
    await expect(editor(page)).toContainText("What to answer for the group's names");
    await expect(choice(page, "0.0.0.0")).toHaveAttribute("aria-checked", "true");
    await choice(page, "NXDOMAIN").click();
    await expect(answer(page)).toHaveText("NXDOMAIN");
    await expect(badge(page)).toHaveText("DNS: blocking · NXDOMAIN");
    await page.keyboard.press("Escape");
    await expect(editor(page)).toHaveCount(0);

    await card(page, 1).locator(".iface-select [data-select-trigger]").click();
    await page.locator('[data-select-item][data-value="nwg0"]').click();
    await expect(answer(page, 1)).toHaveCount(0);

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const [ads, trackers] = daemon.puts[0].groups;
    expect(ads.interface).toBe("block");
    expect(ads.block).toBe("nxdomain");
    expect(trackers.interface).toBe("nwg0");
    expect("block" in trackers).toBe(false);
  });

  // Catches the REFUSED warning missing, or drawn in the plain hint colour like the others.
  test("REFUSED shows its warning in orange", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
    await setup(page, [group("0a000001", "Ads", { interface: "block", block: "refused" })]);
    await expect(badge(page)).toHaveText("DNS: блокировка · REFUSED");
    await answer(page).click();
    await expect(editor(page)).toContainText("Чем отвечать на имена группы");
    const warning = choice(page, "REFUSED").locator(".block-answer-hint");
    await expect(warning).toHaveText(
      "Android и браузеры со своим DoH могут спросить другой DNS и обойти блокировку",
    );
    await expect(warning).toHaveCSS("color", "rgb(253, 151, 31)");
    const plain = choice(page, "NXDOMAIN").locator(".block-answer-hint");
    await expect(plain).toHaveText("«такого имени нет»");
    await expect(plain).not.toHaveCSS("color", "rgb(253, 151, 31)");
    await expect(choice(page, "0.0.0.0")).toContainText(
      "адрес-заглушка: соединение не начнётся, повторов нет",
    );
  });

  // Catches a block group shown as not working, warned about its DNS, or told its traffic goes through "block".
  test("a block group shows no live warning", async ({ page }) => {
    await setup(page, [group("0a000001", "Ads", { interface: "block", block: "nxdomain" })]);
    const status = card(page).locator(".live-status");
    await expect(status).toHaveAttribute("data-kind", "live");
    await expect(card(page).locator(".health-badge")).toHaveCount(0);
    await expect(card(page).locator(".iface-amber")).toHaveCount(0);
    await status.hover();
    const tip = page.getByRole("tooltip");
    await expect(tip).toContainText("The daemon answers the group's names itself");
    await expect(tip).not.toContainText("goes through block");
  });

  // Catches the dialog's DNS row offering a choice for a block group, or saying the blackhole's words.
  test("the group dialog says the daemon answers a block group's names", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "Ads", { interface: "block", block: "nxdomain" }),
    ]);
    await groupsPage.openGroupSettings(0);
    const dns = page.getByRole("dialog").locator("#gd-dns");
    await expect(dns).toContainText("the daemon answers the group's names");
    await expect(dns).not.toContainText("blackhole");
    await expect(dns.locator(".dns-select")).toHaveClass(/disabled/);
  });

  // Catches an answer-only change not counted as an edit, so Save stays off or sends the old answer.
  test("changing only the answer enables Save and sends it", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [
      group("0a000001", "Ads", { interface: "block", block: "nxdomain" }),
    ]);
    await expect(groupsPage.saveButton).toHaveClass(/inactive/);
    await answer(page).click();
    await choice(page, "REFUSED").click();
    await page.keyboard.press("Escape");
    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);
    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].block).toBe("refused");
    expect(daemon.puts[0].groups[0].interface).toBe("block");
  });

  // Catches the blocking badge filled red instead of the plain badge in red, the code hidden under the open picker, or a trigger with no visible keyboard focus.
  test("the badge is red text, and the answer stays in sight and takes focus", async ({ page }) => {
    await setup(page, [
      group("0a000001", "YouTube"),
      group("0a000002", "Ads", { interface: "block", block: "null" }),
    ]);
    const plainBg = await badge(page, 0).evaluate((el) => getComputedStyle(el).backgroundColor);
    await expect(badge(page, 1)).toHaveCSS("background-color", plainBg);
    await expect(badge(page, 1)).toHaveCSS("color", "rgb(248, 81, 73)");

    await card(page, 1).locator(".iface-select [data-select-trigger]").click();
    const content = page.locator("[data-select-content]");
    await expect(content).toBeVisible();
    const [code, menu] = [await answer(page, 1).boundingBox(), await content.boundingBox()];
    expect(menu!.y).toBeGreaterThanOrEqual(code!.y + code!.height);
    await page.keyboard.press("Escape");
    await expect(content).toHaveCount(0);

    await answer(page, 1).focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab");
    await expect(answer(page, 1)).toBeFocused();
    await expect(answer(page, 1)).not.toHaveCSS("outline-style", "none");
  });

  // Catches a long interface name spilling over the badges or the switch instead of ending in an ellipsis, or Block by DNS cut short or unclickable.
  test("a long interface name stays in its column; Block by DNS is shown whole", async ({
    page,
  }) => {
    await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
    await page.setViewportSize({ width: 800, height: 700 });
    await setup(page, [
      group("0a000001", "Работа и учёба", { interface: "ppp1" }),
      group("0a000002", "Реклама и трекеры", { interface: "block", block: "null" }),
    ]);
    for (const n of [0, 1]) {
      const trigger = card(page, n).locator(".iface-select [data-select-trigger]");
      const badges = await card(page, n).locator(".group-badges").boundingBox();
      const badgeEnd = await card(page, n)
        .locator(".resolver-badge")
        .evaluate((el) => el.getBoundingClientRect().right);
      const box = await trigger.boundingBox();
      expect(box!.x, `card ${n}`).toBeGreaterThanOrEqual(badgeEnd);
      expect(badges).not.toBeNull();
    }
    const long = card(page, 0).locator(".selected-value");
    expect(await long.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
    const block = card(page, 1).locator(".selected-value");
    await expect(block).toHaveText("Блокировать по DNS");
    expect(await block.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
    await card(page, 1)
      .locator(".iface-select [data-select-trigger]")
      .click({ position: { x: 4, y: 6 } });
    await expect(page.locator("[data-select-content]")).toBeVisible();
    await page.keyboard.press("Escape");

    await page.setViewportSize({ width: 360, height: 700 });
    for (const n of [0, 1]) {
      const label = await card(page, n)
        .locator(".iface-select [data-select-trigger]")
        .evaluate((el) => el.getBoundingClientRect().right);
      const toggle = await card(page, n)
        .locator(".enable-group")
        .evaluate((el) => el.getBoundingClientRect().left);
      expect(label, `phone card ${n}`).toBeLessThanOrEqual(toggle);
    }
    expect(await long.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
    expect(await block.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  });
});
