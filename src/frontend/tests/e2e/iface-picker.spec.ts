import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const IFACES = [
  { id: "blackhole" },
  { id: "block" },
  { id: "eth2.1", role: "other" },
  { id: "br0", name: "Home network", role: "lan" },
  { id: "nwg0", name: "WARP", role: "tunnel" },
  { id: "ppp0", name: "Broadband", ndmsName: "PPPoE0", role: "wan" },
  { id: "nwg2", ndmsName: "Wireguard2", role: "tunnel" },
  { id: "tunvless0", name: "VLESS tunnel", role: "tunnel" },
];

const group = (id: string, name: string, iface: string) => ({
  id,
  name,
  interface: iface,
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  live: true,
});

async function setup(page: Page, groups: Record<string, unknown>[], locale = "ru") {
  await signedIn(page);
  await page.addInitScript(
    (l) => localStorage.setItem("locale", JSON.stringify({ value: l })),
    locale,
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: IFACES } }));
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/groups(\?.*)?$/, (route) => route.fulfill({ json: { groups } }));
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(groups.length);
}

const shown = (page: Page) =>
  page
    .locator("[data-select-content] [data-select-item]")
    .evaluateAll((els) => els.map((el) => el.getAttribute("data-value")));

async function openPicker(page: Page, n = 0) {
  await page.locator(".group .iface-select [data-select-trigger]").nth(n).click();
  await expect(page.locator("[data-select-content]")).toBeVisible();
}

// Catches a non-tunnel among the first rows, the block row missing or not red, or the rest shown before it is asked for.
test("a group on a tunnel sees the tunnels, Block and a folded rest", async ({ page }) => {
  await setup(page, [group("0a000001", "YouTube", "nwg0")]);
  const trigger = page.locator(".group .iface-select [data-select-trigger]").first();
  await expect(trigger.locator(".selected-value")).toHaveText("WARP");
  await expect(trigger.locator(".selected-description")).toHaveText("nwg0");
  await openPicker(page);
  expect(await shown(page)).toEqual([
    "nwg0",
    "nwg2",
    "tunvless0",
    "blackhole",
    "block",
    "__more__",
  ]);
  const block = page.locator('[data-select-item][data-value="blackhole"]');
  await expect(block).toHaveText(/Блокировать/);
  await expect(block.locator(".option-label")).toHaveClass(/danger/);
  await expect(page.locator('[data-select-item][data-value="nwg2"]')).toContainText("Wireguard2");
  const more = page.getByRole("option", { name: "Ещё 3 интерфейса" });
  await expect(more).toHaveAttribute("aria-expanded", "false");
  await more.click();
  expect(await shown(page)).toEqual([
    "nwg0",
    "nwg2",
    "tunvless0",
    "blackhole",
    "block",
    "__more__",
    "ppp0",
    "br0",
    "eth2.1",
  ]);
  await expect(page.locator('[data-select-item][data-value="ppp0"]')).toContainText("провайдер");
  await expect(page.locator('[data-select-item][data-value="br0"]')).not.toContainText("провайдер");
  await page.locator('[data-select-item][data-value="br0"]').click();
  await expect(trigger.locator(".selected-value")).toHaveText("Home network");
});

// Catches either hint missing or swapped, Block by DNS above the blackhole, or the hint repeated in the closed picker.
test("Block and Block by DNS each say what they do", async ({ page }) => {
  await setup(page, [group("0a000001", "YouTube", "nwg0"), group("0a000002", "Ads", "block")]);
  const second = page.locator(".group .iface-select [data-select-trigger]").nth(1);
  await expect(second.locator(".selected-value")).toHaveText("Блокировать по DNS");
  await expect(second.locator(".selected-description")).toHaveCount(0);
  await openPicker(page);
  const blackhole = page.locator('[data-select-item][data-value="blackhole"]');
  const block = page.locator('[data-select-item][data-value="block"]');
  await expect(blackhole.locator(".option-label")).toHaveText("Блокировать");
  await expect(blackhole.locator(".option-subline")).toHaveText(
    "вести в никуда: соединения отвергаются",
  );
  await expect(blackhole.locator(".option-subline")).toBeVisible();
  await expect(block.locator(".option-label")).toHaveText("Блокировать по DNS");
  await expect(block.locator(".option-subline")).toHaveText(
    "ответить на имена сами, никуда не вести",
  );
  await expect(block.locator(".option-subline")).toBeVisible();
  await expect(block.locator(".option-label")).toHaveCSS("color", "rgb(253, 151, 31)");
  const [b1, b2] = [await blackhole.boundingBox(), await block.boundingBox()];
  expect(b2!.y).toBeGreaterThan(b1!.y);
});

// Catches the fold unreachable or unopenable from the keyboard, Enter on it choosing it, or a row under it out of reach.
test("the keyboard opens the fold and picks a row under it", async ({ page }) => {
  await setup(page, [group("0a000001", "YouTube", "nwg0")]);
  const trigger = page.locator(".group .iface-select [data-select-trigger]").first();
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("[data-select-content]")).toBeVisible();
  const more = page.getByRole("option", { name: "Ещё 3 интерфейса" });
  for (let i = 0; i < 6; i++) {
    if ((await more.getAttribute("data-highlighted")) !== null) break;
    await page.keyboard.press("ArrowDown");
  }
  await expect(more).toHaveAttribute("data-highlighted", "");
  await page.keyboard.press("Enter");
  await expect(more).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("[data-select-content]")).toBeVisible();
  await expect(trigger.locator(".selected-value")).toHaveText("WARP");
  await page.keyboard.press("ArrowDown");
  await expect(page.locator('[data-select-item][data-value="ppp0"]')).toHaveAttribute(
    "data-highlighted",
    "",
  );
  await page.keyboard.press("Enter");
  await expect(page.locator("[data-select-content]")).toHaveCount(0);
  await expect(trigger.locator(".selected-value")).toHaveText("Broadband");
});

// Catches the rest folded away while the group's own interface is in it.
test("a group on a non-tunnel interface opens with the rest shown", async ({ page }) => {
  await setup(page, [group("0a000002", "Banks", "ppp0")]);
  await openPicker(page);
  expect(await shown(page)).toContain("ppp0");
  await expect(page.getByRole("option", { name: "Ещё 3 интерфейса" })).toHaveAttribute(
    "aria-expanded",
    "true",
  );
});

// Catches the open list spilling past a phone's screen.
test("the open list fits a 390 px phone", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page, [group("0a000001", "YouTube", "nwg0")]);
  await openPicker(page);
  await page.getByRole("option", { name: "Ещё 3 интерфейса" }).click();
  const box = await page.locator("[data-select-content]").boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
});

// Catches the bulk menu listing every interface flat, its rest unreachable, or left open for the next opening.
test("the bulk interface menu folds the rest the same way", async ({ page }) => {
  await setup(page, [group("0a000001", "YouTube", "nwg0")], "en");
  await page.getByRole("button", { name: "Select group YouTube", exact: true }).click();
  await page
    .getByRole("region", { name: "Selected groups" })
    .getByRole("button", { name: "Interface" })
    .click();
  const menu = page.getByRole("menuitem");
  await expect(menu).toHaveText([
    /WARP\s*nwg0/,
    /Wireguard2\s*nwg2/,
    /VLESS tunnel\s*tunvless0/,
    "Block",
    /3 more interfaces/,
  ]);
  await menu.filter({ hasText: "3 more interfaces" }).click();
  await expect(menu.filter({ hasText: "Broadband" })).toContainText("provider");
  await expect(menu).toHaveCount(8);
  await page.keyboard.press("Escape");
  await page
    .getByRole("region", { name: "Selected groups" })
    .getByRole("button", { name: "Interface" })
    .click();
  await expect(menu).toHaveCount(5);
});
