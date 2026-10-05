import { expect, test, type Locator, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const IFACES = ["eth0", "wlan0", "wg0", "wg1", "wg2", "wg3"];

async function setup(page: Page) {
  await signedIn(page);
  await page.route("**/system/interfaces", (route) =>
    route.fulfill({ json: { interfaces: IFACES.map((id) => ({ id, name: id })) } }),
  );
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({
      json: {
        groups: [{ id: "aaaaaaaa", name: "g", interface: "eth0", enable: true, rules: [] }],
      },
    }),
  );
  await new GroupsPage(page).goto();
}

async function clickAtCentre(page: Page, item: Locator) {
  const box = await item.boundingBox();
  if (!box) throw new Error("item has no box");
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}

test.describe("Select list placement", () => {
  test("a collapsed group's interface list is clickable below the card edge", async ({ page }) => {
    await setup(page);
    const card = page.locator(".group-wrapper-inner").first();
    const trigger = page.locator(".iface-select [data-select-trigger]").first();
    await expect(trigger).toContainText("eth0");
    await trigger.click();

    const item = page.locator('[data-select-item][data-value="wg2"]');
    await expect(item).toBeVisible();
    const cardBox = await card.boundingBox();
    const itemBox = await item.boundingBox();
    expect(itemBox!.y).toBeGreaterThan(cardBox!.y + cardBox!.height);

    await clickAtCentre(page, item);
    await expect(trigger).toContainText("wg2");
  });

  test("a select inside the group dialog is clickable above the overlay", async ({ page }) => {
    await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    const trigger = dialog.locator("[data-select-trigger]").first();
    await trigger.click();

    const item = page.locator('[data-select-item][data-value="wg1"]');
    await expect(item).toBeVisible();
    const box = await item.boundingBox();
    const top = await page.evaluate(
      ([x, y]) =>
        document.elementFromPoint(x, y)?.closest("[data-select-item]")?.getAttribute("data-value"),
      [box!.x + box!.width / 2, box!.y + box!.height / 2],
    );
    expect(top).toBe("wg1");

    await clickAtCentre(page, item);
    await expect(trigger).toContainText("wg1");
  });
});
