import { expect, test } from "@playwright/test";

import { signedIn } from "./pages/session";

test.describe("Header Settings", () => {
  test.beforeEach(async ({ page }) => {
    await signedIn(page);
    await page.route("**/groups?with_rules=true", async (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.route("**/interfaces", async (route) => route.fulfill({ json: { interfaces: [] } }));
    await page.goto("/");
  });

  test("should display version", async ({ page }) => {
    const version = page.locator(".version .version-text");
    await expect(version).toBeVisible();
    expect(version.textContent.length).toBeGreaterThan(0);
  });

  test("should rotate locale", async ({ page }) => {
    const localeBtn = page.locator(".locale button");

    const initialText = await localeBtn.textContent();

    await localeBtn.click();

    await expect(localeBtn).not.toHaveText(initialText || "");

    await localeBtn.click();
  });

  test("should open info dialog", async ({ page }) => {
    const infoBtn = page.locator(".info button");
    await expect(infoBtn).toBeVisible();

    await infoBtn.click();

    const dialog = page.locator("[data-dialog-content]");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("About", { exact: true })).toBeVisible();

    await expect(dialog.locator("text=Repository")).toBeVisible();
    await expect(dialog.locator("text=Bug Tracker")).toBeVisible();
    await expect(dialog.locator('a[href="https://github.com/hoaxisr/firc"]')).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  });
});
