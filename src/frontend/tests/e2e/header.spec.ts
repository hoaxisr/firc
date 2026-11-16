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

  // Catches a phone menu that hides which page is open, cannot be dismissed by a tap outside, or leaves its backdrop behind.
  test("on a phone the menu names the page and a tap outside closes it", async ({ page }) => {
    await page.setViewportSize({ width: 400, height: 760 });
    const button = page.locator(".mobile-dropdown-btn");
    await expect(page.locator(".mobile-title")).toHaveText("Groups");
    await button.click();
    await expect(button).toHaveAttribute("aria-expanded", "true");
    await page.mouse.click(380, 700);
    await expect(button).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".menu-backdrop")).toHaveCount(0);
    await button.click();
    await page.getByRole("tab", { name: "Journal" }).click();
    await expect(page.locator(".mobile-title")).toHaveText("Journal");
    await expect(button).toHaveAttribute("aria-expanded", "false");
  });

  // Catches a long version drawn over the Russian nav tabs, or the dev badge back next to it.
  for (const width of [1290, 1024]) {
    test(`a long version stays clear of the nav tabs at ${width} px`, async ({ page }) => {
      await page.evaluate(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
      await page.setViewportSize({ width, height: 600 });
      await page.reload();
      await expect(page.getByRole("tab").last()).toHaveText("Настройки");
      await expect(page.getByText("dev", { exact: true })).toHaveCount(0);
      const version = page.locator(".version .version-text");
      await version.evaluate(
        (el) => (el.textContent = "0.3.1~git20261016154241.805abcd (805abcd)"),
      );
      const v = await version.boundingBox();
      const tab = await page.getByRole("tab").last().boundingBox();
      expect(v && tab).toBeTruthy();
      const apart = v!.x >= tab!.x + tab!.width || v!.x + v!.width <= tab!.x;
      expect(apart).toBe(true);
      expect(v!.width).toBeGreaterThan(0);
    });
  }

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
    await expect(dialog.getByRole("link", { name: "https://firc.hoaxisr.ru" })).toHaveAttribute(
      "href",
      "https://firc.hoaxisr.ru",
    );
    await expect(dialog.locator("text=API")).toBeVisible();
    await expect(
      dialog.getByRole("link", {
        name: "https://github.com/hoaxisr/firc/blob/main/docs/swagger.yaml",
      }),
    ).toHaveAttribute("href", "https://github.com/hoaxisr/firc/blob/main/docs/swagger.yaml");

    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  });

  for (const width of [360, 390]) {
    test(`the version reads whole beside the Russian Settings title at ${width} px`, async ({
      page,
    }) => {
      // Catches the version squeezed to an ellipsis by the longest phone title.
      await page.evaluate(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
      await page.setViewportSize({ width, height: 760 });
      await page.goto("/settings");
      await expect(page.locator(".mobile-title")).toHaveText("Настройки");
      const version = page.locator(".version .version-text");
      await expect(version).toBeVisible();
      const fit = await version.evaluate((el) => el.scrollWidth <= el.clientWidth);
      expect(fit).toBe(true);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        width,
      );
    });

    test(`the version and About buttons are big enough to tap at ${width} px`, async ({ page }) => {
      // Catches header buttons shrunk below a 32 px tap target on a phone.
      await page.setViewportSize({ width, height: 760 });
      for (const selector of [".version-button", ".info button"]) {
        const box = (await page.locator(selector).boundingBox())!;
        expect(box.width, selector).toBeGreaterThanOrEqual(32);
        expect(box.height, selector).toBeGreaterThanOrEqual(32);
      }
    });

    test(`the shortcuts button is hidden alike at ${width} px`, async ({ page }) => {
      // Catches the shortcuts button shown on one phone width and hidden on another.
      await page.setViewportSize({ width, height: 760 });
      await expect(page.locator(".keys button")).toHaveCount(1);
      await expect(page.locator(".keys button")).toBeHidden();
    });

    test(`the page keeps a gutter from the screen edge at ${width} px`, async ({ page }) => {
      // Catches the header and the page bar drawn a few pixels from the edge of a phone.
      await page.setViewportSize({ width, height: 760 });
      const nav = (await page.locator("nav").boundingBox())!;
      const article = (await page.locator("article").boundingBox())!;
      expect(nav.x).toBeGreaterThanOrEqual(8);
      expect(article.x).toBeGreaterThanOrEqual(8);
      expect(width - (article.x + article.width)).toBeGreaterThanOrEqual(8);
    });
  }

  // Catches a page title on a phone that does not open the menu when tapped.
  test("a tap on the page title opens the phone menu", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 760 });
    await page.locator(".mobile-title").click();
    await expect(page.locator(".mobile-dropdown-btn")).toHaveAttribute("aria-expanded", "true");
  });

  // Catches a phone menu that ignores Escape.
  test("Escape closes the phone menu", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 760 });
    const button = page.locator(".mobile-dropdown-btn");
    await button.click();
    await expect(button).toHaveAttribute("aria-expanded", "true");
    await page.keyboard.press("Escape");
    await expect(button).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".menu-backdrop")).toHaveCount(0);
  });

  // Catches the update popover or the About dialog opened over a menu left open under it.
  for (const [name, selector, opened] of [
    ["update popover", ".version-button", ".update-popover"],
    ["About dialog", ".info button", "[data-dialog-content]"],
  ]) {
    test(`opening the ${name} closes the phone menu`, async ({ page }) => {
      await page.setViewportSize({ width: 360, height: 760 });
      const button = page.locator(".mobile-dropdown-btn");
      await button.click();
      await expect(button).toHaveAttribute("aria-expanded", "true");
      await page.locator(selector).click();
      await expect(page.locator(opened)).toBeVisible();
      await expect(button).toHaveAttribute("aria-expanded", "false");
      await expect(page.locator(".tabs-panel")).toBeHidden();
    });
  }
});
