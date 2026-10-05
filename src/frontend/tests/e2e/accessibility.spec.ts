import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Accessibility", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);
    await signedIn(page);
    await page.route("**/groups?with_rules=true", async (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.route("**/interfaces", async (route) => route.fulfill({ json: { interfaces: [] } }));
    await groupsPage.goto();
  });

  // Icon-only controls once had no aria-label, title or text, so a screen reader announced nothing.
  test("every icon-only control has an accessible name", async ({ page }) => {
    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll("button, a[href]")]
        .filter((el) => {
          const label = el.getAttribute("aria-label") || el.getAttribute("title") || "";
          return !label.trim() && !(el.textContent || "").trim();
        })
        .map((el) => {
          const path = [];
          for (let n: Element | null = el; n && n !== document.body; n = n.parentElement) {
            path.unshift(
              n.tagName.toLowerCase() +
                (n.className ? "." + String(n.className).split(" ")[0] : ""),
            );
          }
          return path.join(" > ");
        }),
    );
    expect(unnamed).toEqual([]);
  });

  // The tooltip once fired on pointer hover only, so a keyboard user never saw it.
  test("the tooltip appears on focus and is a tooltip", async ({ page }) => {
    await page.locator("[data-value] button").first().focus();
    const bubble = page.locator("#global-tooltip");
    await expect(bubble).toBeVisible();
    await expect(bubble).toHaveAttribute("role", "tooltip");
  });

  test("should focus group name on creation", async ({ page }) => {
    await groupsPage.createGroup();

    const groupNameInput = page.locator(".group-wrapper").first().locator("input.group-name");
    await expect(groupNameInput).toBeFocused();
  });

  test("should tab through group controls", async ({ page }) => {
    await groupsPage.createGroup();
    const groupNameInput = page.locator(".group-wrapper").first().locator("input.group-name");

    await groupNameInput.focus();

    await page.keyboard.press("Tab");
    const interfaceTrigger = page
      .locator(".group-wrapper")
      .first()
      .locator("[data-select-trigger]")
      .first();
    await expect(interfaceTrigger).toBeFocused();

    await page.keyboard.press("Tab");
    const switchBtn = page.locator(".group-wrapper").first().locator(".enable-group");
    await expect(switchBtn).toBeFocused();

    await page.keyboard.press("Tab");
    const deleteBtn = page
      .locator(".group-wrapper")
      .first()
      .locator(".group-actions button")
      .nth(2);
    await expect(deleteBtn).toBeFocused();
  });
});
