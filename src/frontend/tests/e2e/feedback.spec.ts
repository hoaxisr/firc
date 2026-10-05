import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Feedback Components", () => {
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

  test("should show toast on success", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);

    await page.route("**/groups?save=true", async (route) => {
      await route.fulfill({ status: 200, json: {} });
    });

    await groupsPage.setGroupName(0, "G");
    await groupsPage.setRulePattern(0, 0, "p");

    await groupsPage.save();

    const toast = page.getByText("Saved");
    await expect(toast).toBeVisible();
  });

  test("should show overlay on loading", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setGroupName(0, "G");
    await groupsPage.setRulePattern(0, 0, "p");

    await page.route("**/groups?save=true", async (route) => {
      await page.waitForTimeout(500);
      await route.fulfill({ status: 200, json: {} });
    });

    const savePromise = groupsPage.save();

    const overlay = page.locator(".overlay");
    await expect(overlay).toBeVisible();

    await savePromise;

    await expect(overlay).toBeHidden();
  });
});
