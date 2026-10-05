import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Drag and Drop", () => {
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

  test("should reorder groups", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.setGroupName(0, "Group A");

    await groupsPage.createGroup();
    await groupsPage.setGroupName(1, "Group B");

    await expect(
      groupsPage.page.locator(".group-wrapper").nth(0).locator("input.group-name"),
    ).toHaveValue("Group A");
    await expect(
      groupsPage.page.locator(".group-wrapper").nth(1).locator("input.group-name"),
    ).toHaveValue("Group B");

    const source = groupsPage.page.locator(".group-wrapper").nth(0).locator(".group-grip");

    const sourceBox = await source.boundingBox();

    if (!sourceBox) throw new Error("Source grip not found");

    await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2);
    await page.mouse.down();

    const targetGroup = groupsPage.page.locator(".group-wrapper").nth(1);
    const dropSlot = targetGroup.locator(".group-drop-slot--bottom");
    const targetBox = await dropSlot.boundingBox();

    if (!targetBox) throw new Error("Target slot not found");

    await page.mouse.move(targetBox.x + targetBox.width / 2, targetBox.y + targetBox.height / 2, {
      steps: 10,
    });
    await page.mouse.up();

    await expect(
      groupsPage.page.locator(".group-wrapper").nth(0).locator("input.group-name"),
    ).toHaveValue("Group B");
    await expect(
      groupsPage.page.locator(".group-wrapper").nth(1).locator("input.group-name"),
    ).toHaveValue("Group A");
  });

  test("should reorder rules", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "one.example.com");

    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "two.example.com");

    await expect(page.locator(".rule").nth(0).locator(".pattern-input")).toHaveValue(
      "two.example.com",
    );
    await expect(page.locator(".rule").nth(1).locator(".pattern-input")).toHaveValue(
      "one.example.com",
    );

    const source = page.locator(".rule").nth(0).locator(".grip");
    const target = page.locator(".rule").nth(1);

    const sourceBox = await source.boundingBox();
    const targetBox = await target.boundingBox();

    if (!sourceBox || !targetBox) throw new Error("Box not found");

    await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2);
    await page.mouse.down();

    await page.mouse.move(
      targetBox.x + targetBox.width / 2,
      targetBox.y + targetBox.height * 0.75,
      { steps: 10 },
    );
    await page.mouse.up();

    await expect(page.locator(".rule").nth(0).locator(".pattern-input")).toHaveValue(
      "one.example.com",
    );
    await expect(page.locator(".rule").nth(1).locator(".pattern-input")).toHaveValue(
      "two.example.com",
    );
  });
});
