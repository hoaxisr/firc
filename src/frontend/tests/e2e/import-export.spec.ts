import fs from "fs";
import path from "path";
import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Import/Export", () => {
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

  test("should export config", async ({ page }) => {
    await groupsPage.createGroup();

    const downloadPromise = page.waitForEvent("download");
    await page.locator(".group-controls-actions button").nth(2).click();

    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("config.firc");
  });

  test("should import config", async ({ page }) => {
    const configData = {
      groups: [
        {
          id: "12345678",
          name: "Imported Group",
          rules: [],
          enable: true,
          interface: "",
        },
      ],
    };
    const testDir = "tests/e2e/fixtures";
    if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });
    const filePath = path.join(testDir, "config.firc");
    fs.writeFileSync(filePath, JSON.stringify(configData));

    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.locator(".group-controls-actions button").nth(1).click();

    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles(filePath);

    await expect(page.getByRole("dialog")).toBeVisible();

    await expect(page.getByText("Imported Group")).toBeVisible();

    await page.getByRole("button", { name: "All", exact: true }).click();

    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: "Import" }).click();

    await expect(page.locator(".group-wrapper")).toHaveCount(1);
    await expect(page.locator("input.group-name")).toHaveValue("Imported Group");
  });
});
