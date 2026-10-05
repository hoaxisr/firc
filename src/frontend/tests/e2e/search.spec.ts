import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Groups Search", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);

    await signedIn(page);

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "1",
              name: "Group Alpha",
              rules: [],
              enable: true,
              interface: "",
            },
            {
              id: "2",
              name: "Group Beta",
              rules: [],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await page.route("**/interfaces", async (route) => {
      await route.fulfill({ json: { interfaces: [] } });
    });

    await groupsPage.goto();
  });

  test("should filter groups by name", async ({ page }) => {
    await expect(page.locator(".group-wrapper")).toHaveCount(2);

    await groupsPage.search("Alpha");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(1);

    await expect(page.locator(".group-wrapper:visible input.group-name")).toHaveValue(
      "Group Alpha",
    );

    await groupsPage.search("Beta");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(1);
    await expect(page.locator(".group-wrapper:visible input.group-name")).toHaveValue("Group Beta");
  });

  test("should clear search results when cleared", async ({ page }) => {
    await groupsPage.search("Alpha");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(1);

    await groupsPage.search("");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(2);
  });

  test("searches the pattern, never a name the payload carries", async ({ page }) => {
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "1",
              name: "Group A",
              rules: [
                { id: "12345671", name: "Alpha Rule", rule: "a", type: "namespace", enable: true },
                { id: "12345672", rule: "alpha.example.com", type: "namespace", enable: true },
              ],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();

    await expect(page.locator(".rule")).toHaveCount(2);

    await groupsPage.search("Alpha");
    await expect(page.locator(".rule")).toHaveCount(1);
    await expect(page.locator(".rule .pattern input").first()).toHaveValue("alpha.example.com");
  });

  test("should filter rules by pattern", async ({ page }) => {
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "1",
              name: "Group A",
              rules: [
                {
                  id: "12345671",
                  name: "Google",
                  rule: "google.com",
                  type: "domain",
                  enable: true,
                },
                {
                  id: "12345672",
                  name: "Local",
                  rule: "192.168.1.1",
                  type: "subnet",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();

    await groupsPage.search("192");
    await expect(page.locator(".rule")).toHaveCount(1);
    await expect(page.locator(".rule .pattern input").first()).toHaveValue("192.168.1.1");

    await groupsPage.search("google");
    await expect(page.locator(".rule")).toHaveCount(1);
    await expect(page.locator(".rule .pattern input").first()).toHaveValue("google.com");
  });

  test("should highlight matched text in group name and pattern", async ({ page }) => {
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "g-highlight",
              name: "Zeta Group",
              rules: [
                {
                  id: "r-other",
                  rule: "first.example.com",
                  type: "domain",
                  enable: true,
                },
                {
                  id: "r-pattern",
                  rule: "needle.example.com",
                  type: "domain",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();

    const group = page.locator(".group-wrapper").first();
    const groupNameOverlay = group.locator(".group-name-field .group-name-search-overlay");

    await groupsPage.search("zeta");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(1);
    await expect(groupNameOverlay.locator("mark")).toHaveCount(1);
    await expect(groupNameOverlay.locator("mark").first()).toHaveText("Zeta");
    await expect(group.locator(".rule .search-highlight-overlay mark")).toHaveCount(0);

    await groupsPage.search("needle");
    await expect(group.locator(".rule")).toHaveCount(1);
    const patternMatchedRule = group.locator('.rule[data-uuid="r-pattern"]');
    await expect(patternMatchedRule.locator(".pattern .search-highlight-overlay mark")).toHaveCount(
      1,
    );
    await expect(
      patternMatchedRule.locator(".pattern .search-highlight-overlay mark").first(),
    ).toHaveText("needle");
    await expect(groupNameOverlay.locator("mark")).toHaveCount(0);
  });
});
