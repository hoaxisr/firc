import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const PAGE_SIZE = 50;

function rules(badIndex: number, badType = "subnet") {
  return Array.from({ length: PAGE_SIZE + 20 }, (_, i) => ({
    id: `7000${i.toString().padStart(4, "0")}`,
    name: `Rule ${i}`,
    rule: i === badIndex ? "not-an-address.example.com" : `host-${i}.example.com`,
    type: i === badIndex ? badType : "namespace",
    enable: true,
  }));
}

async function setup(page: Page, badIndex: number, badType = "subnet") {
  await signedIn(page);
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/subscriptions", (route) => route.fulfill({ json: { subscriptions: [] } }));
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({
      json: {
        groups: [
          {
            id: "g-paged",
            name: "Paged Group",
            rules: rules(badIndex, badType),
            enable: true,
            interface: "",
          },
        ],
      },
    }),
  );
  await page.goto("/");
  await page.locator(".group-wrapper").first().waitFor();
}

test.describe("Rule validity across pagination", () => {
  test("a rule that cannot work on a later page still blocks Save", async ({ page }) => {
    await setup(page, PAGE_SIZE + 5);

    const name = page.locator(".group-header input.group-name").first();
    await name.fill("Renamed");
    await name.blur();

    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  // Catches an unknown rule type passing because only types with a validator were checked.
  test("a type the daemon does not know blocks Save", async ({ page }) => {
    await setup(page, 0, "keyword");

    const name = page.locator(".group-header input.group-name").first();
    await name.fill("Renamed");
    await name.blur();

    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  test("...and a group whose rules all work saves", async ({ page }) => {
    await setup(page, -1);

    const name = page.locator(".group-header input.group-name").first();
    await name.fill("Renamed");
    await name.blur();

    await expect(page.locator("#save-changes")).not.toHaveClass(/inactive/);
  });
});
