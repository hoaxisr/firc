import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const LONG = "very-long-subdomain-name.another-long-label.example-company-international.com";

async function open(page: Page) {
  await signedIn(page);
  await page.route("**/interfaces", (r) => r.fulfill({ json: { interfaces: [{ id: "wg0" }] } }));
  await page.route("**/system/netfilter", (r) => r.fulfill({ json: { ok: true } }));
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const g = {
      id: "0a000001",
      name: "Meta",
      interface: "wg0",
      enable: true,
      devices: { allow: [], deny: [] },
      resolve: { tunnel: true, server: "" },
      rules: [
        { id: "0b000001", type: "domain", rule: LONG, enable: true },
        { id: "0b000002", type: "domain", rule: "a.com", enable: true },
      ],
      live: true,
    };
    const { rules, ...rest } = g;
    const withRules = route.request().url().includes("with_rules=true");
    await route.fulfill({ json: { groups: [withRules ? g : rest] } });
  });
  const groups = new GroupsPage(page);
  await groups.goto();
  await groups.expandGroup(0);
}

test.describe("a rule's text on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true });

  // catches a long pattern cut mid-glyph with no ellipsis and no full text to read
  test("a long pattern ends in an ellipsis and carries its full text", async ({ page }) => {
    await open(page);
    const input = page.locator(".pattern-input").first();
    const style = await input.evaluate((e) => getComputedStyle(e).textOverflow);
    expect(style).toBe("ellipsis");
    await expect(input).toHaveAttribute("title", LONG);
    const short = page.locator(".pattern-input").nth(1);
    await expect(short).toHaveAttribute("title", "a.com");
  });
});
