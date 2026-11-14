import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const NAMES = ["Telegram", "Twitter", "WhatsApp Business и звонки"];

async function open(page: Page) {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", async (route) => {
    await route.fulfill({
      json: {
        groups: NAMES.map((name, i) => ({
          id: `aaaaaaa${i}`,
          name,
          interface: "eth0",
          enable: true,
          rules: [],
        })),
      },
    });
  });
  await page.route("**/interfaces", async (route) => {
    await route.fulfill({ json: { interfaces: ["eth0"] } });
  });
  await new GroupsPage(page).goto();
  await expect(page.locator("input.group-name")).toHaveCount(NAMES.length);
}

const fit = (page: Page) =>
  page.$$eval(".group-name-field", (fields) =>
    fields.map((f) => {
      const input = f.querySelector("input") as HTMLInputElement;
      const row = f.closest(".group-name-row") as HTMLElement;
      return {
        cut: input.scrollWidth > input.clientWidth,
        field: f.getBoundingClientRect().right,
        row: row.getBoundingClientRect().right,
      };
    }),
  );

// Catches a name field sized by a measurement that came back short, so a wide screen cuts "Telegram" to "Telegr…".
test("on a wide screen every group name is shown whole", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await open(page);
  expect((await fit(page)).map((f) => f.cut)).toEqual([false, false, false]);
});

// Catches a name field that stopped shrinking, so a long name pushes past its row on a phone.
test("on a phone a long name is cut inside its row", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await open(page);
  const f = await fit(page);
  expect(f[2].cut).toBe(true);
  for (const x of f) expect(x.field).toBeLessThanOrEqual(x.row + 0.5);
});

// Catches a name field that takes the browser's own input padding, so iOS Safari's wider one cuts "Telegram" to "Telegr…".
test("a browser's own input padding does not cut a group name", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await open(page);
  await page.addStyleTag({ content: "input { padding: 0.2em 0.5em; }" });
  expect((await fit(page)).map((f) => f.cut)).toEqual([false, false, false]);
});
