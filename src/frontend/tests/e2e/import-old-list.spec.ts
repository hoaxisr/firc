import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const old = (n: number, url: string) => ({
  id: (0x0a000000 + n).toString(16),
  name: `Old ${n}`,
  interface: "eth0",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  list: { url, interval: 3600 },
});

async function importFile(page: Page, body: unknown) {
  await signedIn(page);
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
  await page.route(/\/groups(\?.*)?$/, (route) => route.fulfill({ json: { groups: [] } }));
  await page.goto("/");
  await page
    .locator('input[type="file"]')
    .first()
    .setInputFiles({
      name: "export.firc",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(body)),
    });
  return page.getByRole("dialog");
}

test.describe("Importing a config with the old list key", () => {
  // Catches an import dropping a group's old list without telling, or naming the wrong urls.
  test("names the first three urls and counts the rest", async ({ page }) => {
    const long = "https://long.example/" + "a".repeat(300);
    const dialog = await importFile(page, {
      groups: [
        old(1, "https://one.example/a.txt"),
        old(2, "https://two.example/b.txt"),
        old(3, long),
        old(4, "https://four.example/d.txt"),
        old(5, "https://five.example/e.txt"),
      ],
    });
    const warning = dialog.locator(".old-lists");
    await expect(warning).toBeVisible();
    await expect(warning).toContainText("https://one.example/a.txt");
    await expect(warning).toContainText("https://two.example/b.txt");
    await expect(warning).toContainText(long.slice(0, 200));
    await expect(warning).not.toContainText(long.slice(0, 201));
    await expect(warning).not.toContainText("four.example");
    await expect(warning).toContainText("and 2 more");
  });

  // Catches the notice showing for a config whose groups carry no old list.
  test("shows nothing for a config without it", async ({ page }) => {
    const { list, ...fresh } = old(1, "https://one.example/a.txt");
    const dialog = await importFile(page, { groups: [fresh] });
    await expect(dialog.locator(".import-config")).toBeVisible();
    await expect(dialog.locator(".old-lists")).toHaveCount(0);
  });
});
