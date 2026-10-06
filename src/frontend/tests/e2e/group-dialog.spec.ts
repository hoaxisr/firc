import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

async function openDialog(page: Page) {
  await signedIn(page);
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));

  await page.goto("/");
  await page.locator('[data-value="Add Group"] button').click();
  const dialog = page.getByRole("dialog");
  await dialog.locator("#gd-name").fill("YouTube");
  await dialog.locator('[aria-label="List by URL"]').click();
  await dialog.locator("#gd-url").fill("https://example.com/list.txt");
  return dialog;
}

async function preview(page: Page, body: Record<string, unknown>) {
  await page.route("**/groups/list/preview*", (route) => route.fulfill({ json: body }));
  const dialog = await openDialog(page);
  await dialog.getByRole("button", { name: "Preview", exact: true }).click();
  return dialog;
}

test.describe("Group dialog: list preview", () => {
  test("a list that yields nothing says why", async ({ page }) => {
    const dialog = await preview(page, { rules: [], total: 0, byType: {}, dropped: 5000 });
    await expect(dialog).toContainText("5000");
    await expect(dialog).toContainText("format firc does not route");
  });

  // A list of only comments and blank lines must still say why it is empty.
  test("a list of nothing at all still says why", async ({ page }) => {
    const dialog = await preview(page, { rules: [], total: 0, byType: {}, dropped: 0 });
    await expect(dialog).toContainText("nothing firc can route");
  });

  test("an ordinary list reports its counts and does not complain", async ({ page }) => {
    const dialog = await preview(page, {
      rules: [{ enable: true, id: "11111111", rule: "a.example.com", type: "namespace" }],
      total: 4000,
      byType: { namespace: 3990, subnet: 10 },
      dropped: 3,
    });
    await expect(dialog.locator(".preview-counts")).toContainText("4000");
    await expect(dialog.locator(".breakdown")).toContainText("3990 Namespace");
    await expect(dialog.locator(".preview-note")).toHaveText("Lines that are not rules: 3");
    await expect(dialog.locator(".preview-shown")).toHaveText("Showing the first 1");
    await expect(dialog).not.toContainText("format firc does not route");
  });

  // Catches the preview not counting names that came without their protocol limit.
  test("the preview says how many names came without their protocol limit", async ({ page }) => {
    const dialog = await preview(page, {
      rules: [],
      total: 1,
      byType: { domain: 1 },
      dropped: 0,
      unconstrained: 1,
    });
    await expect(
      dialog.locator(".preview-note", { hasText: "Names without a protocol limit" }),
    ).toHaveText("Names without a protocol limit: 1");
  });

  // Catches the 400 and 502 answers being folded into one generic "failed" message.
  test("the daemon's 400 is shown verbatim", async ({ page }) => {
    await page.route("**/groups/list/preview*", (route) =>
      route.fulfill({ status: 400, json: { error: "list url is required" } }),
    );
    const dialog = await openDialog(page);
    await dialog.getByRole("button", { name: "Preview", exact: true }).click();
    await expect(dialog).toContainText("list url is required");
  });

  test("the daemon's 502 is shown verbatim", async ({ page }) => {
    await page.route("**/groups/list/preview*", (route) =>
      route.fulfill({ status: 502, json: { error: "list fetch failed" } }),
    );
    const dialog = await openDialog(page);
    await dialog.getByRole("button", { name: "Preview", exact: true }).click();
    await expect(dialog).toContainText("list fetch failed");
  });
});

test.describe("Group dialog: adding a group", () => {
  test("a group created with the list toggle off has no list at all", async ({ page }) => {
    await signedIn(page);
    await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.goto("/");

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("Plain Group");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await expect(page.locator(".group-wrapper")).toHaveCount(1);
    await expect(page.locator("input.group-name")).toHaveValue("Plain Group");
    await expect(page.locator(".rule")).toHaveCount(0);
    await expect(page.locator(".list-badge")).toHaveCount(0);
  });

  // Catches the dialog's list block not giving the new group a `list` of {url, interval}.
  test("the_dialog_adds_a_group_with_a_list", async ({ page }) => {
    await signedIn(page);
    await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    let savedBody: any = null;
    await page.route(/\/groups(\?.*)?$/, async (route) => {
      if (route.request().method() !== "PUT") {
        await route.fallback();
        return;
      }
      savedBody = route.request().postDataJSON();
      await route.fulfill({ json: { status: "ok" } });
    });
    await page.goto("/");

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("YouTube");
    await dialog.locator('[aria-label="List by URL"]').click();
    await dialog.locator("#gd-url").fill("https://lists.example.net/youtube.lst");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await expect(page.locator(".group-wrapper")).toHaveCount(1);
    await expect(page.locator(".list-badge")).toHaveCount(1);
    await expect(page.locator(".list-url-input")).toHaveValue(
      "https://lists.example.net/youtube.lst",
    );

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(savedBody?.groups[0].list).toEqual({
      url: "https://lists.example.net/youtube.lst",
      interval: 86400,
    });
  });
});

test.describe("Group dialog on a phone", () => {
  async function tallDialog(page: Page) {
    await page.setViewportSize({ width: 400, height: 700 });
    await signedIn(page);
    await page.addInitScript(() => {
      localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
    });
    await page.route("**/interfaces", (route) =>
      route.fulfill({ json: { interfaces: [{ id: "nwg0", name: "WireGuard Interface" }] } }),
    );
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.goto("/");
    await page.locator('[data-value="Добавить группу"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("YouTube");
    await dialog.locator("#gd-dns [data-select-trigger]").click();
    await page.getByRole("option", { name: "Через туннель — свой сервер" }).click();
    await dialog.locator("#gd-dns-server").fill("9.9.9.9");
    await dialog.locator('[aria-label="Список по URL"]').click();
    await dialog.locator("#gd-url").fill("https://example.com/list.txt");
    return dialog;
  }

  // Catches the dialog no longer scrolling within a 400x700 screen.
  test("Create can be reached and pressed at 400x700", async ({ page }) => {
    const dialog = await tallDialog(page);
    const create = dialog.getByRole("button", { name: "Создать", exact: true });
    await create.scrollIntoViewIfNeeded();
    const box = await create.boundingBox();
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.y + box!.height).toBeLessThanOrEqual(700);
    await create.click();
    await dialog.waitFor({ state: "hidden" });
    await expect(page.locator("input.group-name")).toHaveValue("YouTube");
  });

  // Catches a field, hint or button wider than the dialog, or the preview hint squeezed beside its button.
  test("nothing in it is wider than the screen at 400 px", async ({ page }) => {
    const dialog = await tallDialog(page);
    const hintLines = await dialog.locator(".preview-hint").evaluate((el) => {
      const range = document.createRange();
      range.selectNodeContents(el);
      return new Set([...range.getClientRects()].map((r) => Math.round(r.top))).size;
    });
    expect(hintLines).toBeLessThanOrEqual(2);
    const widest = await dialog.evaluate((el) => {
      let right = 0;
      for (const node of el.querySelectorAll("*")) {
        const r = node.getBoundingClientRect();
        if (r.width > 0) right = Math.max(right, r.right);
      }
      return { right, scroll: el.scrollWidth, client: el.clientWidth };
    });
    expect(widest.right).toBeLessThanOrEqual(400);
    expect(widest.scroll).toBeLessThanOrEqual(widest.client);
  });
});
