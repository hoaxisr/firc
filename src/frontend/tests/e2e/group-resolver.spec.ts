import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const RESOLVERS = { resolvers: [{ interface: "nwg0", servers: ["9.9.9.9", "1.0.0.1"] }] };

async function setup(
  page: Page,
  groups: unknown[] = [],
  putAnswer?: (body: any) => { status: number; json: unknown },
) {
  await signedIn(page);
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "nwg0" }, { id: "blackhole" }, { id: "eth1" }] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: RESOLVERS }));
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups } }));
  const saved: any[] = [];
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    if (route.request().method() !== "PUT") {
      await route.fallback();
      return;
    }
    const body = route.request().postDataJSON();
    saved.push(body);
    const answer = putAnswer ? putAnswer(body) : { status: 200, json: { groups: body.groups } };
    await route.fulfill({ status: answer.status, json: answer.json });
  });
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.goto("/");
  return saved;
}

async function chooseDns(page: Page, label: string) {
  await page.getByRole("dialog").locator("#gd-dns [data-select-trigger]").click();
  const option = page.getByRole("option", { name: label });
  await option.waitFor({ state: "attached" });
  await option.click();
}

async function createGroup(page: Page, pick: (page: Page) => Promise<void>) {
  await page.locator('[data-value="Add Group"] button').click();
  const dialog = page.getByRole("dialog");
  await dialog.locator("#gd-name").fill("NL");
  await pick(page);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  await page.locator("#save-changes").click();
}

const existing = (resolve: unknown, resolver: unknown) => ({
  id: "0a1b2c3d",
  name: "NL",
  interface: "nwg0",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  resolve,
  resolver,
});

test.describe("A group's DNS", () => {
  // Catches a choice mapping to the wrong resolve, or "own" losing its server.
  test("the three choices map to resolve", async ({ page }) => {
    const saved = await setup(page);
    await createGroup(page, async () => {});
    await expect.poll(() => saved.length).toBe(1);
    expect(saved[0].groups[0].resolve).toEqual({ tunnel: true, server: "" });

    await createGroup(page, (p) => chooseDns(p, "Not through the tunnel"));
    await expect.poll(() => saved.length).toBe(2);
    expect(saved[1].groups[1].resolve).toEqual({ tunnel: false, server: "" });

    await createGroup(page, async (p) => {
      await chooseDns(p, "Through the tunnel — own server");
      await p.getByRole("dialog").locator("#gd-dns-server").fill("9.9.9.9:5353");
    });
    await expect.poll(() => saved.length).toBe(3);
    expect(saved[2].groups[2].resolve).toEqual({ tunnel: true, server: "9.9.9.9:5353" });
    expect("resolver" in saved[2].groups[0]).toBe(false);
  });

  // Catches the auto line missing the interface's servers, or suggestions missing the firmware's.
  test("the auto line shows the firmware's servers and the field suggests them", async ({
    page,
  }) => {
    await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.locator(".dns-effective")).toHaveText("9.9.9.9, 1.0.0.1");
    await chooseDns(page, "Through the tunnel — own server");
    const options = dialog.locator("#gd-dns-servers option");
    await expect(options).toHaveCount(4);
    for (const s of ["9.9.9.9", "1.0.0.1", "1.1.1.1", "8.8.8.8"]) {
      await expect(dialog.locator(`#gd-dns-servers option[value="${s}"]`)).toHaveCount(1);
    }
    await expect(dialog).toContainText("a DNS server on the local network will not work");
  });

  // Catches a sink address being submittable, or the field showing no reason.
  test("an address the daemon would refuse cannot be submitted", async ({ page }) => {
    await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await chooseDns(page, "Through the tunnel — own server");
    await dialog.locator("#gd-dns-server").fill("127.0.0.1");
    await expect(dialog.locator(".dns-server-error")).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
    await dialog.locator("#gd-dns-server").fill("9.9.9.9:0");
    await expect(dialog.locator(".dns-server-error")).toContainText("65535");
    await dialog.locator("#gd-dns-server").fill("9.9.9.9");
    await expect(dialog.locator(".dns-server-error")).toHaveCount(0);
    await expect(dialog.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  });

  // Catches the daemon's 400 becoming only a toast, or aria-invalid never flipping.
  test("the daemon's refusal lands on the server field", async ({ page }) => {
    await setup(
      page,
      [
        existing(
          { tunnel: true, server: "" },
          { source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 },
        ),
      ],
      (body) => ({
        status: 400,
        json: {
          error: 'resolve.server "198.18.0.1" is inside firc\'s address pool',
          field: "resolve.server",
          group: body.groups[0].id,
        },
      }),
    );
    await page.getByRole("button", { name: "Group Settings" }).first().click();
    const dialog = page.getByRole("dialog");
    await chooseDns(page, "Through the tunnel — own server");
    await dialog.locator("#gd-dns-server").fill("198.18.0.1");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.locator("#save-changes").click();
    await expect(page.getByRole("dialog").locator(".dns-server-error")).toContainText(
      "inside firc's address pool",
    );
    await expect(page.getByRole("dialog").locator("#gd-dns-server")).toHaveValue("198.18.0.1");
    await expect(page.getByRole("dialog").locator("#gd-dns-server")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  // Catches a blackhole group's DNS being choosable, or the hint missing.
  test("the choice is disabled for a blackhole group", async ({ page }) => {
    await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator(".interface-select [data-select-trigger]").click();
    const bh = page.getByRole("option", { name: "blackhole" });
    await bh.waitFor({ state: "attached" });
    await bh.click();
    await expect(dialog.locator(".dns-blackhole-hint")).toBeVisible();
    await expect(dialog.locator("#gd-dns [data-select-trigger]")).toBeDisabled();
  });

  // Catches a missing or wrong resolver tag, or a zero fallback count being shown.
  test("the panel shows the effective resolver and a non-zero fallback count", async ({ page }) => {
    await setup(page, [
      existing(
        { tunnel: true, server: "" },
        { source: "firmware", servers: ["9.9.9.9", "1.0.0.1"], fallbacks: 4 },
      ),
      {
        ...existing({ tunnel: false, server: "" }, { source: "off", servers: [], fallbacks: 0 }),
        id: "0a1b2c3e",
        name: "DE",
      },
    ]);
    const tags = page.locator(".resolver-badge");
    await expect(tags).toHaveCount(2);
    await expect(tags.nth(0)).toHaveText("DNS 9.9.9.9, 1.0.0.1");
    await expect(tags.nth(1)).toHaveText("DNS: not through the tunnel");
    await expect(page.locator(".fallback-badge")).toHaveCount(1);
    await expect(page.locator(".fallback-badge")).toHaveText("fallbacks: 4");
  });

  // Catches a hidden, invalid typed server riding the PUT instead of the group's own resolve.
  test("switching to blackhole discards a typed invalid server and saves the group's own resolve", async ({
    page,
  }) => {
    const original = { tunnel: true, server: "9.9.9.9" };
    const saved = await setup(page, [
      existing(original, { source: "group", servers: ["9.9.9.9"], fallbacks: 0 }),
    ]);
    await page.getByRole("button", { name: "Group Settings" }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.locator("#gd-dns-server")).toHaveValue("9.9.9.9");
    await dialog.locator("#gd-dns-server").fill("127.0.0.1");
    await expect(dialog.getByRole("button", { name: "Save", exact: true })).toBeDisabled();

    await dialog.locator(".interface-select [data-select-trigger]").click();
    const bh = page.getByRole("option", { name: "blackhole" });
    await bh.waitFor({ state: "attached" });
    await bh.click();
    await expect(dialog.getByRole("button", { name: "Save", exact: true })).toBeEnabled();

    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.locator("#save-changes").click();
    await expect.poll(() => saved.length).toBe(1);
    expect(saved[0].groups[0].resolve).toEqual(original);
  });

  // Catches closing group B's dialog dropping group A's pending refusal.
  test("group B's dialog closing does not drop group A's pending refusal", async ({ page }) => {
    const groupA = existing(
      { tunnel: true, server: "" },
      { source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 },
    );
    const groupB = {
      ...existing(
        { tunnel: true, server: "" },
        { source: "firmware", servers: ["9.9.9.9"], fallbacks: 0 },
      ),
      id: "0a1b2c3e",
      name: "DE",
    };
    const saved = await setup(page, [groupA, groupB], (body) => ({
      status: 400,
      json: {
        error: 'resolve.server "198.18.0.1" is inside firc\'s address pool',
        field: "resolve.server",
        group: groupA.id,
      },
    }));

    await page.getByRole("button", { name: "Group Settings" }).nth(0).click();
    let dialog = page.getByRole("dialog");
    await chooseDns(page, "Through the tunnel — own server");
    await dialog.locator("#gd-dns-server").fill("198.18.0.1");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await page.getByRole("button", { name: "Group Settings" }).nth(1).click();
    dialog = page.getByRole("dialog");
    await expect(dialog.locator("#gd-name")).toHaveValue("DE");

    await page.locator("#save-changes").dispatchEvent("click");
    await expect.poll(() => saved.length).toBe(1);

    await expect(page.getByRole("dialog").locator("#gd-name")).toHaveValue("DE");

    await dialog.locator(".close").click();
    const reopened = page.getByRole("dialog");
    await expect(reopened.locator("#gd-name")).toHaveValue("NL");
    await expect(reopened.locator(".dns-server-error")).toContainText("inside firc's address pool");
  });

  // Catches the "auto" wording falling back to the firmware list instead of group.resolver.
  test("an auto group trusts the daemon's resolver over a firmware list that still has servers", async ({
    page,
  }) => {
    await setup(page, [
      existing({ tunnel: true, server: "" }, { source: "firmware", servers: [], fallbacks: 0 }),
    ]);
    await expect(page.locator(".resolver-badge")).toHaveText("DNS: common upstream");

    await page.getByRole("button", { name: "Group Settings" }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.locator(".dns-effective")).toHaveText(
      "the firmware has no DNS for this interface — common upstream",
    );
  });
  // Catches the DNS tag shrinking to a sliver, or a long name pushing it out.
  test("a plain group's DNS tag is not clipped, and says its servers when hovered", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1150, height: 900 });
    await setup(page, [
      {
        ...existing(
          { tunnel: true, server: "" },
          { source: "firmware", servers: ["9.9.9.9", "1.0.0.1"], fallbacks: 0 },
        ),
        name: "Video and streaming services through the tunnel in the Netherlands, long",
      },
    ]);
    const tag = page.locator(".resolver-badge");
    await expect(tag).toHaveText("DNS 9.9.9.9, 1.0.0.1");
    await expect(tag).toHaveAttribute("title", "DNS 9.9.9.9, 1.0.0.1");
    const { scroll, client } = await tag.evaluate((el) => ({
      scroll: el.scrollWidth,
      client: el.clientWidth,
    }));
    expect(client).toBeGreaterThan(0);
    expect(scroll).toBeLessThanOrEqual(client);
    const name = page.locator("input.group-name");
    const cut = await name.evaluate((el: HTMLInputElement) => el.scrollWidth > el.clientWidth);
    expect(cut).toBe(true);
    const tagBox = await tag.boundingBox();
    const selectBox = await page.locator(".group-actions [data-select-trigger]").boundingBox();
    expect(tagBox!.x + tagBox!.width).toBeLessThanOrEqual(selectBox!.x);
  });
});
