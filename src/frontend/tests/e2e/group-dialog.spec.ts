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
  await dialog.locator("#gd-url").fill("https://example.com/list.txt");
  await dialog.getByRole("button", { name: "Add list", exact: true }).click();
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
      route.fulfill({ status: 502, json: { error: "the server answered 404" } }),
    );
    const dialog = await openDialog(page);
    await dialog.getByRole("button", { name: "Preview", exact: true }).click();
    await expect(dialog).toContainText("the server answered 404");
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

  // Catches the dialog's list block not giving the new group a `lists` entry of {id, url, interval}.
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

    expect(savedBody?.groups[0].lists).toEqual([
      {
        id: expect.stringMatching(/^[0-9a-f]{8}$/),
        url: "https://lists.example.net/youtube.lst",
        interval: 86400,
      },
    ]);
  });
});

test.describe("Group dialog: Cloudflare switch", () => {
  test("the cloudflare switch saves and reloads", async ({ page }) => {
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
    await dialog.locator("#gd-name").fill("CF");
    const toggle = dialog.locator('[aria-label="One Cloudflare address"]');
    await expect(toggle).toHaveAttribute("aria-checked", "false");
    await toggle.click();
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(savedBody?.groups[0].cloudflare).toBe(true);

    await page.getByRole("button", { name: "Group Settings" }).first().click();
    await expect(
      page.getByRole("dialog").locator('[aria-label="One Cloudflare address"]'),
    ).toHaveAttribute("aria-checked", "true");
  });
});

test.describe("Group dialog on a phone", () => {
  async function tallDialog(page: Page, width = 400) {
    await page.setViewportSize({ width, height: 700 });
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
    await dialog.locator("#gd-url").fill("https://example.com/list.txt");
    await dialog.getByRole("button", { name: "Добавить список", exact: true }).click();
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
  for (const width of [360, 400]) {
    test(`nothing in it is wider than the screen at ${width} px`, async ({ page }) => {
      const dialog = await tallDialog(page, width);
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
      expect(widest.right).toBeLessThanOrEqual(width);
      expect(widest.scroll).toBeLessThanOrEqual(widest.client);
    });
  }
});

const SAGERNET = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs";
const HOAXISR = "https://raw.githubusercontent.com/hoaxisr/rulesets/master/srs/{}.srs";
const CATALOG = {
  generated: "2026-10-22T00:00:00Z",
  fetchedAt: 1761091200,
  stale: false,
  sources: [
    { id: "sagernet", url: SAGERNET, names: ["google", "youtube", "youtube@cn", "telegram"] },
    { id: "hoaxisr", url: HOAXISR, names: ["youtube", "discord"] },
  ],
};

type CatalogAnswer = { status: number; json: unknown };

async function catalogDialog(
  page: Page,
  answers: CatalogAnswer[] = [{ status: 200, json: CATALOG }],
  opts: { locale?: string; gate?: Promise<void> } = {},
) {
  const calls = { count: 0 };
  await signedIn(page);
  if (opts.locale) {
    const locale = opts.locale;
    await page.addInitScript((value) => {
      localStorage.setItem("locale", JSON.stringify({ value }));
    }, locale);
  }
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route("**/groups/list/catalog", async (route) => {
    const answer = answers[Math.min(calls.count, answers.length - 1)];
    calls.count++;
    if (opts.gate) await opts.gate;
    await route.fulfill(answer);
  });
  await page.goto("/");
  const add = opts.locale === "ru" ? "Добавить группу" : "Add Group";
  const open = async () => {
    await page.locator(`[data-value="${add}"] button`).click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("YouTube");
    return dialog;
  };
  const dialog = await open();
  return { dialog, calls, open };
}

test.describe("Group dialog: finding a list by name", () => {
  // Catches the arrow keys or Enter not picking the highlighted row, or the list staying open after a pick.
  test("typing a word lists matches, arrow down and Enter add the list", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    const options = dialog.getByRole("option");
    await expect(options).toHaveCount(3);
    await expect(options.first()).toContainText("youtube");
    await expect(options.first()).toContainText("sagernet");
    await expect(field).toHaveAttribute("aria-expanded", "true");
    await field.press("ArrowDown");
    await field.press("Enter");
    await expect(dialog.locator(".gd-list-url")).toHaveValue(
      "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs",
    );
    await expect(field).toHaveValue("");
    await expect(dialog.getByRole("listbox")).toHaveCount(0);
    await expect(field).toHaveAttribute("aria-expanded", "false");
    await expect(dialog.getByRole("button", { name: "Preview", exact: true })).toBeEnabled();
  });

  // Catches one source's name hiding the other's, or a pick taking the wrong source's URL.
  test("the same name in both sources is two rows, each with its own URL", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("youtube");
    const named = dialog
      .getByRole("option")
      .filter({ hasText: /^\s*youtube\s*(sagernet|hoaxisr)\s*$/ });
    await expect(named).toHaveCount(2);
    await dialog.getByRole("option").filter({ hasText: "hoaxisr" }).click();
    await expect(dialog.locator(".gd-list-url")).toHaveValue(
      "https://raw.githubusercontent.com/hoaxisr/rulesets/master/srs/youtube.srs",
    );
    await expect(dialog.getByRole("listbox")).toHaveCount(0);
  });

  // Catches Escape closing the whole dialog, or clearing what was typed.
  test("Escape closes the list and keeps the text", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    await expect(dialog.getByRole("option")).toHaveCount(3);
    await field.press("Escape");
    await expect(dialog.getByRole("listbox")).toHaveCount(0);
    await expect(field).toHaveValue("you");
    await page.waitForTimeout(300);
    await expect(dialog).toBeVisible();
    await field.press("Escape");
    await expect(dialog).toBeHidden();
  });

  // Catches a URL being searched as a word, or the catalog being fetched for it.
  test("a full URL opens no list and asks for no catalog", async ({ page }) => {
    const { dialog, calls } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("https://example.com/list.txt");
    await expect(dialog.getByRole("button", { name: "Add list", exact: true })).toBeEnabled();
    await expect(dialog.getByRole("listbox")).toHaveCount(0);
    await expect(field).toHaveAttribute("aria-expanded", "false");
    expect(calls.count).toBe(0);
    await field.fill("you");
    await expect(dialog.getByRole("option")).toHaveCount(3);
    expect(calls.count).toBe(1);
  });

  // Catches text without a scheme being treated as a URL, or an empty search showing nothing at all.
  test("an address without a scheme finds nothing and cannot be added", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    await dialog.locator("#gd-url").fill("raw.githubusercontent.com/x");
    await expect(dialog.locator(".catalog-panel")).toContainText("nothing found");
    await expect(dialog.locator("#gd-url")).toHaveAttribute("aria-controls", "gd-url-catalog");
    await expect(dialog.locator('[role="status"]')).toHaveText("nothing found");
    await expect(dialog.getByRole("option")).toHaveCount(0);
    await expect(dialog.getByRole("button", { name: "Add list", exact: true })).toBeDisabled();
  });

  // Catches the router's reason being replaced by a generic message, or a failed catalog blocking a hand-typed URL.
  test("a catalog the router could not fetch says why and a URL still works", async ({ page }) => {
    const { dialog } = await catalogDialog(page, [
      { status: 502, json: { error: "the server answered 404" } },
    ]);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    await expect(dialog.locator(".catalog-panel")).toContainText("the server answered 404");
    await field.fill("https://example.com/list.txt");
    await expect(dialog.locator(".catalog-panel")).toHaveCount(0);
    await expect(dialog.getByRole("button", { name: "Add list", exact: true })).toBeEnabled();
  });

  // Catches the unreadable-answer fallback bypassing translation.
  test("an unreadable catalog failure is shown in the chosen language", async ({ page }) => {
    const { dialog } = await catalogDialog(page, [{ status: 502, json: "x" }], { locale: "ru" });
    await dialog.locator("#gd-url").fill("you");
    await expect(dialog.locator(".catalog-panel")).toContainText("Каталог недоступен");
  });

  // Catches a failed catalog being remembered, so the next word never asks again.
  test("after a failed catalog the next word asks again and shows rows", async ({ page }) => {
    const { dialog, calls } = await catalogDialog(page, [
      { status: 502, json: { error: "the server answered 404" } },
      { status: 200, json: CATALOG },
    ]);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    await expect(dialog.locator(".catalog-panel")).toContainText("the server answered 404");
    await field.fill("goo");
    await expect(dialog.getByRole("option")).toHaveCount(1);
    await expect(dialog.getByRole("option")).toContainText("google");
    expect(calls.count).toBe(2);
  });

  // Catches the catalog being fetched again for every word or every opening of the dialog.
  test("the catalog is asked for once across words and a reopened dialog", async ({ page }) => {
    const { dialog, calls, open } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    await expect(dialog.getByRole("option")).toHaveCount(3);
    await field.fill("goo");
    await expect(dialog.getByRole("option")).toHaveCount(1);
    await dialog.locator(".close").click();
    await expect(dialog).toBeHidden();
    const again = await open();
    await again.locator("#gd-url").fill("disc");
    await expect(again.getByRole("option")).toHaveCount(1);
    await expect(again.getByRole("option")).toContainText("discord");
    expect(calls.count).toBe(1);
  });

  // Catches a word being called an invalid URL, or a word letting the group be created.
  test("a word is not an invalid URL and Create waits for a pick", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    const field = dialog.locator("#gd-url");
    await field.fill("you");
    await expect(dialog.getByRole("option")).toHaveCount(3);
    await expect(dialog).not.toContainText("Invalid URL");
    await expect(field).not.toHaveClass(/invalid/);
    const create = dialog.getByRole("button", { name: "Create", exact: true });
    await expect(create).toBeDisabled();
    await dialog.getByRole("option").first().click();
    await expect(create).toBeEnabled();
  });

  // Catches an empty panel while the catalog is still on its way, or a status region born with its text.
  test("the list says it is loading until the catalog arrives", async ({ page }) => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const { dialog } = await catalogDialog(page, undefined, { gate });
    const status = dialog.locator('[role="status"]');
    await expect(status).toHaveText("");
    await dialog.locator("#gd-url").fill("you");
    await expect(dialog.locator(".catalog-panel")).toContainText("loading the catalog…");
    await expect(status).toHaveText("loading the catalog…");
    release();
    await expect(dialog.getByRole("option")).toHaveCount(3);
    await expect(dialog.locator(".catalog-panel")).not.toContainText("loading the catalog…");
  });

  // Catches the field still being labelled as taking only an address.
  test("the field is called Address or name", async ({ page }) => {
    const { dialog } = await catalogDialog(page);
    await expect(dialog.locator('label[for="gd-url"]')).toHaveText("Address or name");
  });

  // Catches the cap of 50 rows missing, or the rest going uncounted, or the Russian strings missing.
  test("in Russian past 50 rows the list counts the rest", async ({ page }) => {
    const names = Array.from({ length: 55 }, (_, i) => `site${String(i).padStart(2, "0")}`);
    const big = { ...CATALOG, sources: [{ id: "hoaxisr", url: HOAXISR, names }] };
    const { dialog } = await catalogDialog(page, [{ status: 200, json: big }], { locale: "ru" });
    await expect(dialog.locator('label[for="gd-url"]')).toHaveText("Адрес или название");
    await dialog.locator("#gd-url").fill("site");
    await expect(dialog.getByRole("option")).toHaveCount(50);
    await expect(dialog.locator(".catalog-panel")).toContainText("ещё 5");
    await dialog.locator("#gd-url").fill("zzz");
    await expect(dialog.locator(".catalog-panel")).toContainText("ничего не найдено");
  });
});

test.describe("Group dialog: DNS only", () => {
  const IFACES = [
    { id: "blackhole" },
    { id: "block" },
    { id: "dns" },
    { id: "nwg0", role: "tunnel" },
  ];
  const URL_ONE = "https://dns.comss.one/dns-query";

  async function setup(page: Page, groups: unknown[] = []) {
    await signedIn(page);
    await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: IFACES } }));
    await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
    let live = groups;
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: live } }),
    );
    const saved: any[] = [];
    await page.route(/\/groups(\?.*)?$/, async (route) => {
      if (route.request().method() !== "PUT") {
        await route.fallback();
        return;
      }
      const body = route.request().postDataJSON();
      saved.push(body);
      live = body.groups;
      await route.fulfill({ json: { groups: body.groups } });
    });
    await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
    await page.goto("/");
    return saved;
  }

  async function pickDns(page: Page) {
    const dialog = page.getByRole("dialog");
    await dialog.locator(".interface-select [data-select-trigger]").click();
    await page.locator('[data-select-item][data-value="dns"]').click();
    return dialog;
  }

  test("a dns group without a server shows the error and is not created", async ({ page }) => {
    const saved = await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = await pickDns(page);
    await dialog.locator("#gd-name").fill("Comss");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await expect(dialog.locator(".dns-server-error")).toHaveText("A DNS only group needs a server");
    await expect(dialog).toBeVisible();
    expect(saved).toHaveLength(0);
    await dialog.locator("#gd-dns-server").fill(URL_ONE);
    await expect(dialog.locator(".dns-server-error")).toHaveCount(0);
  });

  test("a DoH link and the fallback switch go to the PUT and come back on reopen", async ({
    page,
  }) => {
    const saved = await setup(page);
    await page.locator('[data-value="Add Group"] button').click();
    const dialog = await pickDns(page);
    await dialog.locator("#gd-name").fill("Comss");
    await expect(dialog.locator("#gd-dns [data-select-trigger]")).toHaveCount(0);
    await dialog.locator("#gd-dns-server").fill(URL_ONE);
    const fallback = dialog.getByRole("switch", { name: "Fall back to the common DNS" });
    await expect(fallback).toHaveAttribute("aria-checked", "true");
    await fallback.click();
    await expect(fallback).toHaveAttribute("aria-checked", "false");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.locator("#save-changes").click();
    await expect.poll(() => saved.length).toBe(1);
    const sent = saved[0].groups[0];
    expect(sent.interface).toBe("dns");
    expect(sent.resolve.server).toBe(URL_ONE);
    expect(sent.resolve.fallback).toBe(false);

    await page.getByRole("button", { name: "Group Settings" }).first().click();
    const again = page.getByRole("dialog");
    await expect(again.locator("#gd-dns-server")).toHaveValue(URL_ONE);
    await expect(
      again.getByRole("switch", { name: "Fall back to the common DNS" }),
    ).toHaveAttribute("aria-checked", "false");
  });

  test("a group moved off dns sends no fallback key", async ({ page }) => {
    const saved = await setup(page, [
      {
        id: "0a000001",
        name: "Comss",
        interface: "dns",
        enable: true,
        devices: { allow: [], deny: [] },
        resolve: { tunnel: true, server: URL_ONE, fallback: false },
        rules: [],
        live: true,
      },
    ]);
    await page.locator(".group .iface-select [data-select-trigger]").first().click();
    await page.locator('[data-select-item][data-value="nwg0"]').click();
    await page.locator("#save-changes").click();
    await expect.poll(() => saved.length).toBe(1);
    expect(saved[0].groups[0].interface).toBe("nwg0");
    expect("fallback" in saved[0].groups[0].resolve).toBe(false);
  });

  test("toggling only the fallback of an existing dns group reaches the PUT both ways", async ({
    page,
  }) => {
    const saved = await setup(page, [
      {
        id: "0a000001",
        name: "Comss",
        interface: "dns",
        enable: true,
        devices: { allow: [], deny: [] },
        resolve: { server: URL_ONE, fallback: true },
        rules: [],
        live: true,
      },
    ]);
    const toggle = async () => {
      await page.getByRole("button", { name: "Group Settings" }).first().click();
      const dialog = page.getByRole("dialog");
      await dialog.getByRole("switch", { name: "Fall back to the common DNS" }).click();
      await dialog.getByRole("button", { name: "Save", exact: true }).click();
      await dialog.waitFor({ state: "hidden" });
      await page.locator("#save-changes").click();
    };
    await toggle();
    await expect.poll(() => saved.length).toBe(1);
    expect(saved[0].groups[0].resolve.fallback).toBe(false);
    await toggle();
    await expect.poll(() => saved.length).toBe(2);
    expect(saved[1].groups[0].resolve.fallback).not.toBe(false);
  });
});
